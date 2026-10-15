//! The Git client's filesystem confinement.
//!
//! `src/client/git/` drives libgit2 against paths the *model* chooses. `git_clone` writes
//! where it is told; `git_checkout` and `git_delete_branch --force` destroy history in
//! whatever repository is open; `git_push` publishes it. Without a boundary all of that
//! reaches the operator's own repositories, and the client's own CLAUDE.md listed the
//! mitigation as "future".
//!
//! Two layers here, and the second is the one that matters:
//!
//!  * **The boundary itself** — `GitSandbox::resolve` against `..`, symlinks, absolute
//!    escapes and destinations that do not exist yet. Fast, no client, no LLM.
//!  * **The boundary as actually wired** — a real Git client built through `ClientForm`,
//!    with an action injected via `AppState::send_to_client`, asserting that the refusal
//!    happens on the path the dashboard and the model both use and that **nothing was
//!    written**. A guard that is correct but unreachable is the failure mode worth testing
//!    for; every test below that starts a client exists for that reason.
//!
//! Zero LLM calls: every client here points at an unreachable Ollama URL, so the
//! connected-event call fails and the command loop has to tolerate it — which is also
//! asserted, by the injected action running afterwards regardless.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features git --test client \
//!       -- client::git::sandbox --test-threads=100


use std::path::Path;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::git::sandbox::{
    classify_clone_source, CloneSource, GitSandbox, ALLOWED_ROOT_PARAM, ALLOW_REMOTE_WRITES_PARAM,
};
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// The boundary itself
// ---------------------------------------------------------------------------

/// A sandbox rooted at a fresh temp directory. The `TempDir` is returned too — dropping it
/// deletes the tree, so it has to outlive the sandbox.
fn sandboxed() -> (tempfile::TempDir, GitSandbox) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).expect("create root");
    let sandbox = GitSandbox::new(Some(&root.display().to_string()), false).expect("sandbox");
    (temp, sandbox)
}

#[test]
fn a_relative_path_resolves_inside_the_root() {
    let (_temp, sandbox) = sandboxed();

    // `./my-repo` is what every startup example in actions.rs shows. It has to mean
    // "inside the workspace" — resolving it against the process's cwd instead would put it
    // outside the root and it would then be refused, which would be useless.
    let resolved = sandbox.resolve("./my-repo", "test").expect("relative path");
    assert!(
        resolved.starts_with(sandbox.root()),
        "{} should be under {}",
        resolved.display(),
        sandbox.root().display()
    );
    assert!(resolved.ends_with("my-repo"));
}

#[test]
fn a_clone_destination_that_does_not_exist_yet_is_allowed() {
    let (_temp, sandbox) = sandboxed();

    // The whole point of a clone destination is that it is not there yet, so a guard that
    // required the path to exist would refuse every legitimate clone.
    let resolved = sandbox
        .resolve("deeply/nested/not/created/yet", "test")
        .expect("nonexistent destination inside the root");
    assert!(resolved.starts_with(sandbox.root()));
    assert!(!resolved.exists(), "the check must not create anything");
}

#[test]
fn an_absolute_path_outside_the_root_is_refused_and_names_the_parameter() {
    let (_temp, sandbox) = sandboxed();

    let err = sandbox
        .resolve("/etc", "the git_clone 'path'")
        .expect_err("/etc must be refused");
    let message = err.to_string();

    assert!(
        message.contains(ALLOWED_ROOT_PARAM),
        "the refusal must name the parameter the operator can turn, got: {message}"
    );
    assert!(
        message.contains("the git_clone 'path'"),
        "the refusal must say WHICH path was refused — three are in play, got: {message}"
    );
    // Refuse, never relocate: a model that asked for /etc and silently got <root>/etc has a
    // confusing bug where a refusal is a clear one.
    assert!(
        message.contains("Refused rather than relocated"),
        "got: {message}"
    );
}

#[test]
fn dot_dot_cannot_climb_out_of_the_root() {
    let (temp, sandbox) = sandboxed();

    // Textually this is inside the root. Only canonicalisation catches it, which is why
    // `resolve` canonicalises rather than comparing strings.
    let escape = format!("{}/../escaped", sandbox.root().display());
    let err = sandbox.resolve(&escape, "test").expect_err("`..` escape");
    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM));

    // And the same climb spelled relatively.
    let err = sandbox
        .resolve("../escaped", "test")
        .expect_err("relative `..` escape");
    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM));

    assert!(
        !temp.path().join("escaped").exists(),
        "nothing should have been created outside the root"
    );
}

#[test]
fn dot_dot_inside_a_path_that_does_not_exist_is_refused_rather_than_guessed_at() {
    let (_temp, sandbox) = sandboxed();

    // `<root>/nope/../..` — the `..` sits below a component that does not exist, so there
    // is nothing real for it to resolve against and no safe interpretation. Refusing is the
    // only honest answer; textually normalising it would be inventing a resolution the
    // filesystem has not agreed to.
    let err = sandbox
        .resolve("nope/../../outside", "test")
        .expect_err("unresolvable `..`");
    let message = err.to_string();
    assert!(
        message.contains("..") || message.contains(ALLOWED_ROOT_PARAM),
        "got: {message}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_out_of_the_root_is_refused() {
    let (temp, sandbox) = sandboxed();

    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"private").unwrap();

    // A symlink *inside* the root whose target is outside it. `starts_with` on the raw
    // string says this is fine; it is not.
    let link = sandbox.root().join("escape-hatch");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");

    let err = sandbox
        .resolve(&link.display().to_string(), "test")
        .expect_err("a symlink out of the root must be refused");
    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM));

    // Through the link, too — this is the form an actual clone destination would take.
    let err = sandbox
        .resolve("escape-hatch/new-repo", "test")
        .expect_err("a path traversing the symlink must be refused");
    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM));
}

#[test]
fn the_root_itself_and_paths_under_it_are_accepted() {
    let (_temp, sandbox) = sandboxed();

    assert!(sandbox
        .resolve(&sandbox.root().display().to_string(), "test")
        .is_ok());

    let inside = sandbox.root().join("repo");
    std::fs::create_dir_all(&inside).unwrap();
    let resolved = sandbox
        .resolve(&inside.display().to_string(), "test")
        .expect("a real directory inside the root");
    assert!(resolved.starts_with(sandbox.root()));
}

#[test]
fn an_empty_path_is_refused_rather_than_meaning_the_root() {
    let (_temp, sandbox) = sandboxed();
    assert!(sandbox.resolve("", "test").is_err());
    assert!(sandbox.resolve("   ", "test").is_err());
}

#[test]
fn the_default_root_is_neither_home_nor_the_working_directory() {
    let root = netget::client::git::sandbox::default_root();

    if let Some(home) = dirs::home_dir() {
        assert_ne!(root, home, "the default root must not be $HOME itself");
    }
    let cwd = std::env::current_dir().expect("cwd");
    assert_ne!(
        root, cwd,
        "the default root must not be the directory NetGet was launched from — which, for a \
         developer, is this repository"
    );
    assert!(
        !cwd.starts_with(&root),
        "the default root must not contain the working directory: {} contains {}",
        root.display(),
        cwd.display()
    );
    // `~/.netget` is NetGet's settings *file* (src/settings.rs), so a root beneath it can
    // never be created. This is not hypothetical — it is what the first attempt did, and
    // `create_dir_all` failed with ENOTDIR on the maintainer's machine.
    if let Some(home) = dirs::home_dir() {
        assert!(
            !root.starts_with(home.join(".netget")),
            "~/.netget is a file, not a directory: {}",
            root.display()
        );
    }
}

#[test]
fn remote_writes_are_refused_by_default_and_permitted_when_opted_in() {
    let (_temp, sandbox) = sandboxed();
    assert!(!sandbox.remote_writes_allowed());

    let err = sandbox
        .require_remote_writes("git_push")
        .expect_err("push must be refused by default");
    let message = err.to_string();
    assert!(
        message.contains(ALLOW_REMOTE_WRITES_PARAM),
        "the refusal must name the parameter that opens it, got: {message}"
    );

    let opted_in =
        GitSandbox::new(Some(&sandbox.root().display().to_string()), true).expect("sandbox");
    assert!(opted_in.remote_writes_allowed());
    assert!(opted_in.require_remote_writes("git_push").is_ok());
}

#[test]
fn a_local_clone_source_is_told_apart_from_a_network_one() {
    // Network: not a filesystem concern, and confining these would break every ordinary
    // clone.
    for url in [
        "https://github.com/rust-lang/rust.git",
        "http://127.0.0.1:8080/repo.git",
        "git://example.com/repo.git",
        "ssh://git@example.com/repo.git",
        "git@github.com:owner/repo.git",
    ] {
        assert_eq!(
            classify_clone_source(url),
            CloneSource::Remote,
            "{url} should be remote"
        );
    }

    // Local: a read of an arbitrary repository on this disk, whose contents then sit in
    // the workspace. `file://` is the one that matters — it contains `://`, so a naive
    // "has a scheme means remote" test waves it straight through.
    assert_eq!(
        classify_clone_source("file:///Users/someone/private"),
        CloneSource::Local("/Users/someone/private".to_string())
    );
    assert_eq!(
        classify_clone_source("/Users/someone/private"),
        CloneSource::Local("/Users/someone/private".to_string())
    );
    assert_eq!(
        classify_clone_source("../sibling-repo"),
        CloneSource::Local("../sibling-repo".to_string())
    );
}

// ---------------------------------------------------------------------------
// The boundary as actually wired
// ---------------------------------------------------------------------------

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
        "Git client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Start a Git client whose workspace is `root`, opened on `repo`.
async fn client_in(
    state: &AppState,
    root: &Path,
    repo: &Path,
    allow_remote_writes: bool,
) -> ClientId {
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(repo.display().to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            ALLOWED_ROOT_PARAM: root.display().to_string(),
            ALLOW_REMOTE_WRITES_PARAM: allow_remote_writes,
        })),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create git client");
    wait_for_client_handle(state, id).await;
    id
}

/// A repository with one commit, so verbs that need a HEAD have one.
fn repo_with_one_commit(path: &Path) {
    let repo = git2::Repository::init(path).expect("git init");
    std::fs::write(path.join("README.md"), b"hello\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
        .unwrap();
}

/// **The test that fails without the fix.** A `git_clone` aimed outside the workspace must
/// be refused, and must have written nothing.
///
/// Before confinement this cloned happily into whatever directory the model named — the
/// operator's home, `/tmp`, anywhere the process could write.
#[tokio::test]
async fn a_clone_outside_the_workspace_is_refused_and_writes_nothing() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();

    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    repo_with_one_commit(&source);

    // Somewhere the client must not reach: a stand-in for the operator's own tree.
    let forbidden = temp.path().join("operators-own-work");
    std::fs::create_dir_all(&forbidden).unwrap();
    let destination = forbidden.join("stolen-clone");

    let client_id = client_in(&state, &root, &source, false).await;

    let result = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": source.display().to_string(),
                "path": destination.display().to_string(),
            }),
            Duration::from_secs(20),
        )
        .await;

    let err = result
        .expect_err("a clone outside the workspace must fail")
        .to_string();
    assert!(
        err.contains(ALLOWED_ROOT_PARAM),
        "the refusal must name the parameter, got: {err}"
    );
    assert!(
        !destination.exists(),
        "nothing may be written outside the workspace, but {} exists",
        destination.display()
    );
}

/// The same refusal by the other route: `..` out of the workspace.
///
/// A guard that only compared prefixes textually would let this through, and it is the form
/// a model produces naturally when told "clone it next to the other one".
#[tokio::test]
async fn a_clone_that_climbs_out_with_dot_dot_is_refused() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    repo_with_one_commit(&source);

    let client_id = client_in(&state, &root, &source, false).await;

    let result = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": source.display().to_string(),
                "path": "../climbed-out",
            }),
            Duration::from_secs(20),
        )
        .await;

    let err = result.expect_err("`..` must not escape").to_string();
    assert!(err.contains(ALLOWED_ROOT_PARAM), "got: {err}");
    assert!(
        !temp.path().join("climbed-out").exists(),
        "the clone must not have happened"
    );
}

/// A clone *inside* the workspace still works. Confinement that also blocks the legitimate
/// case is not a fix, and this is what would catch an over-tight `starts_with`.
#[tokio::test]
async fn a_clone_inside_the_workspace_still_works() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    repo_with_one_commit(&source);

    let client_id = client_in(&state, &root, &source, false).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": source.display().to_string(),
                // Relative, which is the form the startup examples use: it must land
                // inside the root rather than being refused for not being absolute.
                "path": "cloned-here",
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("a clone inside the workspace must succeed");

    assert!(
        format!("{outcome:?}").contains("cloned-here"),
        "got {outcome:?}"
    );
    assert!(
        root.join("cloned-here").join(".git").exists(),
        "the clone should be at {}",
        root.join("cloned-here").display()
    );
}

/// A client cannot be pointed at a repository outside its workspace at all: the connect
/// itself fails, naming the parameter.
///
/// Refusing at startup rather than at the first verb matters — every other verb operates on
/// `remote_addr`'s repository, so admitting it here would mean `git_checkout` and
/// `git_delete_branch --force` reached the operator's own tree.
#[tokio::test]
async fn a_repository_outside_the_workspace_is_refused_at_connect() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();

    let outside = temp.path().join("operators-own-repo");
    std::fs::create_dir_all(&outside).unwrap();
    repo_with_one_commit(&outside);

    let (tx, _rx) = mpsc::unbounded_channel();
    let err = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(outside.display().to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            ALLOWED_ROOT_PARAM: root.display().to_string(),
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect_err("a repository outside the workspace must be refused");

    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM), "got: {err}");
}

/// `local_path` outside the workspace is refused at startup too, for the same reason: it is
/// the default clone destination, so admitting it would move the refusal to a later,
/// less obvious place.
#[tokio::test]
async fn a_local_path_outside_the_workspace_is_refused_at_connect() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();

    let (tx, _rx) = mpsc::unbounded_channel();
    let err = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some("https://example.invalid/repo.git".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            ALLOWED_ROOT_PARAM: root.display().to_string(),
            "local_path": temp.path().join("elsewhere").display().to_string(),
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect_err("a local_path outside the workspace must be refused");

    assert!(err.to_string().contains(ALLOWED_ROOT_PARAM), "got: {err}");
}

/// `git_push` is refused unless `allow_remote_writes` was set.
///
/// This is gated separately from path confinement because confinement cannot help: the
/// remote URL comes out of the cloned repository's own config and the push carries this
/// client's credentials, so no allow-list of local directories bounds where it goes.
#[tokio::test]
async fn git_push_is_refused_unless_remote_writes_were_opted_into() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    repo_with_one_commit(&repo);

    let client_id = client_in(&state, &root, &repo, false).await;

    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "git_push", "remote": "origin"}),
            Duration::from_secs(20),
        )
        .await
        .expect_err("git_push must be refused by default")
        .to_string();

    assert!(
        err.contains(ALLOW_REMOTE_WRITES_PARAM),
        "the refusal must name the parameter that opens it, got: {err}"
    );

    // And the refusal must come from the gate, not from git2 failing to find a remote —
    // otherwise the test would pass on an unconfigured repository whatever the gate did.
    assert!(
        !err.contains("remote 'origin' does not exist"),
        "the gate must refuse before git2 is reached, got: {err}"
    );
}

/// Deleting a *remote* branch is gated; deleting a local one is not.
///
/// The asymmetry is the decision worth pinning. A local `--force` delete destroys history
/// inside a scratch clone, which is what a scratch clone is for; gating it would train the
/// operator to leave the flag on for routine work, and an opt-in that is always on means
/// nothing. Deleting a branch on a real forge is not recoverable by deleting the workspace.
#[tokio::test]
async fn only_the_remote_half_of_delete_branch_is_gated() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    repo_with_one_commit(&repo);

    let client_id = client_in(&state, &root, &repo, false).await;

    // Remote half: refused, naming the parameter.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_delete_branch",
                "branch": "feature",
                "remote": "origin",
            }),
            Duration::from_secs(20),
        )
        .await
        .expect_err("deleting a remote branch must be refused by default")
        .to_string();
    assert!(err.contains(ALLOW_REMOTE_WRITES_PARAM), "got: {err}");

    // Local half: reaches git2, which reports the branch does not exist. That is the point
    // — it was not stopped by the gate.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_delete_branch",
                "branch": "no-such-branch",
                "force": true,
            }),
            Duration::from_secs(20),
        )
        .await
        .expect_err("git2 should report the missing branch")
        .to_string();
    assert!(
        !err.contains(ALLOW_REMOTE_WRITES_PARAM),
        "a local branch delete must NOT be gated, got: {err}"
    );
}

/// Every path-touching verb is confined, not just the two that take a path parameter.
///
/// The rest reach the filesystem through the session's `repo_path`, and the check lives in
/// `require_repo()` so that each of them performs it. This walks the list and asserts they
/// all refuse once the repository has been moved out from under them — the case the
/// connect-time and clone-time checks structurally cannot catch.
#[tokio::test]
async fn every_repository_verb_rechecks_confinement() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    repo_with_one_commit(&repo);

    let client_id = client_in(&state, &root, &repo, true).await;

    // Sanity: the verbs work while the repository is inside the workspace.
    state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "git_status"}),
            Duration::from_secs(20),
        )
        .await
        .expect("git_status inside the workspace");

    // Now move the repository out of the workspace, leaving a symlink where it was. The
    // session still holds the old path; a check done only at connect would never see this.
    let relocated = temp.path().join("relocated-repo");
    std::fs::rename(&repo, &relocated).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&relocated, &repo).unwrap();

    // Every verb that acts on the open repository.
    for action in [
        serde_json::json!({"type": "git_status"}),
        serde_json::json!({"type": "git_log", "max_count": 1}),
        serde_json::json!({"type": "git_diff"}),
        serde_json::json!({"type": "git_list_branches"}),
        serde_json::json!({"type": "git_list_tags"}),
        serde_json::json!({"type": "git_fetch", "remote": "origin"}),
        serde_json::json!({"type": "git_pull", "remote": "origin"}),
        serde_json::json!({"type": "git_push", "remote": "origin"}),
        serde_json::json!({"type": "git_checkout", "target": "main"}),
        serde_json::json!({"type": "git_delete_branch", "branch": "x", "force": true}),
        serde_json::json!({"type": "git_create_tag", "name": "v1"}),
    ] {
        let name = action["type"].as_str().unwrap().to_string();
        // A sandbox refusal surfaces as `Err` from `send_to_client`: `command_loop` maps
        // only a protocol-level rejection to `Ok(Rejected)` and passes everything else —
        // which includes anything `run_git_operation` returns `Err` for — straight through.
        match state
            .send_to_client(client_id, action, Duration::from_secs(20))
            .await
        {
            Err(e) => assert!(
                e.to_string().contains(ALLOWED_ROOT_PARAM),
                "{name} failed, but not because of confinement: {e}"
            ),
            Ok(outcome) => {
                panic!("{name} ran against a repository outside the workspace: {outcome:?}")
            }
        }
    }
}

/// A `file://` clone source outside the workspace is refused.
///
/// Reading someone else's repository into the workspace is an exfiltration step, not a
/// harmless read: once it is in the workspace, a permitted `git_push` can publish it. And
/// `file://` contains `://`, so a "has a scheme means remote" check waves it straight
/// through — which is exactly why this is asserted through the wired client and not only in
/// the classifier unit test above.
#[tokio::test]
async fn a_file_url_source_outside_the_workspace_is_refused() {
    let state = new_state().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let inside = root.join("repo");
    std::fs::create_dir_all(&inside).unwrap();
    repo_with_one_commit(&inside);

    let private = temp.path().join("operators-private-repo");
    std::fs::create_dir_all(&private).unwrap();
    repo_with_one_commit(&private);

    let client_id = client_in(&state, &root, &inside, false).await;

    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "git_clone",
                "url": format!("file://{}", private.display()),
                "path": "exfiltrated",
            }),
            Duration::from_secs(20),
        )
        .await
        .expect_err("a file:// source outside the workspace must be refused")
        .to_string();

    assert!(err.contains(ALLOWED_ROOT_PARAM), "got: {err}");
    assert!(
        !root.join("exfiltrated").exists(),
        "nothing should have been cloned"
    );
}

/// The client still starts, and still works, on the default root when no parameter is given.
///
/// A guard whose default is unusable gets turned off, so this is worth pinning: the default
/// workspace is created, and a clone into it succeeds.
#[tokio::test]
async fn the_default_workspace_is_usable_without_any_parameter() {
    let state = new_state().await;

    let root = netget::client::git::sandbox::default_root();
    // A subdirectory unique to this test, so a concurrent run cannot collide and nothing
    // outside this test's own tree is touched.
    let mine = root.join(format!("netget-sandbox-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mine);
    std::fs::create_dir_all(&mine).expect("the default root must be creatable");
    let source = mine.join("source");
    std::fs::create_dir_all(&source).unwrap();
    repo_with_one_commit(&source);

    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(source.display().to_string()),
        instruction: Some("test client".to_string()),
        // Deliberately no startup_params at all: this is the out-of-the-box configuration.
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("a repository inside the default workspace must be accepted");

    wait_for_client_handle(&state, client_id).await;
    state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "git_status"}),
            Duration::from_secs(20),
        )
        .await
        .expect("git_status in the default workspace");

    // The connected-event LLM call fails (unreachable URL) and that must not stop the
    // command loop; the `git_status` above having been answered is the proof.

    std::fs::remove_dir_all(&mine).ok();
}
