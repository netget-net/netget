//! NetGet's rsync client against a **stock rsync 3.2.7 daemon** (`rsync --daemon`, from
//! `apt-get install rsync`), run from a config in a temp dir and failing rather than skipping
//! without it. The daemon is at protocol 31 and steps down to NetGet's 29.
//!
//! The chain: on `rsync_ready` the model lists the modules; on the list it lists `pub/`
//! recursively; from the listing it fetches the one Markdown file it finds. Its bytes exist
//! only on the daemon, so receiving them (MD4-checked) is the model's choice served by the
//! daemon. (rsyncd's own log is no help: run as root it stops logging after "allowed access",
//! stock client against stock daemon included.) No LLM calls.
use crate::helpers::real_server::{InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const RSYNC: InstallHint = InstallHint {
    brew: "rsync",
    apt: "rsync",
};

fn config() -> String {
    // A root daemon would serve modules as nobody, who cannot read this temp dir.
    // SAFETY: geteuid has no preconditions.
    let ids = if unsafe { libc::geteuid() } == 0 {
        "uid = 0\ngid = 0\n"
    } else {
        ""
    };
    format!(
        "use chroot = no\nstrict modes = no\nmotd file = {{dir}}/motd\n{ids}\
[pub]\n    path = {{dir}}/pub\n    comment = public files\n    read only = yes\n\
[secret]\n    path = {{dir}}/secret\n    comment = private\n    auth users = alice\n    secrets file = {{dir}}/secrets\n\
[inbox]\n    path = {{dir}}/inbox\n    comment = uploads\n    read only = no\n    munge symlinks = no\n"
    )
}

async fn daemon() -> RealServer {
    RealServer::builder("rsync", RSYNC)
        .config_file("rsyncd.conf", &config())
        .config_file("motd", "Welcome to stock rsyncd")
        .config_file("secrets", "alice:s3cret\n")
        .config_file("pub/hello.txt", "hello from rsyncd\n")
        .config_file("pub/docs/guide.md", "# Guide\nstep one\n")
        .config_file("pub/docs/notes.txt", "notes\n")
        .config_file("pub/bin/data.bin", "\u{1}\u{2}\u{3}")
        .config_file("secret/s.txt", "only for alice\n")
        .config_file("inbox/README", "drop files here\n")
        .args([
            "--daemon",
            "--no-detach",
            "--config={dir}/rsyncd.conf",
            "--port={port}",
            "--address=127.0.0.1",
            "--log-file={dir}/rsyncd.log",
        ])
        .startup_timeout(Duration::from_secs(20))
        .start()
        .await
        .expect("start rsync --daemon")
}

async fn client(addr: &str, params: Value, handlers: Vec<Value>) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "rsync".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Explore the mirror".into()),
        event_handlers: Some(handlers),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect");
    (state, id)
}

async fn wait_event(state: &AppState, id: ClientId, event_type: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == event_type)
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event_type} event"))
}

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='rsync_ready': a=[{'type':'rsync_list_modules'}]
elif t=='rsync_modules': a=[{'type':'rsync_list','path':m['name']+'/','recursive':True} for m in e['modules'] if m['name']=='pub']
elif t=='rsync_listing': a=[{'type':'rsync_fetch','path':'pub/'+x['path']} for x in e['entries'] if x['path'].endswith('.md')]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn netget_client_on_stock_rsyncd() {
    let d = daemon().await;
    let (state, id) = client(
        &d.addr(),
        json!({}),
        vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}})],
    )
    .await;

    let modules = wait_event(&state, id, "rsync_modules").await;
    assert_eq!(modules["motd"], "Welcome to stock rsyncd", "{modules}");
    assert_eq!(
        modules["modules"][0],
        json!({"name": "pub", "comment": "public files"}),
        "{modules}"
    );
    assert_eq!(modules["modules"][1]["name"], "secret", "{modules}");

    let listing = wait_event(&state, id, "rsync_listing").await;
    let paths: Vec<&str> = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    // rsync's own order: "." first, files before directories, each directory then its contents.
    assert_eq!(
        paths,
        [
            ".",
            "hello.txt",
            "bin",
            "bin/data.bin",
            "docs",
            "docs/guide.md",
            "docs/notes.txt"
        ],
        "{listing}"
    );
    let hello = &listing["entries"][1];
    assert_eq!(
        (hello["type"].as_str(), hello["size"].as_u64()),
        (Some("file"), Some(18)),
        "{hello}"
    );

    let fetched = wait_event(&state, id, "rsync_fetched").await;
    assert_eq!(
        fetched["files"],
        json!([{"path": "guide.md", "size": 17, "content": "# Guide\nstep one\n", "encoding": "utf8"}]),
        "{fetched}"
    );
    // Injected: binary content comes back as hex; an unknown module is the daemon's refusal.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"rsync_fetch","path":"pub/bin/data.bin"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let ClientSendOutcome::Executed { detail } = outcome else {
        panic!("{outcome:?}")
    };
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["files"][0]["content"], "010203", "{detail}");
    assert_eq!(detail["files"][0]["encoding"], "hex", "{detail}");
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_list","path":"nosuch/"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(detail.contains("Unknown module"), "{detail}");
    // The protected module without credentials.
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_fetch","path":"secret/s.txt"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(detail.contains("requires authentication"), "{detail}");
}

#[tokio::test]
async fn password_module() {
    let d = daemon().await;
    let silent = vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})];
    let (state, id) = client(
        &d.addr(),
        json!({"username": "alice", "password": "s3cret"}),
        silent.clone(),
    )
    .await;
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_fetch","path":"secret/s.txt"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(
        detail["files"][0]["content"], "only for alice\n",
        "{detail}"
    );

    // The wrong password: the daemon's challenge-response check refuses it.
    let (state, id) = client(
        &d.addr(),
        json!({"username": "alice", "password": "nope"}),
        silent,
    )
    .await;
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_fetch","path":"secret/s.txt"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(detail.contains("auth failed"), "{detail}");
}

/// Uploads: `rsync_push` against the stock daemon's writable `[inbox]`. What lands is read
/// from the daemon's own directory, so every byte below crossed the wire and was accepted by
/// stock rsync's receiver (which checks each file's MD4 sum against the one NetGet sent).
#[tokio::test]
async fn push_to_stock_rsyncd() {
    let d = daemon().await;
    let silent = vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})];
    let (state, id) = client(&d.addr(), json!({}), silent).await;
    // Larger than one 32 KiB literal token, so the file crosses as several.
    let big: String = (0..5000).map(|i| format!("line {i:05}\n")).collect();
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_push","path":"inbox/up","files":[
                {"path":"note.txt","content":"pushed by netget\n"},
                {"path":"bin/blob.bin","content":"00ff10","encoding":"hex"},
                {"path":"deep/er/big.log","content":big},
                {"path":"link","type":"symlink","target":"note.txt"},
                {"path":"empty","type":"dir"}
            ]}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["complete"], true, "{detail}");
    assert_eq!(
        detail["sent"],
        // rsync's file-list order: a directory's files before its subdirectories.
        json!([
            {"path": "note.txt", "size": 17},
            {"path": "bin/blob.bin", "size": 3},
            {"path": "deep/er/big.log", "size": 55000}
        ]),
        "{detail}"
    );
    let up = d.dir().join("inbox/up");
    assert_eq!(
        std::fs::read_to_string(up.join("note.txt")).unwrap(),
        "pushed by netget\n"
    );
    assert_eq!(
        std::fs::read(up.join("bin/blob.bin")).unwrap(),
        [0, 0xff, 0x10]
    );
    assert_eq!(
        std::fs::read_to_string(up.join("deep/er/big.log")).unwrap(),
        big
    );
    assert_eq!(
        std::fs::read_link(up.join("link")).unwrap(),
        std::path::Path::new("note.txt")
    );
    assert!(up.join("empty").is_dir());
    // What was there before is untouched: a push adds, it never deletes.
    assert!(d.dir().join("inbox/README").exists());

    // A read-only module: the daemon refuses, and the refusal is what comes back.
    let ClientSendOutcome::Executed { detail } = state
        .send_to_client(
            id,
            json!({"type":"rsync_push","path":"pub/","files":[{"path":"x.txt","content":"x"}]}),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(detail.contains("read only"), "{detail}");
    assert!(!d.dir().join("pub/x.txt").exists());
}
