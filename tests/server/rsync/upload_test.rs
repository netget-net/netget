//! Uploads to NetGet's rsync daemon from the **stock rsync 3.2.7 client** (a push, protocol 29).
//!
//! The client sends its file list; the model takes all or some of the files; each taken file is
//! requested whole and arrives as literal tokens checked against MD4(seed ‖ data); the contents
//! reach the model in `rsync_upload_complete`, compared here byte for byte with what was on the
//! client's disk. Nothing is written by the daemon. Fails rather than skips without rsync.
use crate::helpers::real_server::find_binary;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// `inbox` takes everything but `deny.txt`; `ro` is refused; the upload's outcome is recorded.
const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='rsync_upload_request':
  if e['module']=='ro':
    a=[{'type':'rsync_refuse','message':'module ro is read only'}]
  else:
    a=[{'type':'rsync_accept_upload','paths':[f['path'] for f in e['files'] if f['type']=='file' and not f['path'].endswith('deny.txt')]}]
else:
  a=[]
print(json.dumps({'actions':a}))"#;

async fn daemon() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "rsync".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Take uploads into inbox".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

async fn rsync(args: &[&str]) -> (i32, String) {
    let bin = find_binary("rsync").expect("rsync is required: apt-get install rsync");
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(bin).args(args).output(),
    )
    .await
    .expect("rsync did not finish")
    .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// The first `kind` event matching `pred`, waiting for it: the completion event is raised
/// after the end-of-run exchange, so it can land just after rsync has exited.
async fn event(state: &AppState, id: ServerId, kind: &str, pred: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let found = state
                .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
                .await
                .into_iter()
                .filter(|e| e.event_type == kind)
                .map(|e| e.request)
                .find(|e| pred(e));
            if let Some(e) = found {
                break e;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no matching {kind} event"))
}

fn file<'a>(complete: &'a Value, path: &str) -> &'a Value {
    complete["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == path)
        .unwrap_or_else(|| panic!("{path} not in {complete}"))
}

/// A tree with text, binary, empty and multi-chunk files, a symlink and a nested directory.
fn tree() -> (tempfile::TempDir, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("hello.txt"), b"hello\n").unwrap();
    std::fs::create_dir_all(root.join("sub/deep")).unwrap();
    std::fs::write(
        root.join("sub/bin.dat"),
        [0u8, 0xff, 0x10, 0xfe, 0x0d, 0x0a],
    )
    .unwrap();
    std::fs::write(root.join("sub/deep/empty"), b"").unwrap();
    // Larger than one 32 KiB literal token, so the client splits it.
    let big: Vec<u8> = (0..100_000u32).map(|n| b'a' + (n % 26) as u8).collect();
    std::fs::write(root.join("big.txt"), &big).unwrap();
    std::fs::write(root.join("deny.txt"), b"not wanted\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    (dir, big)
}

#[tokio::test]
async fn stock_rsync_pushes_a_tree_and_the_model_takes_part_of_it() {
    let (state, id, port) = daemon().await;
    let (src, big) = tree();
    let from = format!("{}/", src.path().display());
    let (code, out) = rsync(&["-rl", &from, &format!("rsync://127.0.0.1:{port}/inbox/up/")]).await;
    // deny.txt was refused, so the run is partial: rsync's own exit code for that.
    assert_eq!(code, 23, "{out}");
    assert!(out.contains("deny.txt: refused by the daemon"), "{out}");

    let request = &event(&state, id, "rsync_upload_request", |_| true).await;
    assert_eq!(request["module"], "inbox");
    assert_eq!(request["path"], "up/");
    assert_eq!(
        request["file_count"], 5,
        "hello, bin.dat, empty, big and deny; link is a symlink"
    );
    let complete = &event(&state, id, "rsync_upload_complete", |_| true).await;
    assert_eq!(file(complete, "up/hello.txt")["content"], "hello\n");
    assert_eq!(file(complete, "up/sub/bin.dat")["content"], "00ff10fe0d0a");
    assert_eq!(file(complete, "up/sub/bin.dat")["encoding"], "hex");
    assert_eq!(file(complete, "up/sub/deep/empty")["size"], 0);
    assert_eq!(
        file(complete, "up/big.txt")["content"],
        String::from_utf8(big).unwrap()
    );
    assert_eq!(file(complete, "up/link")["type"], "symlink");
    assert_eq!(file(complete, "up/sub/deep")["type"], "dir");
    assert_eq!(
        complete["refused"],
        json!([{"path": "up/deny.txt", "reason": "refused by the daemon"}])
    );
    assert!(complete["files"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["path"] != "up/deny.txt"));
}

/// A single file into the module root, with -a (times, permissions, owner and group in the list).
#[tokio::test]
async fn stock_rsync_pushes_one_file_with_archive_mode() {
    let (state, id, port) = daemon().await;
    let src = tempfile::tempdir().unwrap();
    let one = src.path().join("note.txt");
    std::fs::write(&one, "a note\n").unwrap();
    let (code, out) = rsync(&[
        "-a",
        one.to_str().unwrap(),
        &format!("rsync://127.0.0.1:{port}/inbox/"),
    ])
    .await;
    assert_eq!(code, 0, "{out}");
    let complete = &event(&state, id, "rsync_upload_complete", |_| true).await;
    assert_eq!(file(complete, "note.txt")["content"], "a note\n");
    assert_eq!(complete["refused"], json!([]));
}

#[tokio::test]
async fn refused_uploads_and_unsupported_options() {
    let (state, id, port) = daemon().await;
    let src = tempfile::tempdir().unwrap();
    let one = src.path().join("x.txt");
    std::fs::write(&one, "x\n").unwrap();
    let local = one.to_str().unwrap();
    let url = |m: &str| format!("rsync://127.0.0.1:{port}/{m}/");
    // The model refuses the module.
    let (code, out) = rsync(&[local, &url("ro")]).await;
    assert_ne!(code, 0);
    assert!(out.contains("module ro is read only"), "{out}");
    // Options a daemon that stores nothing cannot honour stop the upload before its list.
    for (flag, text) in [
        ("--delete", "--delete is not supported"),
        ("-H", "-H is not supported"),
    ] {
        let (code, out) = rsync(&["-r", flag, local, &url("inbox")]).await;
        assert_ne!(code, 0, "{flag}");
        assert!(out.contains(text), "{flag}: {out}");
    }
    // A file over the per-file bound is refused before it is requested; the rest are taken.
    let big = src.path().join("huge.bin");
    std::fs::write(
        &big,
        vec![7u8; netget::server::rsync::MAX_UPLOAD_FILE_BYTES as usize + 1],
    )
    .unwrap();
    let (code, out) = rsync(&[local, big.to_str().unwrap(), &url("inbox")]).await;
    assert_eq!(code, 23, "{out}");
    assert!(
        out.contains("huge.bin: larger than this daemon accepts"),
        "{out}"
    );
    let last = event(&state, id, "rsync_upload_complete", |c| {
        c["refused"].to_string().contains("huge.bin")
    })
    .await;
    assert_eq!(file(&last, "x.txt")["content"], "x\n");
    // Exactly at the bound is taken.
    let at = src.path().join("at.bin");
    std::fs::write(
        &at,
        vec![7u8; netget::server::rsync::MAX_UPLOAD_FILE_BYTES as usize],
    )
    .unwrap();
    let (code, out) = rsync(&[at.to_str().unwrap(), &url("inbox")]).await;
    assert_eq!(code, 0, "{out}");
}
