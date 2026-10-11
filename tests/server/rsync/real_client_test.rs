//! NetGet's rsync daemon against the **stock rsync 3.2.7 client** (`apt-get install rsync`),
//! which speaks protocol 29 to it. Fails rather than skips without it. What rsync wrote to disk
//! is compared byte for byte with what the model said the module holds. No LLM calls: a
//! python policy is the model.
use crate::helpers::real_server::find_binary;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
big=''.join('line %05d of the big file\n' % n for n in range(4000))
pub=[
  {'path':'hello.txt','type':'file','content':'hello\n','mtime':1704164645},
  {'path':'bin.dat','type':'file','content':'00ff10fe0d0a','encoding':'hex','mode':'600'},
  {'path':'big.txt','type':'file','content':big},
  {'path':'docs/readme.md','type':'file','content':'# Readme\n'},
  {'path':'docs/deep/x.txt','type':'file','content':'deep\n'},
  {'path':'link','type':'symlink','target':'hello.txt'},
  {'path':'empty','type':'file','content':''}]
if t=='rsync_list_modules':
  a=[{'type':'rsync_modules','modules':[{'name':'pub','comment':'public files'},{'name':'mirror','comment':'a mirror'}]}]
elif t=='rsync_upload_request':
  a=[{'type':'rsync_refuse','message':'module %s is read only' % e['module']}]
elif t=='rsync_upload_complete':
  a=[]
elif e['module']=='pub':
  a=[{'type':'rsync_send_entries','entries':pub}]
else:
  a=[{'type':'rsync_refuse','message':"Unknown module '%s'" % e['module']}]
print(json.dumps({'actions':a}))"#;

async fn start() -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "rsync".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Serve pub".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
        ]),
        startup_params: Some(json!({"motd": "Welcome to the NetGet mirror"})),
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
    (state, port)
}

/// Run the stock client; (exit code, stdout, stderr).
async fn rsync(args: &[&str]) -> (i32, String, String) {
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
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[tokio::test]
async fn stock_rsync_lists_and_downloads() {
    let (_state, port) = start().await;
    let url = |p: &str| format!("rsync://127.0.0.1:{port}/{p}");

    // (a) the module list, with the MOTD first.
    let (code, out, err) = rsync(&[&url("")]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("Welcome to the NetGet mirror"), "{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("pub") && l.ends_with("public files")),
        "{out}"
    );
    assert!(out.lines().any(|l| l.starts_with("mirror")), "{out}");

    // (b) a listing: rsync prints the sizes and names the file list carried.
    let (code, out, err) = rsync(&["--list-only", &url("pub/")]).await;
    assert_eq!(code, 0, "{out}{err}");
    for (size, name) in [("6", "hello.txt"), ("9", "link"), ("0", "empty")] {
        assert!(
            out.lines().any(|l| l.contains(size) && l.ends_with(name)),
            "{name}: {out}"
        );
    }
    assert!(
        out.lines()
            .any(|l| l.starts_with('d') && l.ends_with(" docs")),
        "{out}"
    );
    assert!(
        !out.contains("readme.md"),
        "a one-level listing went deeper: {out}"
    );

    // (c) -a of the whole module: every byte, the symlink, modes and the mtime.
    let dest = tempfile::tempdir().unwrap();
    let d = dest.path().join("m");
    let (code, out, err) = rsync(&["-a", &url("pub/"), d.to_str().unwrap()]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(read(&d.join("hello.txt")), b"hello\n");
    assert_eq!(
        read(&d.join("bin.dat")),
        [0x00, 0xff, 0x10, 0xfe, 0x0d, 0x0a]
    );
    let big: String = (0..4000)
        .map(|n| format!("line {n:05} of the big file\n"))
        .collect();
    assert_eq!(
        read(&d.join("big.txt")),
        big.as_bytes(),
        "the 100 KiB file crossed several chunks"
    );
    assert_eq!(read(&d.join("docs/readme.md")), b"# Readme\n");
    assert_eq!(read(&d.join("docs/deep/x.txt")), b"deep\n");
    assert_eq!(read(&d.join("empty")), b"");
    assert_eq!(
        std::fs::read_link(d.join("link")).unwrap(),
        Path::new("hello.txt")
    );
    let meta = std::fs::metadata(d.join("hello.txt")).unwrap();
    assert_eq!(meta.mtime(), 1704164645);
    assert_eq!(meta.permissions().mode() & 0o777, 0o644);
    assert_eq!(
        std::fs::metadata(d.join("bin.dat"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // One named file, no options.
    let one = dest.path().join("one");
    std::fs::create_dir(&one).unwrap();
    let (code, out, err) = rsync(&[&url("pub/docs/readme.md"), one.to_str().unwrap()]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(read(&one.join("readme.md")), b"# Readme\n");

    // A second run onto the same tree: the client offers block checksums for every file it
    // has, NetGet sends whole files anyway, and the result is still identical.
    std::fs::write(d.join("hello.txt"), b"stale\n").unwrap();
    let (code, out, err) = rsync(&["-a", "--checksum", &url("pub/"), d.to_str().unwrap()]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(read(&d.join("hello.txt")), b"hello\n");

    // A dry run transfers nothing.
    let dry = dest.path().join("dry");
    let (code, out, err) = rsync(&["-an", &url("pub/"), dry.to_str().unwrap()]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(!dry.join("hello.txt").exists());
}

#[tokio::test]
async fn refusals() {
    let (_state, port) = start().await;
    let url = |p: &str| format!("rsync://127.0.0.1:{port}/{p}");
    let dest = tempfile::tempdir().unwrap();
    let d = dest.path().to_str().unwrap();

    // The model refuses a module.
    let (code, out, err) = rsync(&[&url("secret/"), d]).await;
    assert_ne!(code, 0);
    assert!(err.contains("Unknown module 'secret'"), "{out}{err}");
    // A path the module does not hold.
    let (code, _, err) = rsync(&[&url("pub/nope.txt"), d]).await;
    assert_eq!(code, 23, "{err}");
    assert!(err.contains("link_stat \"nope.txt\" failed"), "{err}");
    // An upload the model refuses: this policy's modules are read-only.
    let local = dest.path().join("up.txt");
    std::fs::write(&local, b"x").unwrap();
    let (code, _, err) = rsync(&[local.to_str().unwrap(), &url("pub/")]).await;
    assert_ne!(code, 0);
    assert!(err.contains("read only"), "{err}");
    // Compression changes the token format; refused rather than half-supported.
    let (code, _, err) = rsync(&["-z", &url("pub/hello.txt"), d]).await;
    assert_ne!(code, 0);
    assert!(err.contains("-z is not supported"), "{err}");
}
