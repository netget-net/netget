//! macOS: BSD userland and Python on a FUSE-T mount, each a separate process that macOS's NFS
//! client serves through FUSE-T's go-nfsv4 and NetGet. What each tool sees is asserted against
//! the description, and so is what the model was asked: reads cost nothing, each directory is
//! described once, each change is a decision.
//!
//! **These mount FUSE-T.** `require_fuse` fails unless `NETGET_FUSE_MACOS_MOUNT=1`, which says
//! the operator accepts mounting FUSE-T on this Mac: a FUSE-T mount is an NFS mount, and Apple's
//! NFS client can panic the host under attribute churn (FUSE-T issue #109, Apple FB23527406). No
//! CI job runs them; they are run by hand, one at a time, in the order `tests/server/fuse/AGENTS.md`
//! gives. Each test makes its own mount and depends on no other: the reads, the writes and the
//! AppleDouble sidecar tests are separate so the read-only checks can run alone.
//!
//! Where NFS makes macOS differ from Linux, the test says so where it asserts it: a read is an
//! NFS READ of up to 128 KiB, so a file with a failing region fails to read wherever that chunk
//! covers it; a write is decided when the client writes back, so a refusal reaches the process
//! at `close` (or `fsync`); NFS carries no pid, so events say `pid` 0 and no process name; and
//! extended attributes land in AppleDouble `._` sidecars, which this volume accepts and discards
//! without asking the model (FUSE-T is not given `--namedattr`; see `macos.rs` and
//! `appledouble.rs`).
use super::support::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The model, as on Linux (`tools_test::POLICY`): a root with text, a described disk image, a
/// file with a failing region, an inline-described directory, a lazily described one, a refused
/// one, a symlink and a 0444 file; writes to README.txt and refused.txt are refused, everything
/// else is allowed.
const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; p=e.get('path','')
D='fuse_directory'
if t=='fuse_describe_directory':
  if p=='/':
    a={'type':D,'entries':[
      {'name':'README.txt','kind':'file','text':'hello from netget\n','mode':420,'mtime':1700000000},
      {'name':'data.bin','kind':'file','size':12288,'extents':[{'offset':0,'hex':'deadbeef'},{'offset':4096,'length':4096,'fill':171},{'offset':10000,'text':'tail'}]},
      {'name':'bad.bin','kind':'file','size':8192,'text':'good','errors':[{'offset':4096,'length':4096,'error':'EIO'}]},
      {'name':'docs','kind':'dir','entries':[{'name':'guide.md','kind':'file','text':'# Guide\n'}]},
      {'name':'src','kind':'dir'},
      {'name':'locked','kind':'dir'},
      {'name':'latest','kind':'symlink','target':'README.txt'},
      {'name':'readonly.txt','kind':'file','text':'frozen\n','mode':292}]}
  elif p=='/src':
    a={'type':D,'entries':[{'name':'main.rs','kind':'file','text':'fn main() {}\n'}]}
  elif p=='/locked':
    a={'type':'fuse_deny','error':'EACCES'}
  else:
    a={'type':D,'entries':[]}
elif t=='fuse_write' and p=='/refused.txt':
  a={'type':'fuse_deny','error':'ENOSPC'}
elif t=='fuse_write' and p=='/README.txt':
  a={'type':'fuse_deny','error':'EACCES'}
else:
  a={'type':'fuse_allow'}
print(json.dumps({'actions':[a]}))"#;

fn data_bin() -> Vec<u8> {
    let mut d = vec![0u8; 12288];
    d[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    d[4096..8192].fill(0xab);
    d[10000..10004].copy_from_slice(b"tail");
    d
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Python, as a separate process: walk the mount, lstat everything, read every file and link.
const PYTHON_WALK: &str = r#"import hashlib, json, os, stat, sys
root = sys.argv[1]
out = {}
for d, dirs, files in os.walk(root, onerror=lambda e: out.setdefault('errors', []).append(e.strerror)):
    for n in sorted(dirs + files):
        full = os.path.join(d, n)
        rel = os.path.relpath(full, root)
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            out[rel] = {'link': os.readlink(full)}
        elif stat.S_ISDIR(st.st_mode):
            out[rel] = {'dir': True, 'mode': stat.S_IMODE(st.st_mode)}
        else:
            try:
                with open(full, 'rb') as f:
                    data = f.read()
                out[rel] = {'size': st.st_size, 'mode': stat.S_IMODE(st.st_mode), 'sha256': hashlib.sha256(data).hexdigest()}
            except OSError as e:
                out[rel] = {'size': st.st_size, 'error': e.strerror}
print(json.dumps(out))
"#;

/// `stat -f` of `paths`, three times a second apart, must print the same thing each time:
/// inode, size, mtime, ctime and link count stand still while nothing changes them. An NFS
/// client invalidates its caches on any of them moving, and churn is what provokes Apple's
/// NFS client panic.
async fn stands_still(m: &Mounted, paths: &str) {
    let out = m
        .text(&format!(
            r#"for i in 1 2 3; do stat -f '%N %i %z %m %c %l' {paths}; echo --; sleep 1; done"#
        ))
        .await;
    let rounds: Vec<&str> = out
        .split("--")
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .collect();
    assert_eq!(rounds.len(), 3, "{out}");
    assert!(
        rounds.iter().all(|r| r == &rounds[0]),
        "attributes moved with nothing changing them:\n{out}"
    );
}

/// Read-only: nothing here changes the mount, and the model is asked nothing but descriptions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bsd_tools_read_the_description_on_macos() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);

    // ---- Reading: one description for the root, nothing else asked.
    let ls = m.text(r#"ls -la "$M""#).await;
    for name in [
        "README.txt",
        "data.bin",
        "bad.bin",
        "docs",
        "src",
        "locked",
        "readonly.txt",
        "latest -> README.txt",
    ] {
        assert!(ls.contains(name), "ls -la shows {name}: {ls}");
    }
    assert_eq!(m.paths("fuse_describe_directory").await, vec!["/"]);
    assert_eq!(
        m.text(r#"stat -f '%z %Lp %HT %m' "$M/README.txt""#).await,
        "18 644 Regular File 1700000000"
    );
    assert_eq!(
        m.text(r#"stat -f '%Lp %HT' "$M/readonly.txt" "$M/docs""#)
            .await,
        "444 Regular File\n755 Directory"
    );
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello from netget\n");
    assert_eq!(
        m.ok(r#"dd if="$M/data.bin" bs=4096 skip=1 count=1 2>/dev/null"#)
            .await,
        vec![0xab; 4096]
    );
    assert_eq!(
        m.ok(r#"dd if="$M/data.bin" bs=1 skip=10000 count=4 2>/dev/null"#)
            .await,
        b"tail"
    );
    assert_eq!(
        m.ok(r#"head -c 4 "$M/data.bin""#).await,
        vec![0xde, 0xad, 0xbe, 0xef]
    );
    let expected = data_bin();
    assert_eq!(
        m.text(r#"shasum -a 256 "$M/data.bin" | cut -d' ' -f1"#)
            .await,
        sha256_hex(&expected)
    );
    // A failing region: the errno the model named. The NFS client reads in 128 KiB chunks, so
    // the good first page fails with the bad second one (on Linux `head -c 4` reads it).
    m.fails(r#"cat "$M/bad.bin" > /dev/null"#, "Input/output error")
        .await;
    // Symlinks.
    assert_eq!(m.text(r#"readlink "$M/latest""#).await, "README.txt");
    assert_eq!(m.ok(r#"cat "$M/latest""#).await, b"hello from netget\n");
    // find: /src described when first visited, /docs inline and never asked about, /locked
    // refused once and refused every time after.
    let find = m.sh(r#"find "$M" | sort"#).await;
    let listed = String::from_utf8_lossy(&find.stdout);
    for rel in ["docs/guide.md", "src/main.rs", "latest", "locked"] {
        assert!(
            listed.contains(&format!("/mnt/{rel}")),
            "find lists {rel}: {listed}"
        );
    }
    // NetGet refuses /locked with EACCES, but FUSE-T's NFS server does not relay a readdir
    // error (its log says "readdir: 0 error 13") and the NFS client shows the directory as
    // empty, so find prints no error here as it does on Linux. What is asserted is the part
    // NetGet owns: the refusal was decided and logged, and nothing under /locked was listed.
    assert!(
        !listed.contains("/mnt/locked/"),
        "nothing inside the refused directory is listed: {listed}"
    );
    let log = m.log.lock().unwrap().join("\n");
    assert!(
        log.contains("operation=describe path=/locked decision=model_reject"),
        "the refusal of /locked was decided and logged: {:?}",
        String::from_utf8_lossy(&find.stderr)
    );
    // ls of the refused directory: an error, or (as FUSE-T relays it) an empty listing, but
    // never an entry; asked twice, because a refusal is remembered and must stay refused.
    for _ in 0..2 {
        let ls = m.sh(r#"ls "$M/locked""#).await;
        assert!(
            !ls.status.success() || ls.stdout.is_empty(),
            "the refused directory shows nothing: {:?} {:?}",
            String::from_utf8_lossy(&ls.stdout),
            String::from_utf8_lossy(&ls.stderr)
        );
    }
    let mut described = m.paths("fuse_describe_directory").await;
    described.sort();
    assert_eq!(
        described,
        vec!["/", "/locked", "/src"],
        "each directory is asked about once, an inline one never"
    );
    let census = m.census().await;
    assert_eq!(
        census.keys().collect::<Vec<_>>(),
        vec!["fuse_describe_directory"],
        "reading asked the model nothing else: {census:?}"
    );

    // ---- Attributes stand still while nothing changes them.
    stands_still(
        &m,
        r#""$M/README.txt" "$M/data.bin" "$M/docs" "$M/src/main.rs" "$M""#,
    )
    .await;

    // ---- Python as an independent reader, a separate process.
    std::fs::write(m.dir.path().join("walk.py"), PYTHON_WALK).unwrap();
    let walked: Value =
        serde_json::from_slice(&m.ok(r#"python3 "$T/walk.py" "$M""#).await).unwrap();
    assert_eq!(walked["data.bin"]["sha256"], json!(sha256_hex(&expected)));
    assert_eq!(walked["data.bin"]["size"], json!(12288));
    assert_eq!(walked["README.txt"]["mode"], json!(0o644));
    assert_eq!(
        walked["docs/guide.md"]["sha256"],
        json!(sha256_hex(b"# Guide\n"))
    );
    assert_eq!(walked["src/main.rs"]["size"], json!(13));
    assert_eq!(walked["latest"]["link"], json!("README.txt"));
    assert_eq!(walked["bad.bin"]["error"], json!("Input/output error"));
    assert_eq!(walked["errors"], json!(["Permission denied"]), "{walked}");

    // ---- cp out: byte for byte.
    m.ok(r#"cp "$M/data.bin" "$T/out.bin""#).await;
    assert_eq!(
        std::fs::read(m.dir.path().join("out.bin")).unwrap(),
        expected
    );
    let census = m.census().await;
    assert_eq!(
        census.keys().collect::<Vec<_>>(),
        vec!["fuse_describe_directory"],
        "reading asked the model nothing else: {census:?}"
    );
    m.stop().await;
    assert!(
        eventually(20, || !mounted_at(&m.path)).await,
        "stop unmounts"
    );
}

/// Every change a tool makes is one decision, allowed or refused, on a mount of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bsd_tools_change_the_overlay_through_decisions_on_macos() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);
    // The root, and /src (the lazy one) before anything moves into it.
    m.ok(r#"ls "$M" "$M/src""#).await;

    // ---- cp in: a create, and the writes decided in requests of at most 128 KiB.
    let upload: Vec<u8> = (0..300 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(m.dir.path().join("upload.bin"), &upload).unwrap();
    m.ok(r#"cp "$T/upload.bin" "$M/docs/upload.bin""#).await;
    m.ok(r#"cmp "$T/upload.bin" "$M/docs/upload.bin""#).await;
    assert_eq!(
        m.text(r#"shasum -a 256 "$M/docs/upload.bin" | cut -d' ' -f1"#)
            .await,
        sha256_hex(&upload)
    );
    assert!(
        m.paths("fuse_create")
            .await
            .contains(&"/docs/upload.bin".to_string()),
        "cp asked to create the file"
    );
    let writes: Vec<Value> = m
        .events("fuse_write")
        .await
        .into_iter()
        .filter(|w| w["path"] == "/docs/upload.bin")
        .collect();
    let total: u64 = writes.iter().map(|w| w["length"].as_u64().unwrap()).sum();
    assert!(
        total >= 300 * 1024
            && writes
                .iter()
                .all(|w| w["length"].as_u64().unwrap() <= 131072),
        "the whole file was written, in requests of at most max_write: {writes:?}"
    );
    // NFS carries the caller's uid and gid but no pid.
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    assert_eq!(writes[0]["uid"], json!(uid));
    assert_eq!(writes[0]["pid"], json!(0));

    // ---- mv: one rename decision, the content and the inode follow.
    let ino = m.text(r#"stat -f %i "$M/docs/upload.bin""#).await;
    m.ok(r#"mv "$M/docs/upload.bin" "$M/src/moved.bin""#).await;
    m.ok(r#"cmp "$T/upload.bin" "$M/src/moved.bin""#).await;
    m.fails(r#"ls "$M/docs/upload.bin""#, "No such file").await;
    assert_eq!(m.text(r#"stat -f %i "$M/src/moved.bin""#).await, ino);
    let renames = m.events("fuse_rename").await;
    assert_eq!(renames.len(), 1, "{renames:?}");
    assert_eq!(renames[0]["path"], json!("/docs/upload.bin"));
    assert_eq!(renames[0]["new_path"], json!("/src/moved.bin"));

    // ---- mkdir and rmdir.
    m.ok(r#"mkdir "$M/newdir""#).await;
    assert_eq!(m.text(r#"stat -f %HT "$M/newdir""#).await, "Directory");
    m.ok(r#"rmdir "$M/newdir""#).await;
    m.fails(r#"stat "$M/newdir""#, "No such file").await;
    assert_eq!(m.paths("fuse_mkdir").await, vec!["/newdir"]);
    assert_eq!(m.paths("fuse_rmdir").await, vec!["/newdir"]);

    // ---- ln -s and readlink.
    m.ok(r#"ln -s src/main.rs "$M/link2""#).await;
    assert_eq!(m.text(r#"readlink "$M/link2""#).await, "src/main.rs");
    assert_eq!(m.ok(r#"cat "$M/link2""#).await, b"fn main() {}\n");
    let links = m.events("fuse_symlink").await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["target"], json!("src/main.rs"));

    // ---- ln: one inode under two names.
    m.ok(r#"ln "$M/src/main.rs" "$M/hard.rs""#).await;
    assert_eq!(
        m.text(r#"stat -f %i "$M/src/main.rs""#).await,
        m.text(r#"stat -f %i "$M/hard.rs""#).await
    );
    assert_eq!(m.text(r#"stat -f %l "$M/hard.rs""#).await, "2");
    let made = m.events("fuse_link").await;
    assert_eq!(made.len(), 1);
    assert_eq!(made[0]["existing_path"], json!("/src/main.rs"));

    // ---- chmod.
    m.ok(r#"chmod 600 "$M/readonly.txt""#).await;
    assert_eq!(m.text(r#"stat -f %Lp "$M/readonly.txt""#).await, "600");
    assert!(
        m.events("fuse_setattr")
            .await
            .iter()
            .any(|e| e["path"] == "/readonly.txt" && e["mode"] == json!(0o600)),
        "chmod asked with the mode"
    );

    // ---- truncate, shrinking then growing: the hidden tail reads as zeroes.
    m.ok(r#"truncate -s 5 "$M/README.txt""#).await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello");
    m.ok(r#"truncate -s 10 "$M/README.txt""#).await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello\0\0\0\0\0");
    let truncs = m.events("fuse_truncate").await;
    assert!(truncs.iter().any(|t| t["size"] == json!(5)), "{truncs:?}");
    assert!(truncs.iter().any(|t| t["size"] == json!(10)), "{truncs:?}");

    // ---- Refused writes: the process gets the model's errno, at the write or at close (the
    // NFS client writes back when the file is closed), and the model was asked once each.
    let refused = m
        .sh(r#"printf XYZ | dd of="$M/README.txt" bs=3 count=1 conv=notrunc"#)
        .await;
    assert!(
        !refused.status.success()
            && String::from_utf8_lossy(&refused.stderr).contains("Permission denied"),
        "the refusal reaches dd: {:?}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let denied_space = m.sh(r#"printf abc | dd of="$M/refused.txt""#).await;
    assert!(
        !denied_space.status.success()
            && String::from_utf8_lossy(&denied_space.stderr).contains("No space left on device"),
        "{:?}",
        String::from_utf8_lossy(&denied_space.stderr)
    );
    let refused_events: Vec<Value> = m
        .events("fuse_write")
        .await
        .into_iter()
        .filter(|w| w["path"] == "/README.txt" || w["path"] == "/refused.txt")
        .collect();
    assert!(
        refused_events.iter().any(|w| w["data"] == json!("XYZ")),
        "{refused_events:?}"
    );
    assert!(refused_events.iter().any(|w| w["path"] == "/refused.txt"));
    // What the NFS client shows afterwards is its own cache, not the tree; reported, not
    // asserted, so the CI log says what macOS does.
    println!(
        "macOS after refused writes: README.txt reads {:?}, refused.txt is {} bytes",
        String::from_utf8_lossy(&m.ok(r#"cat "$M/README.txt""#).await),
        m.text(r#"stat -f %z "$M/refused.txt""#).await
    );
    let log = m.log.lock().unwrap().join("\n");
    assert!(log.contains("operation=write") && log.contains("decision=model_reject"));

    // ---- rm.
    m.ok(r#"rm "$M/src/moved.bin""#).await;
    m.fails(r#"ls "$M/src/moved.bin""#, "No such file").await;
    assert!(m
        .events("fuse_unlink")
        .await
        .iter()
        .any(|u| u["path"] == "/src/moved.bin"));

    // Each directory was described once, however many changes touched it.
    let mut described = m.paths("fuse_describe_directory").await;
    let all = described.len();
    described.sort();
    described.dedup();
    assert_eq!(
        described.len(),
        all,
        "a directory was described twice: {described:?}"
    );
    m.stop().await;
    assert!(
        eventually(20, || !mounted_at(&m.path)).await,
        "stop unmounts"
    );
}

/// What the model must never see on macOS: the event types it was asked about, minus the
/// directory descriptions every mount starts with.
async fn model_events_beyond_descriptions(m: &Mounted) -> Vec<String> {
    m.census()
        .await
        .into_keys()
        .filter(|k| k != "fuse_describe_directory")
        .collect()
}

/// `xattr -w` on macOS: FUSE-T is never given `--namedattr` (see `src/server/fuse/macos.rs`), so
/// the NFS client writes the attribute into an AppleDouble `._` sidecar, which this volume
/// accepts and discards (`src/server/fuse/appledouble.rs`). Whether `xattr` itself then reports
/// success depends on how macOS treats a sidecar that reads back as zeroes, so that is printed,
/// not asserted. Asserted: the model was asked nothing, no `._` name is listed, and the mount
/// stays up and readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xattr_metadata_is_accepted_and_discarded_without_asking_on_macos() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);
    m.ok(r#"ls "$M""#).await;
    let set = m.sh(r#"xattr -w user.color blue "$M/README.txt""#).await;
    let shown = m.sh(r#"xattr -l "$M/README.txt""#).await;
    println!(
        "macOS xattr -w: status {}, stderr {:?}; xattr -l then: status {}, stdout {:?}, stderr {:?}",
        set.status,
        String::from_utf8_lossy(&set.stderr),
        shown.status,
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
    assert!(
        model_events_beyond_descriptions(&m).await.is_empty(),
        "no xattr or sidecar event reached the model: {:?}",
        m.census().await
    );
    let ls = m.text(r#"ls -la "$M""#).await;
    assert!(!ls.contains("._"), "no AppleDouble name is listed: {ls}");
    assert!(mounted_at(&m.path), "the mount stays up");
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello from netget\n");
    m.stop().await;
    assert!(
        eventually(20, || !mounted_at(&m.path)).await,
        "stop unmounts"
    );
}

/// A sidecar written directly: created and written without a model event, never listed,
/// found by name with stable attributes, and its file's own attributes untouched by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sidecars_are_never_listed_and_leave_their_file_alone_on_macos() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);
    let file_attrs = r#"stat -f '%i %z %m %c %l %Lp' "$M/README.txt""#;
    m.ok(r#"ls "$M""#).await;
    let before = m.text(file_attrs).await;
    // Several writes into the sidecar, as macOS makes them.
    m.ok(r#"head -c 4096 /dev/urandom > "$M/._README.txt""#)
        .await;
    m.ok(
        r#"head -c 100 /dev/urandom | dd of="$M/._README.txt" bs=100 seek=1 conv=notrunc 2>/dev/null"#,
    )
    .await;
    assert_eq!(
        m.text(file_attrs).await,
        before,
        "the file's own attributes are untouched by its sidecar"
    );
    // Found by name, its bytes discarded (zeroes), its length the highest byte written.
    assert_eq!(
        m.text(r#"stat -f '%z %Lp' "$M/._README.txt""#).await,
        "4096 644"
    );
    assert_eq!(
        m.ok(r#"head -c 16 "$M/._README.txt""#).await,
        vec![0u8; 16],
        "a sidecar's bytes are discarded"
    );
    // Its attributes stand still while nothing writes it.
    let side = r#"stat -f '%i %z %m %c' "$M/._README.txt""#;
    let first = m.text(side).await;
    m.ok("sleep 1").await;
    assert_eq!(
        m.text(side).await,
        first,
        "a sidecar's attributes do not flap"
    );
    // Never listed, by ls or find.
    let ls = m.text(r#"ls -la "$M""#).await;
    assert!(!ls.contains("._"), "ls -la lists no sidecar: {ls}");
    let find = m.text(r#"find "$M" -name '._*'"#).await;
    assert!(find.is_empty(), "find lists no sidecar: {find}");
    // Removed like a file; mkdir of an AppleDouble name stays refused.
    m.ok(r#"rm "$M/._README.txt""#).await;
    m.fails(r#"stat "$M/._README.txt""#, "No such file").await;
    let mkdir = m.sh(r#"mkdir "$M/._dir""#).await;
    assert!(
        !mkdir.status.success(),
        "mkdir of an AppleDouble name is refused"
    );
    assert_eq!(m.text(file_attrs).await, before);
    assert!(
        model_events_beyond_descriptions(&m).await.is_empty(),
        "nothing about sidecars reached the model: {:?}",
        m.census().await
    );
    m.stop().await;
    assert!(
        eventually(20, || !mounted_at(&m.path)).await,
        "stop unmounts"
    );
}
