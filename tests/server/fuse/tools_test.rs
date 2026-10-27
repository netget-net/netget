//! Ordinary tools on the mount: coreutils, findutils and Python, each a separate process the
//! kernel's FUSE driver serves through NetGet. What each tool sees is asserted against the
//! description, and so is what the model was asked: reads cost nothing, each directory is
//! described once, and each change is one decision.
use super::support::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The model: a root with text, a described disk image, a file with a failing region, an
/// inline-described directory, a lazily described one, a refused one, a symlink and a 0444
/// file; writes to README.txt and refused.txt are refused, everything else is allowed.
pub const POLICY: &str = r#"import json,sys
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

/// data.bin as described: 12 KiB of zeroes, deadbeef at 0, 4 KiB of 0xAB at 4096, "tail" at
/// 10000.
pub fn data_bin() -> Vec<u8> {
    let mut d = vec![0u8; 12288];
    d[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    d[4096..8192].fill(0xab);
    d[10000..10004].copy_from_slice(b"tail");
    d
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Python, as a separate process: walk the mount, stat everything, read every file and link.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_tools_read_the_description_and_change_the_overlay() {
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
        m.text(r#"stat -c '%s %a %F %Y' "$M/README.txt""#).await,
        "18 644 regular file 1700000000"
    );
    assert_eq!(
        m.text(r#"stat -c '%a %F' "$M/readonly.txt" "$M/docs""#)
            .await,
        "444 regular file\n755 directory"
    );
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello from netget\n");
    // At offsets, through dd and head.
    assert_eq!(
        m.ok(r#"dd if="$M/data.bin" bs=4096 skip=1 count=1 status=none"#)
            .await,
        vec![0xab; 4096]
    );
    assert_eq!(
        m.ok(r#"dd if="$M/data.bin" bs=1 skip=10000 count=4 status=none"#)
            .await,
        b"tail"
    );
    assert_eq!(
        m.ok(r#"head -c 4 "$M/data.bin""#).await,
        vec![0xde, 0xad, 0xbe, 0xef]
    );
    let expected = data_bin();
    assert_eq!(
        m.text(r#"sha256sum "$M/data.bin" | cut -d' ' -f1"#).await,
        sha256_hex(&expected)
    );
    // A failing region: the first page reads, the second is the errno the model named.
    assert_eq!(m.ok(r#"head -c 4 "$M/bad.bin""#).await, b"good");
    m.fails(r#"cat "$M/bad.bin" > /dev/null"#, "Input/output error")
        .await;
    // Symlinks.
    assert_eq!(m.text(r#"readlink "$M/latest""#).await, "README.txt");
    assert_eq!(m.ok(r#"cat "$M/latest""#).await, b"hello from netget\n");
    // find walks everything: /src is described when first visited; /docs came inline and is
    // never asked about; /locked is refused once and stays refused.
    let find = m.sh(r#"find "$M" | sort"#).await;
    let listed = String::from_utf8_lossy(&find.stdout);
    for rel in ["docs/guide.md", "src/main.rs", "latest", "locked"] {
        assert!(
            listed.contains(&format!("/mnt/{rel}")),
            "find lists {rel}: {listed}"
        );
    }
    assert!(
        String::from_utf8_lossy(&find.stderr).contains("Permission denied"),
        "find reports the refused directory: {:?}",
        String::from_utf8_lossy(&find.stderr)
    );
    m.fails(r#"ls "$M/locked""#, "Permission denied").await;
    m.fails(r#"ls "$M/locked""#, "Permission denied").await;
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
    assert_eq!(walked["docs"]["dir"], json!(true));
    assert_eq!(
        walked["errors"],
        json!(["Permission denied"]),
        "os.walk could not list /locked: {walked}"
    );

    // ---- cp out: byte for byte.
    m.ok(r#"cp "$M/data.bin" "$T/out.bin""#).await;
    assert_eq!(
        std::fs::read(m.dir.path().join("out.bin")).unwrap(),
        expected
    );

    // ---- cp in: a create and one decision per write request (128 KiB each).
    let upload: Vec<u8> = (0..300 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(m.dir.path().join("upload.bin"), &upload).unwrap();
    m.ok(r#"cp "$T/upload.bin" "$M/docs/upload.bin""#).await;
    m.ok(r#"cmp "$T/upload.bin" "$M/docs/upload.bin""#).await;
    assert_eq!(
        m.text(r#"sha256sum "$M/docs/upload.bin" | cut -d' ' -f1"#)
            .await,
        sha256_hex(&upload)
    );
    assert_eq!(m.paths("fuse_create").await, vec!["/docs/upload.bin"]);
    let writes = m.events("fuse_write").await;
    let offsets: Vec<u64> = writes
        .iter()
        .map(|w| w["offset"].as_u64().unwrap())
        .collect();
    assert_eq!(
        offsets,
        vec![0, 131072, 262144],
        "cp writes in 128 KiB requests"
    );
    assert_eq!(writes[0]["length"], json!(131072));
    assert_eq!(writes[2]["length"], json!(300 * 1024 - 262144));
    assert_eq!(writes[0]["encoding"], json!("hex"));
    assert_eq!(writes[0]["data_truncated"], json!(true));
    assert_eq!(writes[0]["path"], json!("/docs/upload.bin"));
    assert!(writes[0]["process"].as_str().unwrap().starts_with("cp"));
    assert!(writes[0]["pid"].as_u64().unwrap() > 0);

    // ---- mv: one rename decision, the content follows.
    m.ok(r#"mv "$M/docs/upload.bin" "$M/src/moved.bin""#).await;
    m.ok(r#"cmp "$T/upload.bin" "$M/src/moved.bin""#).await;
    m.fails(r#"ls "$M/docs/upload.bin""#, "No such file").await;
    let renames = m.events("fuse_rename").await;
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0]["path"], json!("/docs/upload.bin"));
    assert_eq!(renames[0]["new_path"], json!("/src/moved.bin"));
    assert_eq!(renames[0]["replaces"], json!(false));

    // ---- mkdir and rmdir; a made directory is never described.
    m.ok(r#"mkdir "$M/newdir""#).await;
    assert_eq!(m.text(r#"stat -c '%F' "$M/newdir""#).await, "directory");
    assert_eq!(m.text(r#"ls -A "$M/newdir" | wc -l"#).await, "0");
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

    // ---- chmod.
    m.ok(r#"chmod 600 "$M/readonly.txt""#).await;
    assert_eq!(m.text(r#"stat -c '%a' "$M/readonly.txt""#).await, "600");
    let setattrs = m.events("fuse_setattr").await;
    assert!(
        setattrs
            .iter()
            .any(|e| e["path"] == "/readonly.txt" && e["mode"] == json!(0o600)),
        "chmod asked with the mode: {setattrs:?}"
    );

    // ---- truncate, shrinking then growing: the hidden tail reads as zeroes.
    m.ok(r#"truncate -s 5 "$M/README.txt""#).await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello");
    m.ok(r#"truncate -s 10 "$M/README.txt""#).await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello\0\0\0\0\0");
    let truncs = m.events("fuse_truncate").await;
    assert_eq!(truncs.len(), 2);
    assert_eq!(truncs[0]["size"], json!(5));
    assert_eq!(truncs[0]["size_before"], json!(18));

    // ---- Refused writes leave the overlay as it was.
    let free_before = m.text(r#"stat -f -c '%f' "$M""#).await;
    m.fails(
        r#"printf XYZ | dd of="$M/README.txt" bs=3 count=1 conv=notrunc status=none"#,
        "Permission denied",
    )
    .await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello\0\0\0\0\0");
    m.fails(
        r#"printf abc | dd of="$M/refused.txt" status=none"#,
        "No space left on device",
    )
    .await;
    assert_eq!(m.text(r#"stat -c '%s' "$M/refused.txt""#).await, "0");
    assert_eq!(
        m.text(r#"stat -f -c '%f' "$M""#).await,
        free_before,
        "no overlay page was taken by a refused write"
    );
    let refused: Vec<Value> = m
        .events("fuse_write")
        .await
        .into_iter()
        .filter(|w| w["path"] == "/README.txt" || w["path"] == "/refused.txt")
        .collect();
    assert_eq!(refused.len(), 2, "each refused write was one decision");
    assert_eq!(refused[0]["data"], json!("XYZ"));
    assert_eq!(refused[0]["encoding"], json!("utf8"));

    // ---- rm.
    m.ok(r#"rm "$M/src/moved.bin""#).await;
    m.fails(r#"ls "$M/src/moved.bin""#, "No such file").await;
    let unlinks = m.events("fuse_unlink").await;
    assert_eq!(unlinks.len(), 1);
    assert_eq!(unlinks[0]["path"], json!("/src/moved.bin"));
    assert_eq!(unlinks[0]["kind"], json!("file"));

    // Still exactly three descriptions after all of it.
    assert_eq!(m.events("fuse_describe_directory").await.len(), 3);
    m.stop().await;
    assert!(
        eventually(10, || !mounted_at(&m.path)).await,
        "stop unmounts"
    );
}
