//! Hard links, extended attributes, fallocate and RENAME_EXCHANGE through the kernel's FUSE
//! driver, driven by coreutils (`ln`, `rm`, `mv`, `stat`, `cat`), findutils (`find
//! -samefile`), attr (`setfattr`, `getfattr`), util-linux (`fallocate`) and Python (`os` and
//! `ctypes` against libc), each a separate process. What each tool saw is asserted, and so is
//! what the model was asked: one decision per change, none for what the kernel or the tree
//! refuses first.
use super::support::*;
use serde_json::{json, Value};

/// The model: a root with its own xattr, a file with xattrs and a described hard link to it, a
/// described disk image and an empty directory. Refuses a link named `denied`, the xattr
/// `user.denied`, removing `user.mime_type`, any fallocate of `/nofalloc` and any rename of
/// `/noswap`; allows everything else.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; p=e.get('path','')
if t=='fuse_describe_directory':
  if p=='/':
    a={'type':'fuse_directory','xattrs':[{'name':'user.volume','text':'netget'}],'entries':[
      {'name':'README.txt','kind':'file','text':'hello\n','xattrs':[{'name':'user.mime_type','text':'text/plain'},{'name':'user.blob','hex':'00ff7f'}]},
      {'name':'README.copy','kind':'hardlink','target':'/README.txt'},
      {'name':'disk.img','kind':'file','size':16384,'extents':[{'offset':0,'length':16384,'fill':171}]},
      {'name':'docs','kind':'dir','entries':[]},
      {'name':'to-readme','kind':'symlink','target':'README.txt'}]}
  else:
    a={'type':'fuse_directory','entries':[]}
elif t=='fuse_link' and p.endswith('/denied'):
  a={'type':'fuse_deny','error':'EPERM'}
elif t=='fuse_setxattr' and e.get('name')=='user.denied':
  a={'type':'fuse_deny','error':'EACCES'}
elif t=='fuse_removexattr' and e.get('name')=='user.mime_type':
  a={'type':'fuse_deny','error':'EPERM'}
elif t=='fuse_fallocate' and p=='/nofalloc':
  a={'type':'fuse_deny','error':'ENOSPC'}
elif t=='fuse_rename' and p=='/noswap':
  a={'type':'fuse_deny','error':'EACCES'}
else:
  a={'type':'fuse_allow'}
print(json.dumps({'actions':[a]}))"#;

/// Whether this process is root in the initial user namespace: the kernel lets only that set
/// `trusted.*` and `security.*` attributes or rename with a whiteout. Root in a rootless
/// container is not.
fn real_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    euid == 0
        && map
            .split_whitespace()
            .collect::<Vec<_>>()
            .starts_with(&["0", "0", "4294967295"])
}

async fn python(m: &Mounted, name: &str, code: &str) -> Value {
    std::fs::write(m.dir.path().join(name), code).unwrap();
    let out = m.ok(&format!(r#"python3 "$T/{name}" "$M""#)).await;
    serde_json::from_slice(&out).unwrap_or_else(|e| {
        panic!(
            "{name} printed JSON: {e}: {}",
            String::from_utf8_lossy(&out)
        )
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hard_links_through_ln_rm_mv_find_and_python() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);

    // The described hard link: one inode, two names, before anything changed.
    let st = m
        .text(r#"stat -c '%i %h' "$M/README.txt" "$M/README.copy""#)
        .await;
    let lines: Vec<&str> = st.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], lines[1], "one inode: {st}");
    assert!(lines[0].ends_with(" 2"), "two links: {st}");
    assert_eq!(m.ok(r#"cat "$M/README.copy""#).await, b"hello\n");
    let ino = lines[0].split(' ').next().unwrap().to_string();

    // ln: a third name, one decision.
    m.ok(r#"ln "$M/README.txt" "$M/docs/third""#).await;
    assert_eq!(
        m.text(r#"stat -c '%i %h' "$M/docs/third""#).await,
        format!("{ino} 3")
    );
    let links = m.events("fuse_link").await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["path"], json!("/docs/third"));
    assert_eq!(links[0]["existing_path"], json!("/README.txt"));
    assert_eq!(links[0]["links"], json!(2));
    assert_eq!(links[0]["kind"], json!("file"));
    assert!(links[0]["process"].as_str().unwrap().starts_with("ln"));
    // find sees the three names as one file.
    assert_eq!(
        m.text(r#"find "$M" -samefile "$M/README.copy" | sed "s|^$M||" | sort"#)
            .await,
        "/README.copy\n/README.txt\n/docs/third"
    );
    // A write through one name reads back through the others.
    m.ok(r#"printf 'more\n' >> "$M/docs/third""#).await;
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello\nmore\n");
    assert_eq!(m.ok(r#"cat "$M/README.copy""#).await, b"hello\nmore\n");

    // mv moves one name; the count stays.
    m.ok(r#"mv "$M/docs/third" "$M/docs/moved""#).await;
    assert_eq!(
        m.text(r#"stat -c '%i %h' "$M/docs/moved""#).await,
        format!("{ino} 3")
    );
    // rm of the first name keeps the inode under the others.
    m.ok(r#"rm "$M/README.txt""#).await;
    m.fails(r#"stat "$M/README.txt""#, "No such file").await;
    assert_eq!(
        m.text(r#"stat -c '%i %h' "$M/README.copy""#).await,
        format!("{ino} 2")
    );
    assert_eq!(m.ok(r#"cat "$M/README.copy""#).await, b"hello\nmore\n");
    let unlinks = m.events("fuse_unlink").await;
    assert_eq!(unlinks.len(), 1);
    assert_eq!(unlinks[0]["links"], json!(3));

    // A refused link: the errno the model chose, and nothing changed.
    m.fails(
        r#"ln "$M/README.copy" "$M/denied""#,
        "Operation not permitted",
    )
    .await;
    m.fails(r#"stat "$M/denied""#, "No such file").await;
    assert_eq!(
        m.text(r#"stat -c '%h' "$M/README.copy""#).await,
        "2",
        "a refused link adds no name"
    );
    // A directory cannot be hard-linked: the kernel refuses it before asking anyone.
    m.fails(r#"ln "$M/docs" "$M/dirlink""#, "not allowed").await;
    // A name that exists: EEXIST from the kernel's own lookup.
    m.fails(r#"ln "$M/README.copy" "$M/disk.img""#, "File exists")
        .await;
    assert_eq!(
        m.paths("fuse_link").await,
        vec!["/docs/third", "/denied"],
        "only the two links that reached the tree's check asked the model"
    );

    // Python: open a file, remove every name, read it through the open descriptor.
    let seen = python(
        &m,
        "unlinked.py",
        r#"import json, os, sys
m = sys.argv[1]
f = open(os.path.join(m, 'README.copy'), 'rb')
os.unlink(os.path.join(m, 'README.copy'))
mid = os.fstat(f.fileno()).st_nlink
os.unlink(os.path.join(m, 'docs', 'moved'))
st = os.fstat(f.fileno())
data = f.read()
f.close()
print(json.dumps({'nlink_mid': mid, 'nlink': st.st_nlink, 'data': data.decode(),
                  'left': sorted(os.listdir(m)), 'docs': os.listdir(os.path.join(m, 'docs'))}))
"#,
    )
    .await;
    assert_eq!(seen["nlink_mid"], json!(1));
    assert_eq!(seen["nlink"], json!(0), "no name left: {seen}");
    assert_eq!(seen["data"], json!("hello\nmore\n"));
    assert_eq!(
        seen["left"],
        json!(["disk.img", "docs", "to-readme"]),
        "{seen}"
    );
    assert_eq!(seen["docs"], json!([]));
    assert_eq!(m.events("fuse_unlink").await.len(), 3);
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xattrs_through_setfattr_getfattr_and_python() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);

    // Described attributes, through getfattr: on the file, on its hard link, on the root.
    assert_eq!(
        m.text(
            r#"getfattr --absolute-names -d -e hex -m '^user\.' "$M/README.txt" | grep '^user'"#
        )
        .await,
        "user.blob=0x00ff7f\nuser.mime_type=0x746578742f706c61696e"
    );
    assert_eq!(
        m.text(r#"getfattr --absolute-names -n user.mime_type --only-values "$M/README.copy""#)
            .await,
        "text/plain"
    );
    assert_eq!(
        m.text(r#"getfattr --absolute-names -n user.volume --only-values "$M""#)
            .await,
        "netget"
    );
    m.fails(
        r#"getfattr --absolute-names -n user.nope "$M/README.txt""#,
        "No such attribute",
    )
    .await;
    // Reading asked the model nothing but the root's description.
    assert_eq!(
        m.census().await.keys().collect::<Vec<_>>(),
        vec!["fuse_describe_directory"]
    );

    // setfattr: one decision each, with the value and whether it replaces.
    m.ok(r#"setfattr -n user.color -v blue "$M/README.txt""#)
        .await;
    assert_eq!(
        m.text(r#"getfattr --absolute-names -n user.color --only-values "$M/README.copy""#)
            .await,
        "blue"
    );
    m.ok(r#"setfattr -n user.color -v red "$M/README.txt""#)
        .await;
    let sets = m.events("fuse_setxattr").await;
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0]["path"], json!("/README.txt"));
    assert_eq!(sets[0]["name"], json!("user.color"));
    assert_eq!(sets[0]["value"], json!("blue"));
    assert_eq!(sets[0]["encoding"], json!("utf8"));
    assert_eq!(sets[0]["replaces"], json!(false));
    assert_eq!(sets[0]["mode"], json!("create_or_replace"));
    assert_eq!(sets[1]["replaces"], json!(true));
    assert!(sets[0]["process"].as_str().unwrap().starts_with("setfattr"));
    // A refused set leaves nothing behind.
    m.fails(
        r#"setfattr -n user.denied -v x "$M/README.txt""#,
        "Permission denied",
    )
    .await;
    m.fails(
        r#"getfattr --absolute-names -n user.denied "$M/README.txt""#,
        "No such attribute",
    )
    .await;
    // Removal: allowed, refused, and absent (ENODATA without asking).
    m.ok(r#"setfattr -x user.color "$M/README.txt""#).await;
    m.fails(
        r#"getfattr --absolute-names -n user.color "$M/README.txt""#,
        "No such attribute",
    )
    .await;
    m.fails(
        r#"setfattr -x user.mime_type "$M/README.txt""#,
        "Operation not permitted",
    )
    .await;
    assert_eq!(
        m.text(r#"getfattr --absolute-names -n user.mime_type --only-values "$M/README.txt""#)
            .await,
        "text/plain"
    );
    m.fails(
        r#"setfattr -x user.never "$M/README.txt""#,
        "No such attribute",
    )
    .await;
    let removes: Vec<String> = m
        .events("fuse_removexattr")
        .await
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(removes, vec!["user.color", "user.mime_type"]);
    // user.* on a symlink: the kernel refuses it before it reaches the filesystem.
    m.fails(
        r#"setfattr -h -n user.x -v 1 "$M/to-readme""#,
        "Operation not permitted",
    )
    .await;

    // Python, as its own process: the flags, the bounds, ERANGE on a short buffer.
    let seen = python(
        &m,
        "xattrs.py",
        r#"import ctypes, errno, json, os, sys
m = sys.argv[1]
f = os.path.join(m, 'README.txt')
out = {}
def err(fn):
    try:
        fn(); return 'ok'
    except OSError as e:
        return errno.errorcode[e.errno]
out['create'] = err(lambda: os.setxattr(f, 'user.py', b'\x01\x02', os.XATTR_CREATE))
out['create_again'] = err(lambda: os.setxattr(f, 'user.py', b'\x03', os.XATTR_CREATE))
out['replace_missing'] = err(lambda: os.setxattr(f, 'user.nothere', b'x', os.XATTR_REPLACE))
out['replace'] = err(lambda: os.setxattr(f, 'user.py', b'\x04\x05\x06', os.XATTR_REPLACE))
out['value'] = os.getxattr(f, 'user.py').hex()
out['get_missing'] = err(lambda: os.getxattr(f, 'user.nothere'))
out['list'] = sorted(os.listxattr(f))
out['big'] = err(lambda: os.setxattr(f, 'user.big', b'z' * 65536))
out['big_len'] = len(os.getxattr(f, 'user.big'))
out['too_big'] = err(lambda: os.setxattr(f, 'user.toobig', b'z' * 65537))
out['name255'] = err(lambda: os.setxattr(f, 'user.' + 'n' * 250, b'1'))
out['name256'] = err(lambda: os.setxattr(f, 'user.' + 'n' * 251, b'1'))
out['other_namespace'] = err(lambda: os.setxattr(f, 'os2.x', b'1'))
libc = ctypes.CDLL(None, use_errno=True)
for fn in (libc.getxattr, libc.listxattr):
    fn.restype = ctypes.c_ssize_t
buf = ctypes.create_string_buffer(64)
out['size_query'] = libc.getxattr(f.encode(), b'user.mime_type', None, 0)
r = libc.getxattr(f.encode(), b'user.mime_type', buf, 1)
out['short_get'] = errno.errorcode[ctypes.get_errno()] if r < 0 else r
out['exact_get'] = libc.getxattr(f.encode(), b'user.mime_type', buf, 10)
out['exact_value'] = buf.raw[:10].decode()
r = libc.getxattr(f.encode(), b'user.nothere', buf, 64)
out['missing_get'] = errno.errorcode[ctypes.get_errno()] if r < 0 else r
r = libc.listxattr(f.encode(), buf, 4)
out['short_list'] = errno.errorcode[ctypes.get_errno()] if r < 0 else r
# The per-node bound: a fresh file takes 128 attributes and refuses the 129th.
g = os.path.join(m, 'many')
open(g, 'w').close()
n = 0
while n < 200:
    r = err(lambda: os.setxattr(g, 'user.n%d' % n, b'v'))
    if r != 'ok':
        out['many_stop'] = r
        break
    n += 1
out['many'] = n
print(json.dumps(out))
"#,
    )
    .await;
    let expect = json!({
        "create": "ok", "create_again": "EEXIST", "replace_missing": "ENODATA",
        "replace": "ok", "value": "040506", "get_missing": "ENODATA",
        "big": "ok", "big_len": 65536, "too_big": "E2BIG",
        "name255": "ok", "name256": "ERANGE", "other_namespace": "ENOTSUP",
        "size_query": 10, "short_get": "ERANGE", "exact_get": 10,
        "exact_value": "text/plain", "missing_get": "ENODATA", "short_list": "ERANGE",
        "many": 128, "many_stop": "ENOSPC",
    });
    for (k, v) in expect.as_object().unwrap() {
        assert_eq!(&seen[k], v, "{k}: {seen}");
    }
    let list: Vec<String> = serde_json::from_value(seen["list"].clone()).unwrap();
    assert_eq!(list, vec!["user.blob", "user.mime_type", "user.py"]);

    // What reached the model from Python: the allowed create and replace, the 64 KiB value,
    // the 255-byte name and 128 attributes; never the refused flags, the over-long value or
    // name, the foreign namespace or the 129th attribute.
    let names: Vec<String> = m
        .events("fuse_setxattr")
        .await
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    let py: Vec<&String> = names
        .iter()
        .filter(|n| !n.starts_with("user.n") || n.len() > 200)
        .skip(3)
        .collect();
    assert_eq!(
        py,
        vec![
            "user.py",
            "user.py",
            "user.big",
            &format!("user.{}", "n".repeat(250))
        ],
        "{names:?}"
    );
    assert_eq!(
        names
            .iter()
            .filter(|n| n.starts_with("user.n") && n.len() < 20)
            .count(),
        128
    );
    let sets = m.events("fuse_setxattr").await;
    let replace = sets.iter().find(|e| e["mode"] == "replace").unwrap();
    assert_eq!(replace["value"], json!("040506"));
    assert_eq!(replace["encoding"], json!("hex"));
    let big = sets.iter().find(|e| e["name"] == "user.big").unwrap();
    assert_eq!(big["length"], json!(65536));
    assert_eq!(big["value_truncated"], json!(true));

    // trusted.* needs CAP_SYS_ADMIN in the initial user namespace; security.* needs it in the
    // namespace that owns the mount (the initial one for fusermount3 run by an ordinary user,
    // a container's own when root in the container mounted it). The kernel checks both before
    // the filesystem hears of them, and passes them through when they pass.
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let trusted_ok = real_root();
    let security_ok = euid == 0;
    for (name, ok) in [("trusted.t", trusted_ok), ("security.s", security_ok)] {
        let before = m.events("fuse_setxattr").await.len();
        let cmd = format!(r#"setfattr -n {name} -v 1 "$M/README.txt""#);
        if ok {
            m.ok(&cmd).await;
            assert_eq!(
                m.text(&format!(
                    r#"getfattr --absolute-names -n {name} --only-values "$M/README.txt""#
                ))
                .await,
                "1"
            );
            assert_eq!(m.events("fuse_setxattr").await.len(), before + 1, "{name}");
        } else {
            m.fails(&cmd, "Operation not permitted").await;
            assert_eq!(
                m.events("fuse_setxattr").await.len(),
                before,
                "the kernel refused {name} without asking the filesystem"
            );
        }
    }
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallocate_through_util_linux_and_python() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);
    m.ok(r#"ls "$M""#).await;

    // Mode 0: the file grows and its blocks are held.
    m.ok(r#"touch "$M/fa" && fallocate -l 1048576 "$M/fa""#)
        .await;
    assert_eq!(m.text(r#"stat -c '%s %b' "$M/fa""#).await, "1048576 2048");
    assert_eq!(
        m.ok(r#"cmp -n 1048576 "$M/fa" /dev/zero && echo same"#)
            .await,
        b"same\n"
    );
    // KEEP_SIZE: blocks held past the end, the size unchanged.
    m.ok(r#"touch "$M/fb" && fallocate -n -l 65536 "$M/fb""#)
        .await;
    assert_eq!(m.text(r#"stat -c '%s %b' "$M/fb""#).await, "0 128");
    // PUNCH_HOLE|KEEP_SIZE over described bytes: that range reads as zeroes, the rest as it
    // was, and the size stays.
    m.ok(r#"fallocate -p -o 4000 -l 4296 "$M/disk.img""#).await;
    let mut want = vec![171u8; 16384];
    want[4000..8296].fill(0);
    assert_eq!(m.ok(r#"cat "$M/disk.img""#).await, want);
    assert_eq!(m.text(r#"stat -c '%s' "$M/disk.img""#).await, "16384");
    // ZERO_RANGE: zeroes and grows.
    m.ok(r#"fallocate -z -o 16000 -l 1000 "$M/disk.img""#).await;
    want[16000..].fill(0);
    want.resize(17000, 0);
    assert_eq!(m.ok(r#"cat "$M/disk.img""#).await, want);
    // ZERO_RANGE|KEEP_SIZE: zeroes, keeps the size.
    m.ok(r#"fallocate -z -n -o 0 -l 10 "$M/disk.img""#).await;
    want[..10].fill(0);
    assert_eq!(m.ok(r#"cat "$M/disk.img""#).await, want);

    let falloc = m.events("fuse_fallocate").await;
    let ops: Vec<(String, bool, u64, u64)> = falloc
        .iter()
        .map(|e| {
            (
                e["operation"].as_str().unwrap().to_string(),
                e["keep_size"].as_bool().unwrap(),
                e["offset"].as_u64().unwrap(),
                e["length"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        ops,
        vec![
            ("allocate".to_string(), false, 0, 1048576),
            ("allocate".to_string(), true, 0, 65536),
            ("punch_hole".to_string(), true, 4000, 4296),
            ("zero_range".to_string(), false, 16000, 1000),
            ("zero_range".to_string(), true, 0, 10),
        ]
    );
    assert_eq!(falloc[2]["size_before"], json!(16384));
    assert!(falloc[0]["process"]
        .as_str()
        .unwrap()
        .starts_with("fallocate"));

    // COLLAPSE_RANGE and INSERT_RANGE: not supported, and the model is never asked.
    m.fails(
        r#"fallocate -c -o 0 -l 4096 "$M/fa""#,
        "Operation not supported",
    )
    .await;
    m.fails(
        r#"fallocate -i -o 0 -l 4096 "$M/fa""#,
        "Operation not supported",
    )
    .await;
    // A refused fallocate: the model's errno, nothing allocated.
    m.fails(
        r#"touch "$M/nofalloc" && fallocate -l 4096 "$M/nofalloc""#,
        "No space left on device",
    )
    .await;
    assert_eq!(m.text(r#"stat -c '%s %b' "$M/nofalloc""#).await, "0 0");
    assert_eq!(m.events("fuse_fallocate").await.len(), 6);

    // Python's os.posix_fallocate, in its own process.
    let seen = python(
        &m,
        "falloc.py",
        r#"import json, os, sys
p = os.path.join(sys.argv[1], 'py.bin')
fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o644)
os.posix_fallocate(fd, 0, 12345)
st = os.fstat(fd)
os.close(fd)
print(json.dumps({'size': st.st_size, 'blocks': st.st_blocks}))
"#,
    )
    .await;
    assert_eq!(seen, json!({"size": 12345, "blocks": 32}));
    let last = m.events("fuse_fallocate").await.pop().unwrap();
    assert_eq!(last["path"], json!("/py.bin"));
    assert_eq!(last["operation"], json!("allocate"));
    assert_eq!(last["length"], json!(12345));
    m.stop().await;
}

/// renameat2 through ctypes: Python's os has no binding for its flags.
const RENAMEAT2: &str = r#"import ctypes, errno, json, os, sys
m = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
EXCHANGE, NOREPLACE, WHITEOUT = 2, 1, 4
def ren(a, b, flags):
    r = libc.renameat2(AT_FDCWD, os.path.join(m, a).encode(), AT_FDCWD, os.path.join(m, b).encode(), flags)
    return 'ok' if r == 0 else errno.errorcode[ctypes.get_errno()]
def read(p):
    with open(os.path.join(m, p)) as f:
        return f.read()
out = {}
for name, text in (('a', 'apple'), ('b', 'banana'), ('noswap', 'stay')):
    with open(os.path.join(m, name), 'w') as f:
        f.write(text)
os.mkdir(os.path.join(m, 'dir'))
out['swap'] = ren('a', 'b', EXCHANGE)
out['a'], out['b'] = read('a'), read('b')
out['swap_dir'] = ren('a', 'dir', EXCHANGE)
out['a_is_dir'] = os.path.isdir(os.path.join(m, 'a'))
out['dir_text'] = read('dir')
out['swap_missing'] = ren('b', 'nothing', EXCHANGE)
out['noreplace'] = ren('b', 'dir', NOREPLACE)
out['refused'] = ren('noswap', 'b', EXCHANGE)
out['noswap'], out['b_after'] = read('noswap'), read('b')
out['whiteout'] = ren('b', 'white', WHITEOUT)
out['both'] = ren('b', 'dir', EXCHANGE | NOREPLACE)
print(json.dumps(out))
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_exchange_through_renameat2() {
    let m = mount(policy(POLICY), json!({"decision_timeout_secs": 30})).await;
    let _diag = OnFailure(&m);
    m.ok(r#"ls "$M""#).await;
    let seen = python(&m, "exchange.py", RENAMEAT2).await;
    assert_eq!(seen["swap"], json!("ok"), "{seen}");
    assert_eq!(
        (&seen["a"], &seen["b"]),
        (&json!("banana"), &json!("apple"))
    );
    assert_eq!(seen["swap_dir"], json!("ok"));
    assert_eq!(seen["a_is_dir"], json!(true));
    assert_eq!(seen["dir_text"], json!("banana"));
    assert_eq!(seen["swap_missing"], json!("ENOENT"));
    assert_eq!(seen["noreplace"], json!("EEXIST"));
    assert_eq!(seen["refused"], json!("EACCES"));
    assert_eq!(
        (&seen["noswap"], &seen["b_after"]),
        (&json!("stay"), &json!("apple"))
    );
    // A whiteout reaches the filesystem whoever asks (Linux 5.8 dropped the CAP_MKNOD check),
    // and this one refuses it.
    assert_eq!(seen["whiteout"], json!("EINVAL"), "{seen}");
    assert_eq!(seen["both"], json!("EINVAL"));
    let renames = m.events("fuse_rename").await;
    let exchanges: Vec<(&str, &str)> = renames
        .iter()
        .filter(|e| e["exchange"] == json!(true))
        .map(|e| (e["path"].as_str().unwrap(), e["new_path"].as_str().unwrap()))
        .collect();
    assert_eq!(
        exchanges,
        vec![("/a", "/b"), ("/a", "/dir"), ("/noswap", "/b")],
        "one decision per exchange that reached the tree; none for the missing name, \
         NOREPLACE, the whiteout or the contradiction"
    );
    assert_eq!(renames.len(), 3);
    m.stop().await;
}
