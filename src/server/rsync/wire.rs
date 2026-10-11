//! rsync's daemon protocol, pinned at **protocol 29**: the `@RSYNCD:` text handshake, the
//! argument list, multiplexed framing, the file list, and the MD4 checksums. Shared by the
//! daemon (`src/server/rsync/`) and the client (`src/client/rsync/`).
//!
//! Why 29: it is the smallest version rsync 3.2.7 still speaks in full. There are no
//! compat flags, no checksum or compression negotiation, no incremental recursion, plain int32
//! file indexes, fixed-width file-list fields, and a client→daemon direction that is never
//! multiplexed. Everything is MD4: the whole-file sum is MD4(le32(seed) ‖ data). Advertise
//! exactly `29.0`: a non-zero sub-version makes a 3.2.7 peer drop to 28.
use anyhow::{bail, ensure, Context, Result};
use md4::{Digest, Md4};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const PROTOCOL: i32 = 29;
pub const GREETING: &str = "@RSYNCD: 29.0\n";
pub const NDX_DONE: i32 = -1;
const MPLEX_BASE: u8 = 7;
pub const MSG_DATA: u8 = 0;
pub const MSG_ERROR_XFER: u8 = 1;
pub const MSG_INFO: u8 = 2;
pub const MSG_ERROR: u8 = 3;
pub const MSG_WARNING: u8 = 4;
pub const MSG_IO_ERROR: u8 = 22;
pub const MSG_NOOP: u8 = 42;
pub const MSG_ERROR_EXIT: u8 = 86;

pub const ITEM_TRANSFER: u16 = 0x8000;
pub const ITEM_IS_NEW: u16 = 0x2000;
pub const ITEM_XNAME_FOLLOWS: u16 = 0x1000;
pub const ITEM_BASIS_TYPE_FOLLOWS: u16 = 0x0800;

const XMIT_TOP_DIR: u16 = 0x01;
const XMIT_SAME_MODE: u16 = 0x02;
const XMIT_EXTENDED_FLAGS: u16 = 0x04;
const XMIT_SAME_UID: u16 = 0x08;
const XMIT_SAME_GID: u16 = 0x10;
const XMIT_SAME_NAME: u16 = 0x20;
const XMIT_LONG_NAME: u16 = 0x40;
const XMIT_SAME_TIME: u16 = 0x80;

/// Literal data is sent in pieces of at most this many bytes (rsync's CHUNK_SIZE).
pub const CHUNK: usize = 32 * 1024;
/// A text line of the handshake, an argument, or a module line.
pub const MAX_LINE: usize = 4096;
pub const MAX_ARGS: usize = 64;
/// A file-list name.
pub const MAX_NAME: usize = 4096;
/// Entries in one file list.
pub const MAX_ENTRIES: usize = 100_000;
/// Total bytes of filter rules a client may send.
pub const MAX_FILTER_BYTES: usize = 64 * 1024;
/// Block checksums one request may carry (count × (4 + s2length) bytes are read and dropped).
pub const MAX_SUM_COUNT: i32 = 1 << 20;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
        }
    }
    pub fn of_mode(mode: u32) -> Option<Self> {
        match mode & S_IFMT {
            S_IFREG => Some(Kind::File),
            S_IFDIR => Some(Kind::Dir),
            S_IFLNK => Some(Kind::Symlink),
            _ => None,
        }
    }
}

/// One file-list entry. `path` is relative to the transfer root, `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    /// Regular files: the bytes. Symlinks: the target. Directories: empty.
    pub data: Vec<u8>,
    pub mode: u32,
    pub mtime: u32,
    pub uid: u32,
    pub gid: u32,
    /// Size as the list says it (a received list carries no data until it is fetched).
    pub size: u64,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }
}

pub fn le32(x: i32) -> [u8; 4] {
    x.to_le_bytes()
}

pub fn longint(x: u64) -> Vec<u8> {
    if x <= 0x7fff_ffff {
        (x as i32).to_le_bytes().to_vec()
    } else {
        let mut v = vec![0xff; 4];
        v.extend_from_slice(&(x as i64).to_le_bytes());
        v
    }
}

/// MD4 over the pieces, in order.
pub fn md4(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md4::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The whole-file checksum at protocol 29: MD4(le32(seed) ‖ data), the seed always first.
pub fn file_sum(seed: i32, data: &[u8]) -> [u8; 16] {
    md4(&[&seed.to_le_bytes(), data])
}

/// The `-c` file-list checksum: MD4 of the contents, unseeded.
pub fn list_sum(data: &[u8]) -> [u8; 16] {
    md4(&[data])
}

/// The answer to `@RSYNCD: AUTHREQD <challenge>` at protocol 29 (no digest list was offered,
/// so the daemon uses MD4 with a zero seed): base64 without padding of
/// MD4(00 00 00 00 ‖ password ‖ challenge).
pub fn auth_response(password: &str, challenge: &str) -> String {
    use base64::Engine;
    let digest = md4(&[&[0u8; 4], password.as_bytes(), challenge.as_bytes()]);
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
}

/// One multiplexed frame: a little-endian (tag << 24 | len) header, then the payload.
pub fn frame(code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    let header = ((u32::from(MPLEX_BASE + code)) << 24) | payload.len() as u32;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// MSG_DATA frames for a byte stream, split at 0xFFFF bytes.
pub fn data_frames(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 4 * (bytes.len() / 0xffff + 1));
    for chunk in bytes.chunks(0xffff) {
        out.extend_from_slice(&frame(MSG_DATA, chunk));
    }
    out
}

/// rsync's file-list order (f_name_cmp at protocol ≥ 29) as a sort key: "." first; within a
/// directory, non-directories by bytes, then directories by name + "/", each followed by its
/// subtree.
pub fn sort_key(path: &str, is_dir: bool) -> Vec<(u8, Vec<u8>)> {
    if path == "." {
        return vec![];
    }
    let comps: Vec<&[u8]> = path.as_bytes().split(|&b| b == b'/').collect();
    let mut key = Vec::with_capacity(comps.len());
    for c in &comps[..comps.len() - 1] {
        key.push((1, [*c, b"/"].concat()));
    }
    let last = comps[comps.len() - 1];
    key.push(if is_dir {
        (1, [last, b"/"].concat())
    } else {
        (0, last.to_vec())
    });
    key
}

pub fn sort(entries: &mut [Entry]) {
    entries.sort_by_cached_key(|e| sort_key(&e.path, e.is_dir()));
}

/// The options a sender cares about, parsed from the argument list.
#[derive(Debug, Default, Clone)]
pub struct Request {
    pub sender: bool,
    pub recursive: bool,
    pub dirs: bool,
    pub links: bool,
    pub owner: bool,
    pub group: bool,
    pub dry_run: bool,
    pub checksum: bool,
    pub numeric_ids: bool,
    pub list_only: bool,
    /// -D: devices and specials are listed with their rdev.
    pub devices: bool,
    /// -H: an uploading client's list would carry device and inode numbers.
    pub hard_links: bool,
    pub checksum_seed: Option<i32>,
    /// Paths after ".", with the module prefix stripped ("" is the module root).
    pub paths: Vec<String>,
    /// Why the request cannot be served, in rsync's own words.
    pub refusal: Option<String>,
}

/// Parse the daemon argument list (`--server --sender -logDtpr . mod/path`).
pub fn parse_args(args: &[String], module: &str) -> Request {
    let mut r = Request::default();
    let mut paths = false;
    for a in args {
        if paths {
            let p = if a == module {
                ""
            } else if let Some(rest) = a.strip_prefix(&format!("{module}/")) {
                rest
            } else {
                r.refusal
                    .get_or_insert(format!("path {a:?} is outside module {module}"));
                continue;
            };
            r.paths.push(p.to_string());
            continue;
        }
        match a.as_str() {
            "." => paths = true,
            "--server" => {}
            "--sender" => r.sender = true,
            "--numeric-ids" => r.numeric_ids = true,
            "--list-only" => r.list_only = true,
            "--devices" | "--specials" => r.devices = true,
            // With --delete the uploading client sends a filter list before its file list, and
            // the receiver is expected to delete what the list does not name; neither applies
            // to a daemon that stores nothing.
            s if s.starts_with("--delete") || s == "--del" => {
                r.refusal
                    .get_or_insert(format!("{s} is not supported by this daemon"));
            }
            s if s.starts_with("--checksum-seed=") => {
                r.checksum_seed = s["--checksum-seed=".len()..].parse().ok();
            }
            s if s.starts_with("--files-from") || s == "--from0" || s == "--secluded-args" => {
                r.refusal
                    .get_or_insert(format!("{s} is not supported by this daemon"));
            }
            s if s.starts_with("--") => {}
            s if s.starts_with('-') => {
                for c in s[1..].chars() {
                    match c {
                        'e' => break, // the capability string runs to the end of the cluster
                        'r' => r.recursive = true,
                        'd' => r.dirs = true,
                        'l' => r.links = true,
                        'o' => r.owner = true,
                        'g' => r.group = true,
                        'n' => r.dry_run = true,
                        'c' => r.checksum = true,
                        'D' => r.devices = true,
                        'H' => r.hard_links = true,
                        'z' | 'U' | 'N' | 'R' | 's' => {
                            r.refusal
                                .get_or_insert(format!("-{c} is not supported by this daemon"));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if !r.sender && r.paths.len() > 1 {
        r.refusal
            .get_or_insert("an upload names one destination".into());
    }
    if !r.sender && r.hard_links {
        r.refusal
            .get_or_insert("-H is not supported for uploads by this daemon".into());
    }
    r
}

/// Encodes entries in order, keeping the "previous entry" state both ends share.
#[derive(Default)]
pub struct FlistWriter {
    last_name: Vec<u8>,
    mode: Option<u32>,
    mtime: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl FlistWriter {
    /// One entry, with the transfer root's flag `top` for "." and named top-level dirs.
    pub fn entry(&mut self, e: &Entry, top: bool, r: &Request, out: &mut Vec<u8>) {
        let name = e.path.as_bytes();
        let first = self.mode.is_none();
        let mut x: u16 = 0;
        if e.is_dir() && top {
            x |= XMIT_TOP_DIR;
        }
        if self.mode == Some(e.mode) {
            x |= XMIT_SAME_MODE;
        }
        if !r.owner || (!first && self.uid == Some(e.uid)) {
            x |= XMIT_SAME_UID;
        }
        if !r.group || (!first && self.gid == Some(e.gid)) {
            x |= XMIT_SAME_GID;
        }
        if self.mtime == Some(e.mtime) {
            x |= XMIT_SAME_TIME;
        }
        let l1 = self
            .last_name
            .iter()
            .zip(name)
            .take(255)
            .take_while(|(a, b)| a == b)
            .count();
        let l2 = name.len() - l1;
        if l1 > 0 {
            x |= XMIT_SAME_NAME;
        }
        if l2 > 255 {
            x |= XMIT_LONG_NAME;
        }
        if x == 0 && !e.is_dir() {
            x |= XMIT_TOP_DIR; // filler: a zero flags byte would end the list
        }
        if x & 0xff00 != 0 || x == 0 {
            x |= XMIT_EXTENDED_FLAGS;
            out.extend_from_slice(&x.to_le_bytes());
        } else {
            out.push(x as u8);
        }
        if x & XMIT_SAME_NAME != 0 {
            out.push(l1 as u8);
        }
        if x & XMIT_LONG_NAME != 0 {
            out.extend_from_slice(&le32(l2 as i32));
        } else {
            out.push(l2 as u8);
        }
        out.extend_from_slice(&name[l1..]);
        out.extend_from_slice(&longint(e.size));
        if x & XMIT_SAME_TIME == 0 {
            out.extend_from_slice(&e.mtime.to_le_bytes());
        }
        if x & XMIT_SAME_MODE == 0 {
            out.extend_from_slice(&e.mode.to_le_bytes());
        }
        if r.owner && x & XMIT_SAME_UID == 0 {
            out.extend_from_slice(&e.uid.to_le_bytes());
        }
        if r.group && x & XMIT_SAME_GID == 0 {
            out.extend_from_slice(&e.gid.to_le_bytes());
        }
        if r.links && e.kind == Kind::Symlink {
            out.extend_from_slice(&le32(e.data.len() as i32));
            out.extend_from_slice(&e.data);
        }
        if r.checksum && e.kind == Kind::File {
            out.extend_from_slice(&list_sum(&e.data));
        }
        self.last_name = name.to_vec();
        self.mode = Some(e.mode);
        self.mtime = Some(e.mtime);
        self.uid = Some(e.uid);
        self.gid = Some(e.gid);
    }

    /// End of list, empty id lists for what was asked, and io_error.
    pub fn finish(r: &Request, io_error: i32, out: &mut Vec<u8>) {
        out.push(0);
        if r.owner && !r.numeric_ids {
            out.extend_from_slice(&le32(0));
        }
        if r.group && !r.numeric_ids {
            out.extend_from_slice(&le32(0));
        }
        out.extend_from_slice(&le32(io_error));
    }
}

/// A demultiplexing reader: MSG_DATA becomes a byte stream, other messages are collected.
pub struct MuxReader<R> {
    inner: R,
    left: usize,
    /// False for a stream that is not multiplexed (client to daemon at protocol 29).
    mux: bool,
    /// Bytes read from `inner`, frame headers included.
    pub consumed: u64,
    pub messages: Vec<(u8, String)>,
    pub io_error: i32,
}

impl<R: AsyncRead + Unpin> MuxReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            left: 0,
            mux: true,
            consumed: 0,
            messages: vec![],
            io_error: 0,
        }
    }
    /// The same decoders over a stream that carries no multiplexing frames: what a daemon
    /// reads from an uploading client at protocol 29.
    pub fn raw(inner: R) -> Self {
        Self {
            mux: false,
            ..Self::new(inner)
        }
    }
    pub async fn read(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        if !self.mux {
            self.inner
                .read_exact(&mut out)
                .await
                .context("the peer closed the connection")?;
            self.consumed += n as u64;
            return Ok(out);
        }
        let mut have = 0;
        while have < n {
            while self.left == 0 {
                let mut h = [0u8; 4];
                self.inner
                    .read_exact(&mut h)
                    .await
                    .context("the daemon closed the connection")?;
                self.consumed += 4;
                let h = u32::from_le_bytes(h);
                let tag = ((h >> 24) as u8).wrapping_sub(MPLEX_BASE);
                let len = (h & 0x00ff_ffff) as usize;
                if tag == MSG_DATA {
                    self.left = len;
                    continue;
                }
                ensure!(len <= 8192, "a {len}-byte rsync message is too long");
                let mut body = vec![0u8; len];
                self.inner.read_exact(&mut body).await?;
                self.consumed += len as u64;
                match tag {
                    MSG_ERROR_XFER | MSG_INFO | MSG_ERROR | MSG_WARNING => self
                        .messages
                        .push((tag, String::from_utf8_lossy(&body).trim_end().to_string())),
                    MSG_IO_ERROR if len == 4 => {
                        self.io_error |= i32::from_le_bytes([body[0], body[1], body[2], body[3]])
                    }
                    MSG_NOOP => {}
                    MSG_ERROR_EXIT => bail!("the daemon exited with an error"),
                    other => bail!("unexpected rsync message tag {other}"),
                }
            }
            let k = (n - have).min(self.left);
            self.inner.read_exact(&mut out[have..have + k]).await?;
            self.consumed += k as u64;
            have += k;
            self.left -= k;
        }
        Ok(out)
    }
    pub async fn byte(&mut self) -> Result<u8> {
        Ok(self.read(1).await?[0])
    }
    pub async fn int(&mut self) -> Result<i32> {
        let b = self.read(4).await?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub async fn short(&mut self) -> Result<u16> {
        let b = self.read(2).await?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub async fn longint(&mut self) -> Result<u64> {
        let v = self.int().await?;
        if v != -1 {
            return Ok(v as u32 as u64);
        }
        let b = self.read(8).await?;
        Ok(i64::from_le_bytes(b.try_into().unwrap_or([0; 8])) as u64)
    }

    /// Read a file list sent for request `r` (entries in the order sent, plus io_error).
    pub async fn file_list(&mut self, r: &Request) -> Result<(Vec<Entry>, i32)> {
        let mut entries = Vec::new();
        let (mut last, mut mode, mut mtime, mut uid, mut gid) =
            (Vec::new(), 0u32, 0u32, 0u32, 0u32);
        loop {
            let mut x = u16::from(self.byte().await?);
            if x == 0 {
                break;
            }
            if x & XMIT_EXTENDED_FLAGS != 0 {
                x |= u16::from(self.byte().await?) << 8;
            }
            let l1 = if x & XMIT_SAME_NAME != 0 {
                self.byte().await? as usize
            } else {
                0
            };
            let l2 = if x & XMIT_LONG_NAME != 0 {
                self.int().await?.max(0) as usize
            } else {
                self.byte().await? as usize
            };
            ensure!(
                l1 <= last.len() && l1 + l2 <= MAX_NAME,
                "a file-list name is malformed"
            );
            let mut name = last[..l1].to_vec();
            name.extend(self.read(l2).await?);
            last = name.clone();
            let size = self.longint().await?;
            if x & XMIT_SAME_TIME == 0 {
                mtime = self.int().await? as u32;
            }
            if x & XMIT_SAME_MODE == 0 {
                mode = self.int().await? as u32;
            }
            if r.owner && x & XMIT_SAME_UID == 0 {
                uid = self.int().await? as u32;
            }
            if r.group && x & XMIT_SAME_GID == 0 {
                gid = self.int().await? as u32;
            }
            let kind = Kind::of_mode(mode);
            let mut data = Vec::new();
            if r.links && kind == Some(Kind::Symlink) {
                let n = self.int().await?;
                ensure!(
                    (0..=MAX_NAME as i32).contains(&n),
                    "a symlink target is too long"
                );
                data = self.read(n as usize).await?;
            }
            ensure!(
                kind.is_some() || !r.devices,
                "a device or special file in the list; -D is not supported for uploads"
            );
            if r.checksum && kind == Some(Kind::File) {
                self.read(16).await?;
            }
            let path = String::from_utf8_lossy(&name).to_string();
            ensure!(
                !path.starts_with('/') && !path.split('/').any(|c| c == ".."),
                "unsafe file-list name {path:?}"
            );
            ensure!(
                entries.len() < MAX_ENTRIES,
                "more than {MAX_ENTRIES} file-list entries"
            );
            // Devices, FIFOs and sockets are listed by mode only without -D; skip them.
            if let Some(kind) = kind {
                entries.push(Entry {
                    path,
                    kind,
                    data,
                    mode,
                    mtime,
                    uid,
                    gid,
                    size,
                });
            }
        }
        for wanted in [r.owner, r.group] {
            if wanted && !r.numeric_ids {
                loop {
                    let id = self.int().await?;
                    if id == 0 {
                        break;
                    }
                    let n = self.byte().await?;
                    self.read(n as usize).await?;
                }
            }
        }
        let io_error = self.int().await?;
        Ok((entries, io_error))
    }
}

/// An entry as the model sees it.
pub fn entry_json(e: &Entry) -> Value {
    let mut v = json!({
        "path": e.path,
        "type": e.kind.name(),
        "size": e.size,
        "mode": format!("{:o}", e.mode & 0o7777),
        "mtime": e.mtime,
    });
    if e.kind == Kind::Symlink && !e.data.is_empty() {
        v["target"] = json!(String::from_utf8_lossy(&e.data));
    }
    v
}

/// Text when it is printable UTF-8, hex otherwise, with the encoding named.
pub fn content_json(data: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(data) {
        Ok(s)
            if s.chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
        {
            (s.to_string(), "utf8")
        }
        _ => (hex::encode(data), "hex"),
    }
}

/// One entry the model described: `{path, type, content, encoding, mode, mtime, target, uid, gid}`.
pub fn entry_from_json(v: &Value, default_mtime: u32) -> Result<Entry> {
    let path = v["path"]
        .as_str()
        .context("each entry needs a path")?
        .trim_matches('/')
        .to_string();
    ensure!(
        !path.is_empty() && path.len() <= MAX_NAME,
        "an entry path is empty or too long"
    );
    ensure!(
        !path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == ".."),
        "entry path {path:?} must be relative, without . or .. components"
    );
    let kind = match v["type"].as_str().unwrap_or("file") {
        "file" => Kind::File,
        "dir" | "directory" => Kind::Dir,
        "symlink" | "link" => Kind::Symlink,
        other => bail!("entry type {other:?} is not file, dir or symlink"),
    };
    let data = match kind {
        Kind::File => {
            let content = v["content"].as_str().unwrap_or_default();
            match v["encoding"].as_str().unwrap_or("utf8") {
                "utf8" => content.as_bytes().to_vec(),
                "hex" => hex::decode(content).context("content is not hex")?,
                other => bail!("encoding {other:?} is not utf8 or hex"),
            }
        }
        Kind::Symlink => v["target"]
            .as_str()
            .context("a symlink needs a target")?
            .as_bytes()
            .to_vec(),
        Kind::Dir => vec![],
    };
    let type_bits = match kind {
        Kind::File => S_IFREG,
        Kind::Dir => S_IFDIR,
        Kind::Symlink => S_IFLNK,
    };
    let perms = match v.get("mode") {
        None | Some(Value::Null) => match kind {
            Kind::File => 0o644,
            Kind::Dir => 0o755,
            Kind::Symlink => 0o777,
        },
        Some(Value::String(s)) => u32::from_str_radix(s.trim_start_matches("0o"), 8)
            .with_context(|| format!("mode {s:?} is not octal"))?,
        Some(n) => n
            .as_u64()
            .context("mode is an octal string such as \"644\"")? as u32,
    };
    ensure!(
        perms <= 0o7777,
        "mode {perms:o} has bits beyond permissions"
    );
    let mtime = v["mtime"]
        .as_u64()
        .map(|t| t as u32)
        .unwrap_or(default_mtime);
    let size = match kind {
        Kind::Dir => 4096,
        _ => data.len() as u64,
    };
    Ok(Entry {
        path,
        kind,
        data,
        mode: type_bits | perms,
        mtime,
        uid: v["uid"].as_u64().unwrap_or(0) as u32,
        gid: v["gid"].as_u64().unwrap_or(0) as u32,
        size,
    })
}
