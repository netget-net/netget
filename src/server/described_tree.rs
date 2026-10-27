//! A file tree the model describes rather than stores: directories, files and symlinks with
//! their modes, owners and times, and file content described the way `described_disk` describes
//! a disk (text, hex, extents, fill bytes and failing regions). Rust answers every lookup,
//! getattr, readdir, read and readlink from the description at no model cost.
//!
//! Directories are described lazily: a directory starts `Pending`, and the first lookup or
//! listing inside it asks the model once; the answer is kept for the life of the tree. An answer
//! may describe subdirectories inline (their own `entries`), so one answer at the root can
//! describe a whole tree, and a subdirectory without `entries` is asked about when first
//! visited. A description that fails is asked again at most [`MAX_DESCRIBE_ATTEMPTS`] times.
//!
//! A non-directory may have several names (hard links): one inode, its content, attributes and
//! extended attributes shared by every name, `nlink` counting them, and the inode kept until its
//! last name is gone and nothing holds it open. A description declares one with `kind:
//! "hardlink"` and `target`, the absolute path of a file described in the same answer or before
//! it. Any node may carry extended attributes (`xattrs`), described or set, in the `user.`,
//! `trusted.` and `security.` namespaces, every one of them bounded.
//!
//! Changes the model accepts — creates, writes, truncates, fallocate, renames (exchanges
//! included), links, removals, attribute and extended-attribute changes, symlinks — go into an
//! in-memory overlay: written pages over the described content, bounded
//! in bytes and discarded with the tree. Nothing touches a disk. Every mutation is a pure
//! function of the tree here; asking the model whether it may happen is the caller's business,
//! and a refused mutation never reaches this module, so it leaves the tree unchanged.
//!
//! Shared vocabulary with the other file servers: `kind` file/dir/symlink, `mode` as a decimal
//! number (420 is 0644), `mtime` in Unix seconds, `entries` for a listing (9P's), and content
//! fields from `src/server/described_disk.rs` (NBD, iSCSI, NVMe/TCP).
use super::described_disk::{self, Content, ErrorRegion, Extent};
use crate::utils::clock::{SystemTime, UNIX_EPOCH};
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value as Json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

/// The root directory's inode number.
pub const ROOT: u64 = 1;
/// The overlay's unit: a written byte costs the whole page it falls in.
pub const PAGE: u64 = 4096;
/// Live nodes (files, directories, symlinks) in one tree.
pub const MAX_NODES: usize = 65_536;
/// Entries in one directory.
pub const MAX_DIR_ENTRIES: usize = 4096;
/// Bytes in one name.
pub const MAX_NAME_BYTES: usize = 255;
/// Directories below the root. The description walk is iterative and counts this; a deeper
/// directory is refused whether it came from the model or from `mkdir`.
pub const MAX_TREE_DEPTH: usize = 64;
/// A file's size, described or written.
pub const MAX_FILE_SIZE: u64 = 1 << 30;
/// Explicit content bytes (text and hex) the model may describe over the whole tree.
pub const MAX_DESCRIBED_BYTES: usize = described_disk::MAX_CONTENT;
/// Bytes in a symlink's target (PATH_MAX less its NUL).
pub const MAX_SYMLINK_TARGET: usize = 4095;
/// Entries one answer may describe, nested ones included.
pub const MAX_ENTRIES_PER_ANSWER: usize = 16_384;
/// Times a directory's description is asked for before the directory reads as an I/O error.
pub const MAX_DESCRIBE_ATTEMPTS: u8 = 3;
/// The overlay's default bound, and the most it may be configured to.
pub const DEFAULT_MAX_OVERLAY_BYTES: u64 = 64 << 20;
pub const MAX_OVERLAY_LIMIT: u64 = 1 << 30;
/// Names one non-directory may have; one more is EMLINK.
pub const MAX_LINKS: usize = 1024;
/// Names beyond each node's first, over the whole tree; one more is ENOSPC. With [`MAX_NODES`]
/// this bounds every directory entry the tree can hold.
pub const MAX_HARD_LINKS: usize = MAX_NODES;
/// Bytes in an extended attribute's name, namespace included (Linux's XATTR_NAME_MAX).
pub const MAX_XATTR_NAME_BYTES: usize = 255;
/// Bytes in an extended attribute's value (Linux's XATTR_SIZE_MAX).
pub const MAX_XATTR_VALUE_BYTES: usize = 64 * 1024;
/// Extended attributes on one node; one more is ENOSPC.
pub const MAX_XATTRS_PER_NODE: usize = 128;
/// Bytes of extended attributes (names and values, described and set) over the whole tree; past
/// it a set is ENOSPC and a description is refused.
pub const MAX_XATTR_BYTES: usize = 16 << 20;
/// The extended-attribute namespaces the tree holds. `user.` is any process's (the kernel lets
/// it on files and directories only, checking the file's mode); `trusted.` and `security.` the
/// kernel lets only a privileged process set. Any other name is EOPNOTSUPP.
pub const XATTR_NAMESPACES: [&str; 3] = ["user.", "trusted.", "security."];

/// The errno names a model may use to refuse something, as the platform's numbers.
pub fn errno_named(name: &str) -> Option<i32> {
    Some(match name.to_ascii_uppercase().as_str() {
        "EACCES" => libc::EACCES,
        "EPERM" => libc::EPERM,
        "EROFS" => libc::EROFS,
        "ENOSPC" => libc::ENOSPC,
        "EDQUOT" => libc::EDQUOT,
        "EEXIST" => libc::EEXIST,
        "ENOENT" => libc::ENOENT,
        "ENOTEMPTY" => libc::ENOTEMPTY,
        "EIO" => libc::EIO,
        "EBUSY" => libc::EBUSY,
        "EINVAL" => libc::EINVAL,
        "EFBIG" => libc::EFBIG,
        "ENAMETOOLONG" => libc::ENAMETOOLONG,
        "EAGAIN" => libc::EAGAIN,
        "ETXTBSY" => libc::ETXTBSY,
        "EISDIR" => libc::EISDIR,
        "ENOTDIR" => libc::ENOTDIR,
        "EXDEV" => libc::EXDEV,
        "EMLINK" => libc::EMLINK,
        "ENODATA" => libc::ENODATA,
        "EOPNOTSUPP" | "ENOTSUP" => libc::EOPNOTSUPP,
        _ => return None,
    })
}

/// The names [`errno_named`] accepts, for refusal messages and action descriptions.
pub const ERRNO_NAMES: &str = "EACCES, EPERM, EROFS, ENOSPC, EDQUOT, EEXIST, ENOENT, ENOTEMPTY, \
                               EIO, EBUSY, EINVAL, EFBIG, ENAMETOOLONG, EAGAIN, ETXTBSY, EISDIR, \
                               ENOTDIR, EXDEV, EMLINK, ENODATA or EOPNOTSUPP";

/// The name of an errno this module produces, for logs and events.
pub fn errno_name(code: i32) -> String {
    for name in ERRNO_NAMES.split([',', ' ']).filter(|n| n.starts_with('E')) {
        if errno_named(name) == Some(code) {
            return name.to_string();
        }
    }
    format!("errno {code}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    /// Made by mknod/mkfifo/bind; the kernel serves their I/O, the tree only names them.
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
            Kind::CharDevice => "char",
            Kind::BlockDevice => "block",
        }
    }
}

/// What a getattr answers.
#[derive(Clone, Debug, PartialEq)]
pub struct Attr {
    pub ino: u64,
    pub kind: Kind,
    pub size: u64,
    pub blocks: u64,
    pub perm: u16,
    pub nlink: u32,
    /// The device number of a character or block device node.
    pub rdev: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

/// Why a tree operation did not happen: an errno for the caller, or a directory whose
/// description it needs first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Errno(i32),
    Describe(u64),
}

pub type Outcome<T> = std::result::Result<T, Stop>;

fn errno<T>(code: i32) -> Outcome<T> {
    Err(Stop::Errno(code))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirState {
    /// Not described yet; the count is how many descriptions failed.
    Pending(u8),
    Described,
    /// [`MAX_DESCRIBE_ATTEMPTS`] descriptions failed: the directory reads as EIO.
    Failed,
    /// The model refused to describe it: the directory reads as that errno.
    Refused(i32),
}

#[derive(Debug)]
struct FileBody {
    size: u64,
    base: Vec<Extent>,
    errors: Vec<ErrorRegion>,
    /// Described bytes are visible only below this: a truncate below it hides the rest.
    base_limit: u64,
    /// Written pages, by page index.
    pages: BTreeMap<u64, Box<[u8]>>,
}

#[derive(Debug)]
struct DirBody {
    entries: BTreeMap<String, u64>,
    state: DirState,
}

#[derive(Debug)]
enum Body {
    File(FileBody),
    Dir(DirBody),
    Symlink(String),
    /// A FIFO, socket or device node and its device number.
    Special(Kind, u32),
}

#[derive(Debug)]
struct Node {
    /// The first name's directory; 0 for a node unlinked while still open.
    parent: u64,
    name: String,
    /// A non-directory's further names (hard links), each a directory and a name in it.
    links: Vec<(u64, String)>,
    /// Extended attributes, by full name (namespace included).
    xattrs: BTreeMap<String, Vec<u8>>,
    perm: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    open: u32,
    body: Body,
}

fn xattr_cost(name: &str, value: &[u8]) -> usize {
    name.len() + value.len()
}

impl Node {
    fn xattr_bytes(&self) -> usize {
        self.xattrs.iter().map(|(n, v)| xattr_cost(n, v)).sum()
    }

    /// How many names it has (0 once unlinked while open).
    fn names(&self) -> usize {
        if self.parent == 0 {
            0
        } else {
            1 + self.links.len()
        }
    }

    fn kind(&self) -> Kind {
        match self.body {
            Body::File(_) => Kind::File,
            Body::Dir(_) => Kind::Dir,
            Body::Symlink(_) => Kind::Symlink,
            Body::Special(k, _) => k,
        }
    }
}

/// What a setxattr may do about an attribute that does or does not exist yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrMode {
    /// Create it or replace it.
    Either,
    /// XATTR_CREATE: EEXIST if it exists.
    Create,
    /// XATTR_REPLACE: ENODATA if it does not.
    Replace,
}

impl XattrMode {
    pub fn name(self) -> &'static str {
        match self {
            XattrMode::Either => "create_or_replace",
            XattrMode::Create => "create",
            XattrMode::Replace => "replace",
        }
    }
}

/// Linux's FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE and FALLOC_FL_ZERO_RANGE, spelled out so
/// the tree reads a mode on every platform it compiles on.
pub const FALLOC_KEEP_SIZE: i32 = 0x01;
pub const FALLOC_PUNCH_HOLE: i32 = 0x02;
pub const FALLOC_ZERO_RANGE: i32 = 0x10;

/// What a fallocate asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocation {
    /// Mode 0 (and KEEP_SIZE): reserve the range in the overlay, so writes to it cannot fail for
    /// space; without `keep_size` the file grows to cover it.
    Allocate { keep_size: bool },
    /// PUNCH_HOLE|KEEP_SIZE: the range reads as zeroes; the size does not change.
    PunchHole,
    /// ZERO_RANGE: the range reads as zeroes and is reserved; without `keep_size` the file grows
    /// to cover it.
    ZeroRange { keep_size: bool },
}

impl Allocation {
    /// The modes the tree implements; `None` for every other (COLLAPSE_RANGE, INSERT_RANGE,
    /// UNSHARE_RANGE, a punch without KEEP_SIZE, ...), which the caller answers EOPNOTSUPP.
    pub fn from_mode(mode: i32) -> Option<Allocation> {
        let keep_size = mode & FALLOC_KEEP_SIZE != 0;
        match mode & !FALLOC_KEEP_SIZE {
            0 => Some(Allocation::Allocate { keep_size }),
            FALLOC_PUNCH_HOLE if keep_size => Some(Allocation::PunchHole),
            FALLOC_ZERO_RANGE => Some(Allocation::ZeroRange { keep_size }),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Allocation::Allocate { .. } => "allocate",
            Allocation::PunchHole => "punch_hole",
            Allocation::ZeroRange { .. } => "zero_range",
        }
    }

    pub fn keep_size(self) -> bool {
        match self {
            Allocation::Allocate { keep_size } | Allocation::ZeroRange { keep_size } => keep_size,
            Allocation::PunchHole => true,
        }
    }
}

/// What fallocate does to one page of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageOp {
    Nothing,
    /// Give it an overlay page holding what it shows now.
    Materialize,
    /// Zero these bytes of the page (offsets within it), giving it an overlay page first if it
    /// has none.
    Zero(usize, usize),
    /// Discard its overlay page: there is nothing beneath it, so it reads as zeroes.
    Drop,
}

/// Attribute changes a setattr asks for.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Changes {
    pub perm: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<SystemTime>,
    pub mtime: Option<SystemTime>,
}

/// The tree, its overlay and its bounds.
#[derive(Debug)]
pub struct Tree {
    nodes: HashMap<u64, Node>,
    next_ino: u64,
    uid: u32,
    gid: u32,
    born: SystemTime,
    described_bytes: usize,
    overlay_bytes: u64,
    max_overlay: u64,
    /// Names beyond each node's first.
    hard_links: usize,
    /// Extended-attribute names and values over the whole tree.
    xattr_bytes: usize,
}

/// One entry of an answer, checked, before anything is committed.
struct Staged {
    /// The answer's own directory, or an earlier staged entry.
    parent: Option<usize>,
    name: String,
    /// Its path from the mount's root, for hard links that name it.
    path: String,
    xattrs: BTreeMap<String, Vec<u8>>,
    perm: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    body: StagedBody,
}

enum StagedBody {
    File {
        size: u64,
        base: Vec<Extent>,
        errors: Vec<ErrorRegion>,
    },
    Dir {
        described: bool,
    },
    Symlink(String),
    /// Another name for a file: the path it names, resolved once every entry is staged.
    HardLink(String),
}

/// What a staged hard link names.
#[derive(Clone, Copy)]
enum LinkTarget {
    Staged(usize),
    Existing(u64),
}

/// A name as a directory entry may have it.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

fn time_of(v: &Json, key: &str) -> Result<Option<SystemTime>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(t) => {
            let secs = t
                .as_u64()
                .with_context(|| format!("{key} is Unix seconds, a non-negative integer"))?;
            ensure!(secs < 1 << 40, "{key} is out of range");
            Ok(Some(UNIX_EPOCH + Duration::from_secs(secs)))
        }
    }
}

/// Whether an extended attribute's name is one the tree holds: in one of [`XATTR_NAMESPACES`]
/// with something after the prefix (EOPNOTSUPP otherwise), at most [`MAX_XATTR_NAME_BYTES`]
/// (ERANGE, Linux's own answer to a name too long), without NUL.
pub fn check_xattr_name(name: &str) -> Outcome<()> {
    if name.is_empty() || name.contains('\0') {
        return errno(libc::EINVAL);
    }
    if name.len() > MAX_XATTR_NAME_BYTES {
        return errno(libc::ERANGE);
    }
    if !XATTR_NAMESPACES
        .iter()
        .any(|ns| name.starts_with(ns) && name.len() > ns.len())
    {
        return errno(libc::EOPNOTSUPP);
    }
    Ok(())
}

/// A description's `xattrs`: `[{name, text | hex}]`, every name and value bounded. A value with
/// neither key is empty.
fn parse_xattrs(v: &Json) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let list = match v.get("xattrs") {
        None | Some(Json::Null) => return Ok(out),
        Some(Json::Array(a)) => a,
        Some(_) => bail!("xattrs is an array of {{name, text | hex}}"),
    };
    ensure!(
        list.len() <= MAX_XATTRS_PER_NODE,
        "a node has at most {MAX_XATTRS_PER_NODE} xattrs"
    );
    for x in list {
        let name = x
            .get("name")
            .and_then(Json::as_str)
            .context("each xattr has a name")?;
        ensure!(
            check_xattr_name(name).is_ok(),
            "an xattr name is 1 to {MAX_XATTR_NAME_BYTES} bytes in the user., trusted. or \
             security. namespace: {:?}",
            name.chars().take(64).collect::<String>()
        );
        let value = match (x.get("text"), x.get("hex")) {
            (Some(Json::String(t)), None) => t.as_bytes().to_vec(),
            (None, Some(Json::String(h))) => {
                ensure!(
                    h.len() <= 2 * MAX_XATTR_VALUE_BYTES,
                    "an xattr value is at most {MAX_XATTR_VALUE_BYTES} bytes"
                );
                hex::decode(h).context("an xattr's hex is not hex")?
            }
            (None, None) => vec![],
            (Some(_), Some(_)) => bail!("an xattr has text or hex, not both"),
            _ => bail!("an xattr's text and hex are strings"),
        };
        ensure!(
            value.len() <= MAX_XATTR_VALUE_BYTES,
            "an xattr value is at most {MAX_XATTR_VALUE_BYTES} bytes"
        );
        ensure!(
            out.insert(name.to_string(), value).is_none(),
            "xattr {name:?} appears twice on one node"
        );
    }
    Ok(out)
}

fn xattrs_cost(x: &BTreeMap<String, Vec<u8>>) -> usize {
    x.iter().map(|(n, v)| xattr_cost(n, v)).sum()
}

/// A hard link's target: an absolute path from the mount's root, its components valid names.
fn link_target_path(target: &str) -> Result<Vec<&str>> {
    ensure!(
        target.starts_with('/') && target.len() <= MAX_SYMLINK_TARGET,
        "a hard link's target is an absolute path from the mount's root, at most \
         {MAX_SYMLINK_TARGET} bytes"
    );
    let parts: Vec<&str> = target[1..].split('/').collect();
    ensure!(
        parts.len() <= MAX_TREE_DEPTH + 1 && parts.iter().all(|c| valid_name(c)),
        "a hard link's target is a path of names (no '.', '..' or empty components): {:?}",
        target.chars().take(128).collect::<String>()
    );
    Ok(parts)
}

fn id_of(v: &Json, key: &str, default: u32) -> Result<u32> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(default),
        Some(n) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .with_context(|| format!("{key} is a numeric id")),
    }
}

/// A file entry's content: its size, extents, failing regions and explicit bytes.
fn file_content(e: &Json) -> Result<(u64, Vec<Extent>, Vec<ErrorRegion>, usize)> {
    let size = match e.get("size") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .context("size is a non-negative number of bytes")?,
        ),
    };
    let inline = match (e.get("text"), e.get("hex")) {
        (Some(Json::String(t)), None) => Some(t.as_bytes().to_vec()),
        (None, Some(Json::String(h))) => Some(hex::decode(h).context("hex is not hex")?),
        (None, None) => None,
        (Some(_), Some(_)) => bail!("a file has text or hex, not both"),
        _ => bail!("text and hex are strings"),
    };
    let has_extents = e.get("extents").is_some_and(|v| !v.is_null());
    ensure!(
        !(inline.is_some() && has_extents),
        "a file has text, hex or extents, not more than one"
    );
    ensure!(
        !has_extents || size.is_some(),
        "a file described by extents gives its size"
    );
    let inline_len = inline.as_ref().map_or(0, Vec::len);
    ensure!(
        inline_len <= described_disk::MAX_CONTENT,
        "a file's text or hex is at most {} bytes",
        described_disk::MAX_CONTENT
    );
    let size = size.unwrap_or(inline_len as u64);
    ensure!(
        size <= MAX_FILE_SIZE,
        "a file is at most {MAX_FILE_SIZE} bytes"
    );
    ensure!(
        inline_len as u64 <= size,
        "size {size} is smaller than the file's text or hex"
    );
    let base = match inline {
        Some(bytes) if !bytes.is_empty() => vec![Extent {
            offset: 0,
            length: bytes.len() as u64,
            content: Content::Bytes(bytes),
        }],
        Some(_) => vec![],
        None => described_disk::parse_extents(e, size)?,
    };
    let errors = described_disk::parse_errors(
        e,
        size,
        |name| errno_named(name).map(|c| c as u32),
        "EIO",
        ERRNO_NAMES,
    )?;
    let explicit = base
        .iter()
        .map(|x| match &x.content {
            Content::Bytes(b) => b.len(),
            Content::Fill(_) => 0,
        })
        .sum();
    Ok((size, base, errors, explicit))
}

/// Move a served timestamp forward: to `now`, or a microsecond past where it is when the clock
/// reads earlier (a description's mtime in the future, a clock stepped back). mtime and ctime
/// never go backwards, and every approved change moves them. An NFS client (FUSE-T on macOS)
/// invalidates its caches on what it sees change; a time that regresses across a change is the
/// attribute churn that provokes a known panic in Apple's NFS client (FB23527406).
fn advance(t: &mut SystemTime, now: SystemTime) {
    *t = if now > *t {
        now
    } else {
        *t + Duration::from_micros(1)
    };
}

impl Tree {
    /// An empty tree whose root is a directory waiting for its description, owned by
    /// `uid`/`gid` (and every described entry that names no owner).
    pub fn new(root_perm: u16, uid: u32, gid: u32, max_overlay: u64) -> Self {
        let born = SystemTime::now();
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT,
            Node {
                parent: ROOT,
                name: String::new(),
                links: Vec::new(),
                xattrs: BTreeMap::new(),
                perm: root_perm & 0o7777,
                uid,
                gid,
                atime: born,
                mtime: born,
                ctime: born,
                open: 0,
                body: Body::Dir(DirBody {
                    entries: BTreeMap::new(),
                    state: DirState::Pending(0),
                }),
            },
        );
        Tree {
            nodes,
            next_ino: ROOT + 1,
            uid,
            gid,
            born,
            described_bytes: 0,
            overlay_bytes: 0,
            max_overlay: max_overlay.min(MAX_OVERLAY_LIMIT),
            hard_links: 0,
            xattr_bytes: 0,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Names beyond each node's first, over the whole tree.
    pub fn hard_links(&self) -> usize {
        self.hard_links
    }

    /// Extended-attribute names and values over the whole tree, in bytes.
    pub fn xattr_bytes(&self) -> usize {
        self.xattr_bytes
    }

    pub fn overlay_bytes(&self) -> u64 {
        self.overlay_bytes
    }

    pub fn max_overlay(&self) -> u64 {
        self.max_overlay
    }

    pub fn described_bytes(&self) -> usize {
        self.described_bytes
    }

    pub fn attr(&self, ino: u64) -> Option<Attr> {
        let n = self.nodes.get(&ino)?;
        let names = n.names() as u32;
        let (size, nlink) = match &n.body {
            Body::File(f) => (f.size, names),
            Body::Symlink(t) => (t.len() as u64, names),
            Body::Special(..) => (0, names),
            Body::Dir(d) => {
                let subdirs = d
                    .entries
                    .values()
                    .filter(|i| self.nodes.get(i).is_some_and(|c| c.kind() == Kind::Dir))
                    .count();
                (4096, 2 + subdirs as u32)
            }
        };
        // A file's blocks cover its size, or the overlay pages it holds (fallocate with
        // KEEP_SIZE reserves pages past the end) when those are more.
        let held = match &n.body {
            Body::File(f) => f.pages.len() as u64 * (PAGE / 512),
            _ => 0,
        };
        Some(Attr {
            ino,
            kind: n.kind(),
            size,
            blocks: size.div_ceil(512).max(held),
            perm: n.perm,
            // A node unlinked while open has no name left.
            nlink: if n.parent == 0 { 0 } else { nlink },
            rdev: match n.body {
                Body::Special(_, rdev) => rdev,
                _ => 0,
            },
            uid: n.uid,
            gid: n.gid,
            atime: n.atime,
            mtime: n.mtime,
            ctime: n.ctime,
        })
    }

    pub fn kind(&self, ino: u64) -> Option<Kind> {
        self.nodes.get(&ino).map(Node::kind)
    }

    /// Where a directory's description stands, or `None` for something that is not one.
    pub fn dir_state(&self, ino: u64) -> Option<DirState> {
        match &self.nodes.get(&ino)?.body {
            Body::Dir(d) => Some(d.state.clone()),
            _ => None,
        }
    }

    /// The parent of a node (the root is its own; an unlinked node has 0).
    pub fn parent(&self, ino: u64) -> Option<u64> {
        self.nodes.get(&ino).map(|n| n.parent)
    }

    /// Directories between a node and the root.
    pub fn depth(&self, ino: u64) -> usize {
        let mut depth = 0;
        let mut at = ino;
        while at != ROOT && depth <= MAX_TREE_DEPTH + 1 {
            match self.nodes.get(&at) {
                Some(n) if n.parent != 0 => at = n.parent,
                _ => break,
            }
            depth += 1;
        }
        depth
    }

    /// The node's path from the root, `/` separated.
    pub fn path(&self, ino: u64) -> String {
        if ino == ROOT {
            return "/".into();
        }
        let mut parts = Vec::new();
        let mut at = ino;
        while at != ROOT && parts.len() <= MAX_TREE_DEPTH + 1 {
            let Some(n) = self.nodes.get(&at) else {
                break;
            };
            parts.push(n.name.as_str());
            if n.parent == 0 {
                parts.push("(unlinked)");
                break;
            }
            at = n.parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// The path a new entry `name` in `parent` would have.
    pub fn child_path(&self, parent: u64, name: &str) -> String {
        let p = self.path(parent);
        if p == "/" {
            format!("/{name}")
        } else {
            format!("{p}/{name}")
        }
    }

    fn dir(&self, ino: u64) -> Outcome<&DirBody> {
        match self.nodes.get(&ino).map(|n| &n.body) {
            None => errno(libc::ENOENT),
            Some(Body::Dir(d)) => match d.state {
                DirState::Described => Ok(d),
                DirState::Pending(_) => Err(Stop::Describe(ino)),
                DirState::Failed => errno(libc::EIO),
                DirState::Refused(code) => errno(code),
            },
            Some(_) => errno(libc::ENOTDIR),
        }
    }

    fn dir_mut(&mut self, ino: u64) -> &mut DirBody {
        match &mut self.nodes.get_mut(&ino).expect("checked").body {
            Body::Dir(d) => d,
            _ => unreachable!("checked to be a directory"),
        }
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Outcome<Attr> {
        let d = self.dir(parent)?;
        match d.entries.get(name) {
            Some(ino) => Ok(self.attr(*ino).expect("an entry names a live node")),
            None => errno(libc::ENOENT),
        }
    }

    /// A described directory's entries: inode, kind and name, in name order.
    pub fn list(&self, ino: u64) -> Outcome<Vec<(u64, Kind, String)>> {
        let d = self.dir(ino)?;
        Ok(d.entries
            .iter()
            .filter_map(|(name, i)| Some((*i, self.nodes.get(i)?.kind(), name.clone())))
            .collect())
    }

    /// Record a description that did not arrive or was refused; true when the directory has
    /// now failed for good.
    pub fn description_failed(&mut self, ino: u64) -> bool {
        if let Some(Node {
            body: Body::Dir(d), ..
        }) = self.nodes.get_mut(&ino)
        {
            if let DirState::Pending(n) = d.state {
                d.state = if n + 1 >= MAX_DESCRIBE_ATTEMPTS {
                    DirState::Failed
                } else {
                    DirState::Pending(n + 1)
                };
            }
            return d.state == DirState::Failed;
        }
        false
    }

    /// Record that the model refused to describe a pending directory: it reads as `code`.
    pub fn description_refused(&mut self, ino: u64, code: i32) {
        if let Some(Node {
            body: Body::Dir(d), ..
        }) = self.nodes.get_mut(&ino)
        {
            if matches!(d.state, DirState::Pending(_)) {
                d.state = DirState::Refused(code);
            }
        }
    }

    /// Commit a model's description of a pending directory: `{"entries": [...]}`. Everything is
    /// checked before anything is committed, so a refused answer changes nothing. Returns the
    /// number of entries described.
    pub fn describe(&mut self, dir: u64, answer: &Json) -> Result<usize> {
        match self.nodes.get(&dir).map(|n| &n.body) {
            Some(Body::Dir(DirBody {
                state: DirState::Pending(_),
                ..
            })) => {}
            Some(Body::Dir(_)) => bail!("the directory is already described"),
            _ => bail!("not a directory"),
        }
        let top = answer
            .get("entries")
            .and_then(Json::as_array)
            .context("entries is an array")?;
        // The directory's own extended attributes (the only way to give the root any), merged
        // over what its parent's entry gave it.
        let own_xattrs = parse_xattrs(answer)?;
        let own_xattr_delta = {
            let n = self.nodes.get(&dir).expect("checked");
            let mut merged = n.xattrs.clone();
            merged.extend(own_xattrs.iter().map(|(k, v)| (k.clone(), v.clone())));
            ensure!(
                merged.len() <= MAX_XATTRS_PER_NODE,
                "a node has at most {MAX_XATTRS_PER_NODE} xattrs"
            );
            xattrs_cost(&merged) as isize - n.xattr_bytes() as isize
        };
        let base_depth = self.depth(dir);
        let mut staged: Vec<Staged> = Vec::new();
        let mut explicit = 0usize;
        let mut xattr_bytes = own_xattr_delta;
        ensure!(
            self.xattr_bytes as isize + xattr_bytes <= MAX_XATTR_BYTES as isize,
            "the tree's xattrs are at most {MAX_XATTR_BYTES} bytes"
        );
        let mut new_nodes = 0usize;
        // Iterative: (the staged directory these entries belong to, its entries, their depth).
        let mut work: Vec<(Option<usize>, &Vec<Json>, usize)> = vec![(None, top, base_depth + 1)];
        while let Some((parent, entries, depth)) = work.pop() {
            ensure!(
                depth <= MAX_TREE_DEPTH,
                "the tree is at most {MAX_TREE_DEPTH} directories deep"
            );
            ensure!(
                entries.len() <= MAX_DIR_ENTRIES,
                "a directory has at most {MAX_DIR_ENTRIES} entries"
            );
            let mut names = HashSet::new();
            for e in entries {
                ensure!(
                    staged.len() < MAX_ENTRIES_PER_ANSWER,
                    "one answer describes at most {MAX_ENTRIES_PER_ANSWER} entries"
                );
                let name = e
                    .get("name")
                    .and_then(Json::as_str)
                    .context("each entry has a name")?;
                ensure!(
                    valid_name(name),
                    "a name is 1 to {MAX_NAME_BYTES} bytes, not . or .., without / or NUL"
                );
                ensure!(
                    names.insert(name),
                    "{name:?} appears twice in one directory"
                );
                let path = match parent {
                    None => self.child_path(dir, name),
                    Some(i) => format!("{}/{name}", staged[i].path),
                };
                let kind = e.get("kind").and_then(Json::as_str).unwrap_or_default();
                if kind == "hardlink" {
                    // Another name for a file: only its target, which owns everything else.
                    for key in e.as_object().map(|o| o.keys()).into_iter().flatten() {
                        ensure!(
                            matches!(key.as_str(), "name" | "kind" | "target"),
                            "a hard link has a name and a target only; {key:?} belongs to the \
                             file it names"
                        );
                    }
                    let target = e
                        .get("target")
                        .and_then(Json::as_str)
                        .context("a hard link has a target: the path of the file it names")?;
                    link_target_path(target)?;
                    staged.push(Staged {
                        parent,
                        name: name.to_string(),
                        path,
                        xattrs: BTreeMap::new(),
                        perm: 0,
                        uid: 0,
                        gid: 0,
                        atime: self.born,
                        mtime: self.born,
                        ctime: self.born,
                        body: StagedBody::HardLink(target.to_string()),
                    });
                    continue;
                }
                ensure!(
                    self.nodes.len() + new_nodes < MAX_NODES,
                    "the tree holds at most {MAX_NODES} entries"
                );
                new_nodes += 1;
                let xattrs = parse_xattrs(e)?;
                xattr_bytes += xattrs_cost(&xattrs) as isize;
                ensure!(
                    self.xattr_bytes as isize + xattr_bytes <= MAX_XATTR_BYTES as isize,
                    "the tree's xattrs are at most {MAX_XATTR_BYTES} bytes"
                );
                let mtime = time_of(e, "mtime")?.unwrap_or(self.born);
                let atime = time_of(e, "atime")?.unwrap_or(mtime);
                let ctime = time_of(e, "ctime")?.unwrap_or(mtime);
                let (body, default_perm) = match kind {
                    "file" => {
                        let (size, base, errors, bytes) = file_content(e)?;
                        explicit += bytes;
                        ensure!(
                            self.described_bytes + explicit <= MAX_DESCRIBED_BYTES,
                            "the tree's text and hex are at most {MAX_DESCRIBED_BYTES} bytes"
                        );
                        (StagedBody::File { size, base, errors }, 0o644)
                    }
                    "dir" | "directory" => {
                        let nested = match e.get("entries") {
                            None | Some(Json::Null) => None,
                            Some(Json::Array(a)) => Some(a),
                            Some(_) => bail!("a directory's entries is an array"),
                        };
                        if let Some(children) = nested {
                            work.push((Some(staged.len()), children, depth + 1));
                        }
                        (
                            StagedBody::Dir {
                                described: nested.is_some(),
                            },
                            0o755,
                        )
                    }
                    "symlink" => {
                        let target = e
                            .get("target")
                            .and_then(Json::as_str)
                            .context("a symlink has a target")?;
                        ensure!(
                            !target.is_empty()
                                && target.len() <= MAX_SYMLINK_TARGET
                                && !target.contains('\0'),
                            "a symlink target is 1 to {MAX_SYMLINK_TARGET} bytes without NUL"
                        );
                        (StagedBody::Symlink(target.to_string()), 0o777)
                    }
                    _ => bail!("kind is file, dir, symlink or hardlink"),
                };
                let perm = match e.get("mode") {
                    None | Some(Json::Null) => default_perm,
                    Some(m) => {
                        let m = m.as_u64().context("mode is a number (420 is 0644)")?;
                        ensure!(m <= 0o7777, "mode is permission bits, at most 4095 (07777)");
                        m as u16
                    }
                };
                staged.push(Staged {
                    parent,
                    name: name.to_string(),
                    path,
                    xattrs,
                    perm,
                    uid: id_of(e, "uid", self.uid)?,
                    gid: id_of(e, "gid", self.gid)?,
                    atime,
                    mtime,
                    ctime,
                    body,
                });
            }
        }
        // Hard links, now that every entry is staged: each names a file (or symlink) described
        // in this answer or already in the tree, and no file gets more than MAX_LINKS names.
        let by_path: HashMap<&str, usize> = staged
            .iter()
            .enumerate()
            .map(|(i, s)| (s.path.as_str(), i))
            .collect();
        let mut targets: Vec<Option<LinkTarget>> = vec![None; staged.len()];
        let mut added: HashMap<(bool, u64), usize> = HashMap::new();
        let mut links = 0usize;
        for (i, s) in staged.iter().enumerate() {
            let StagedBody::HardLink(target) = &s.body else {
                continue;
            };
            let resolved = match by_path.get(target.as_str()) {
                Some(&j) => match staged[j].body {
                    StagedBody::File { .. } | StagedBody::Symlink(_) => LinkTarget::Staged(j),
                    StagedBody::Dir { .. } => {
                        bail!("hard link {} names {target}, a directory", s.path)
                    }
                    StagedBody::HardLink(_) => bail!(
                        "hard link {} names {target}, another hard link: name the file itself",
                        s.path
                    ),
                },
                None => match self.resolve_described(target) {
                    Some(ino) if self.kind(ino) != Some(Kind::Dir) => LinkTarget::Existing(ino),
                    Some(_) => bail!("hard link {} names {target}, a directory", s.path),
                    None => bail!(
                        "hard link {} names {target}, which is not a file described in this \
                         answer or before it",
                        s.path
                    ),
                },
            };
            let (key, before) = match resolved {
                LinkTarget::Staged(j) => ((true, j as u64), 1),
                LinkTarget::Existing(ino) => (
                    (false, ino),
                    self.nodes.get(&ino).map_or(1, |n| n.names().max(1)),
                ),
            };
            let n = added.entry(key).or_default();
            *n += 1;
            ensure!(
                before + *n <= MAX_LINKS,
                "a file has at most {MAX_LINKS} names ({target} would have more)"
            );
            links += 1;
            ensure!(
                self.hard_links + links <= MAX_HARD_LINKS,
                "the tree holds at most {MAX_HARD_LINKS} hard links"
            );
            targets[i] = Some(resolved);
        }
        // Commit: every check above passed. Nodes first, then the hard links naming them.
        let mut inos = vec![0u64; staged.len()];
        let count = staged.len();
        let mut link_names: Vec<(usize, u64, String)> = Vec::new();
        for (i, s) in staged.into_iter().enumerate() {
            let parent = s.parent.map_or(dir, |p| inos[p]);
            if let StagedBody::HardLink(_) = s.body {
                link_names.push((i, parent, s.name));
                continue;
            }
            let ino = self.next_ino;
            self.next_ino += 1;
            let body = match s.body {
                StagedBody::File { size, base, errors } => Body::File(FileBody {
                    size,
                    base,
                    errors,
                    base_limit: size,
                    pages: BTreeMap::new(),
                }),
                StagedBody::Dir { described } => Body::Dir(DirBody {
                    entries: BTreeMap::new(),
                    state: if described {
                        DirState::Described
                    } else {
                        DirState::Pending(0)
                    },
                }),
                StagedBody::Symlink(t) => Body::Symlink(t),
                StagedBody::HardLink(_) => unreachable!("handled above"),
            };
            self.dir_mut(parent).entries.insert(s.name.clone(), ino);
            self.nodes.insert(
                ino,
                Node {
                    parent,
                    name: s.name,
                    links: Vec::new(),
                    xattrs: s.xattrs,
                    perm: s.perm,
                    uid: s.uid,
                    gid: s.gid,
                    atime: s.atime,
                    mtime: s.mtime,
                    ctime: s.ctime,
                    open: 0,
                    body,
                },
            );
            inos[i] = ino;
        }
        for (i, parent, name) in link_names {
            let ino = match targets[i].expect("resolved above") {
                LinkTarget::Staged(j) => inos[j],
                LinkTarget::Existing(ino) => ino,
            };
            inos[i] = ino;
            self.dir_mut(parent).entries.insert(name.clone(), ino);
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.links.push((parent, name));
            }
            self.hard_links += 1;
        }
        if let Some(n) = self.nodes.get_mut(&dir) {
            n.xattrs.extend(own_xattrs);
        }
        self.dir_mut(dir).state = DirState::Described;
        self.described_bytes += explicit;
        self.xattr_bytes = (self.xattr_bytes as isize + xattr_bytes) as usize;
        Ok(count)
    }

    /// The node a path names, walking only directories already described (no description is
    /// asked for); `None` when any step is missing or not described.
    fn resolve_described(&self, path: &str) -> Option<u64> {
        let parts = link_target_path(path).ok()?;
        let mut at = ROOT;
        for c in parts {
            at = *self.dir(at).ok()?.entries.get(c)?;
        }
        Some(at)
    }

    /// Bytes of a file at an offset, at most `size` of them and none past its end; an errno
    /// when the range touches a failing region the overlay has not overwritten.
    pub fn read(&self, ino: u64, offset: u64, size: u32) -> Outcome<Vec<u8>> {
        let f = match self.nodes.get(&ino).map(|n| &n.body) {
            None => return errno(libc::ENOENT),
            Some(Body::File(f)) => f,
            Some(Body::Dir(_)) => return errno(libc::EISDIR),
            Some(Body::Symlink(_) | Body::Special(..)) => return errno(libc::EINVAL),
        };
        let end = offset.saturating_add(size as u64).min(f.size);
        if offset >= end {
            return Ok(vec![]);
        }
        let mut out = vec![0u8; (end - offset) as usize];
        let mut pos = offset;
        while pos < end {
            let page = pos / PAGE;
            let start = page * PAGE;
            let stop = (start + PAGE).min(end);
            let dst = &mut out[(pos - offset) as usize..(stop - offset) as usize];
            if let Some(p) = f.pages.get(&page) {
                dst.copy_from_slice(&p[(pos - start) as usize..(stop - start) as usize]);
            } else if pos < f.base_limit {
                let base_end = stop.min(f.base_limit);
                if let Some((_, code)) = described_disk::error_in(&f.errors, pos, base_end - pos) {
                    return errno(code as i32);
                }
                let bytes = described_disk::read(&f.base, pos, (base_end - pos) as usize);
                dst[..bytes.len()].copy_from_slice(&bytes);
            }
            pos = stop;
        }
        Ok(out)
    }

    pub fn readlink(&self, ino: u64) -> Outcome<String> {
        match self.nodes.get(&ino).map(|n| &n.body) {
            None => errno(libc::ENOENT),
            Some(Body::Symlink(t)) => Ok(t.clone()),
            Some(_) => errno(libc::EINVAL),
        }
    }

    pub fn opened(&mut self, ino: u64) {
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.open = n.open.saturating_add(1);
        }
    }

    pub fn released(&mut self, ino: u64) {
        let gone = match self.nodes.get_mut(&ino) {
            Some(n) => {
                n.open = n.open.saturating_sub(1);
                n.open == 0 && n.parent == 0
            }
            None => false,
        };
        if gone {
            self.drop_node(ino);
        }
    }

    /// Remove a node from the table and return its overlay and extended-attribute bytes.
    fn drop_node(&mut self, ino: u64) {
        if let Some(n) = self.nodes.remove(&ino) {
            let freed = match &n.body {
                Body::File(f) => f.pages.len() as u64 * PAGE,
                Body::Symlink(t) => t.len() as u64,
                Body::Dir(_) | Body::Special(..) => 0,
            };
            self.overlay_bytes = self.overlay_bytes.saturating_sub(freed);
            self.xattr_bytes = self.xattr_bytes.saturating_sub(n.xattr_bytes());
            self.hard_links = self.hard_links.saturating_sub(n.links.len());
        }
    }

    /// Remove one name of a node from its record: the first name gives way to the next hard
    /// link, if there is one. True when the node has no name left.
    fn forget_name(&mut self, ino: u64, parent: u64, name: &str) -> bool {
        let Some(n) = self.nodes.get_mut(&ino) else {
            return false;
        };
        if n.parent == parent && n.name == name {
            if n.links.is_empty() {
                return true;
            }
            let (p, nm) = n.links.remove(0);
            n.parent = p;
            n.name = nm;
        } else if let Some(i) = n
            .links
            .iter()
            .position(|(p, nm)| *p == parent && nm == name)
        {
            n.links.remove(i);
        } else {
            return false;
        }
        self.hard_links -= 1;
        false
    }

    /// Point the record of one of a node's names somewhere else (rename, exchange).
    fn move_name(&mut self, ino: u64, from: (u64, &str), to: (u64, &str)) {
        let Some(n) = self.nodes.get_mut(&ino) else {
            return;
        };
        if n.parent == from.0 && n.name == from.1 {
            n.parent = to.0;
            n.name = to.1.to_string();
        } else if let Some(l) = n
            .links
            .iter_mut()
            .find(|(p, nm)| *p == from.0 && nm == from.1)
        {
            *l = (to.0, to.1.to_string());
        }
    }

    /// Detach `name` from `parent`. The node goes with its last name, unless it is open, in
    /// which case it lives on nameless until its last release.
    fn detach(&mut self, parent: u64, name: &str, now: SystemTime) {
        let Some(ino) = self.dir_mut(parent).entries.remove(name) else {
            return;
        };
        self.touch_dir(parent, now);
        if !self.forget_name(ino, parent, name) {
            // Other names remain: the inode stays, its link count one less.
            if let Some(n) = self.nodes.get_mut(&ino) {
                advance(&mut n.ctime, now);
            }
            return;
        }
        let open = self.nodes.get(&ino).is_some_and(|n| n.open > 0);
        if open {
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.parent = 0;
                advance(&mut n.ctime, now);
            }
        } else {
            self.drop_node(ino);
        }
    }

    fn touch_dir(&mut self, ino: u64, now: SystemTime) {
        if let Some(n) = self.nodes.get_mut(&ino) {
            advance(&mut n.mtime, now);
            advance(&mut n.ctime, now);
        }
    }

    /// Whether a new entry `name` for a new node may appear in `parent`.
    pub fn check_new_entry(&self, parent: u64, name: &str) -> Outcome<()> {
        self.check_new_name(parent, name)?;
        if self.nodes.len() >= MAX_NODES {
            return errno(libc::ENOSPC);
        }
        Ok(())
    }

    /// Whether a new name may appear in `parent` (for a new node or another name of one).
    fn check_new_name(&self, parent: u64, name: &str) -> Outcome<()> {
        let d = self.dir(parent)?;
        if name.len() > MAX_NAME_BYTES {
            return errno(libc::ENAMETOOLONG);
        }
        if !valid_name(name) {
            return errno(libc::EINVAL);
        }
        if d.entries.contains_key(name) {
            return errno(libc::EEXIST);
        }
        if d.entries.len() >= MAX_DIR_ENTRIES {
            return errno(libc::ENOSPC);
        }
        if self.depth(parent) + 1 > MAX_TREE_DEPTH {
            return errno(libc::ENAMETOOLONG);
        }
        Ok(())
    }

    /// Whether `ino` may have another name, `new_name` in `new_parent` (link(2)).
    pub fn check_link(&self, ino: u64, new_parent: u64, new_name: &str) -> Outcome<()> {
        let n = self.nodes.get(&ino).ok_or(Stop::Errno(libc::ENOENT))?;
        if n.kind() == Kind::Dir {
            return errno(libc::EPERM);
        }
        self.check_new_name(new_parent, new_name)?;
        // Unlinked while open: nothing names it any more, so nothing can link to it.
        if n.parent == 0 {
            return errno(libc::ENOENT);
        }
        if n.names() >= MAX_LINKS {
            return errno(libc::EMLINK);
        }
        if self.hard_links >= MAX_HARD_LINKS {
            return errno(libc::ENOSPC);
        }
        Ok(())
    }

    /// Give `ino` another name: one inode, one more link.
    pub fn link(&mut self, ino: u64, new_parent: u64, new_name: &str) -> Outcome<Attr> {
        self.check_link(ino, new_parent, new_name)?;
        let now = SystemTime::now();
        self.dir_mut(new_parent)
            .entries
            .insert(new_name.to_string(), ino);
        self.touch_dir(new_parent, now);
        let n = self.nodes.get_mut(&ino).expect("checked");
        n.links.push((new_parent, new_name.to_string()));
        advance(&mut n.ctime, now);
        self.hard_links += 1;
        Ok(self.attr(ino).expect("live"))
    }

    /// Every path a node has, its first name first.
    pub fn paths(&self, ino: u64) -> Vec<String> {
        let Some(n) = self.nodes.get(&ino) else {
            return vec![];
        };
        if n.parent == 0 {
            return vec![];
        }
        let mut out = vec![self.path(ino)];
        out.extend(n.links.iter().map(|(p, nm)| self.child_path(*p, nm)));
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        parent: u64,
        name: &str,
        perm: u16,
        uid: u32,
        gid: u32,
        body: Body,
        now: SystemTime,
    ) -> Attr {
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(
            ino,
            Node {
                parent,
                name: name.to_string(),
                links: Vec::new(),
                xattrs: BTreeMap::new(),
                perm: perm & 0o7777,
                uid,
                gid,
                atime: now,
                mtime: now,
                ctime: now,
                open: 0,
                body,
            },
        );
        self.dir_mut(parent).entries.insert(name.to_string(), ino);
        self.touch_dir(parent, now);
        self.attr(ino).expect("just inserted")
    }

    pub fn create(
        &mut self,
        parent: u64,
        name: &str,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Outcome<Attr> {
        self.check_new_entry(parent, name)?;
        let body = Body::File(FileBody {
            size: 0,
            base: vec![],
            errors: vec![],
            base_limit: 0,
            pages: BTreeMap::new(),
        });
        Ok(self.insert(parent, name, perm, uid, gid, body, SystemTime::now()))
    }

    pub fn mkdir(
        &mut self,
        parent: u64,
        name: &str,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Outcome<Attr> {
        self.check_new_entry(parent, name)?;
        let body = Body::Dir(DirBody {
            entries: BTreeMap::new(),
            state: DirState::Described,
        });
        Ok(self.insert(parent, name, perm, uid, gid, body, SystemTime::now()))
    }

    /// A FIFO, socket or device node (mknod, mkfifo, bind). `kind` must be one of those four.
    #[allow(clippy::too_many_arguments)]
    pub fn mknod(
        &mut self,
        parent: u64,
        name: &str,
        kind: Kind,
        perm: u16,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Outcome<Attr> {
        if matches!(kind, Kind::File | Kind::Dir | Kind::Symlink) {
            return errno(libc::EINVAL);
        }
        self.check_new_entry(parent, name)?;
        let body = Body::Special(kind, rdev);
        Ok(self.insert(parent, name, perm, uid, gid, body, SystemTime::now()))
    }

    pub fn check_symlink(&self, parent: u64, name: &str, target: &str) -> Outcome<()> {
        self.check_new_entry(parent, name)?;
        if target.is_empty() {
            return errno(libc::ENOENT);
        }
        if target.len() > MAX_SYMLINK_TARGET {
            return errno(libc::ENAMETOOLONG);
        }
        if target.contains('\0') {
            return errno(libc::EINVAL);
        }
        if self.overlay_bytes + target.len() as u64 > self.max_overlay {
            return errno(libc::ENOSPC);
        }
        Ok(())
    }

    pub fn symlink(
        &mut self,
        parent: u64,
        name: &str,
        target: &str,
        uid: u32,
        gid: u32,
    ) -> Outcome<Attr> {
        self.check_symlink(parent, name, target)?;
        self.overlay_bytes += target.len() as u64;
        let body = Body::Symlink(target.to_string());
        Ok(self.insert(parent, name, 0o777, uid, gid, body, SystemTime::now()))
    }

    pub fn check_unlink(&self, parent: u64, name: &str) -> Outcome<u64> {
        let d = self.dir(parent)?;
        let ino = *d.entries.get(name).ok_or(Stop::Errno(libc::ENOENT))?;
        if self.kind(ino) == Some(Kind::Dir) {
            return errno(libc::EISDIR);
        }
        Ok(ino)
    }

    pub fn unlink(&mut self, parent: u64, name: &str) -> Outcome<()> {
        self.check_unlink(parent, name)?;
        self.detach(parent, name, SystemTime::now());
        Ok(())
    }

    /// Whether a directory is described and empty (`Describe` when it has not been described).
    fn check_empty_dir(&self, ino: u64) -> Outcome<()> {
        let d = self.dir(ino)?;
        if d.entries.is_empty() {
            Ok(())
        } else {
            errno(libc::ENOTEMPTY)
        }
    }

    pub fn check_rmdir(&self, parent: u64, name: &str) -> Outcome<u64> {
        let d = self.dir(parent)?;
        let ino = *d.entries.get(name).ok_or(Stop::Errno(libc::ENOENT))?;
        if self.kind(ino) != Some(Kind::Dir) {
            return errno(libc::ENOTDIR);
        }
        self.check_empty_dir(ino)?;
        Ok(ino)
    }

    pub fn rmdir(&mut self, parent: u64, name: &str) -> Outcome<()> {
        self.check_rmdir(parent, name)?;
        self.detach(parent, name, SystemTime::now());
        Ok(())
    }

    /// Remove `name` from `parent` with everything below it, whether or not the directories
    /// below were ever described; the inodes removed, the top one first. Iterative. This is
    /// HDFS's recursive delete, which is one namespace operation rather than an unlink or rmdir
    /// per entry, so it does not ask for a description of a directory it is about to discard.
    /// Open counts are not consulted: nothing that uses it opens nodes. A file with a hard link
    /// outside the subtree loses only its names inside it, and is not among those returned.
    pub fn remove_subtree(&mut self, parent: u64, name: &str) -> Outcome<Vec<u64>> {
        let d = self.dir(parent)?;
        let top = *d.entries.get(name).ok_or(Stop::Errno(libc::ENOENT))?;
        // Every (directory, name, inode) in the subtree.
        let mut names = Vec::new();
        let mut work = vec![(parent, name.to_string(), top)];
        while let Some((at, nm, ino)) = work.pop() {
            if let Some(Node {
                body: Body::Dir(d), ..
            }) = self.nodes.get(&ino)
            {
                work.extend(d.entries.iter().map(|(n, i)| (ino, n.clone(), *i)));
            }
            names.push((at, nm, ino));
        }
        self.dir_mut(parent).entries.remove(name);
        self.touch_dir(parent, SystemTime::now());
        let mut removed = Vec::new();
        for (at, nm, ino) in names {
            if self.kind(ino) != Some(Kind::Dir) && !self.forget_name(ino, at, &nm) {
                continue;
            }
            self.drop_node(ino);
            removed.push(ino);
        }
        Ok(removed)
    }

    /// The deepest directory level under `ino`, relative to it (0 for a non-directory or an
    /// empty one). Iterative, and bounded by the tree.
    fn height(&self, ino: u64) -> usize {
        let mut deepest = 0;
        let mut work = vec![(ino, 0usize)];
        while let Some((at, level)) = work.pop() {
            if let Some(Node {
                body: Body::Dir(d), ..
            }) = self.nodes.get(&at)
            {
                for child in d.entries.values() {
                    if self.kind(*child) == Some(Kind::Dir) {
                        deepest = deepest.max(level + 1);
                        work.push((*child, level + 1));
                    }
                }
            }
        }
        deepest
    }

    /// Whether `ancestor` is `ino` or above it.
    fn is_ancestor(&self, ancestor: u64, ino: u64) -> bool {
        let mut at = ino;
        for _ in 0..=MAX_TREE_DEPTH + 1 {
            if at == ancestor {
                return true;
            }
            if at == ROOT || at == 0 {
                return false;
            }
            match self.nodes.get(&at) {
                Some(n) => at = n.parent,
                None => return false,
            }
        }
        false
    }

    /// Whether a rename may happen; `Some(ino)` is the entry it would replace.
    pub fn check_rename(
        &self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Outcome<Option<u64>> {
        let from = self.dir(parent)?;
        let to = self.dir(new_parent)?;
        let src = *from.entries.get(name).ok_or(Stop::Errno(libc::ENOENT))?;
        if new_name.len() > MAX_NAME_BYTES {
            return errno(libc::ENAMETOOLONG);
        }
        if !valid_name(new_name) {
            return errno(libc::EINVAL);
        }
        let src_dir = self.kind(src) == Some(Kind::Dir);
        if src_dir && self.is_ancestor(src, new_parent) {
            return errno(libc::EINVAL);
        }
        if self.depth(new_parent) + 1 + self.height(src) > MAX_TREE_DEPTH {
            return errno(libc::ENAMETOOLONG);
        }
        match to.entries.get(new_name) {
            Some(&dst) if dst == src => Ok(None),
            Some(&dst) => {
                if no_replace {
                    return errno(libc::EEXIST);
                }
                let dst_dir = self.kind(dst) == Some(Kind::Dir);
                match (src_dir, dst_dir) {
                    (true, false) => errno(libc::ENOTDIR),
                    (false, true) => errno(libc::EISDIR),
                    (true, true) => self.check_empty_dir(dst).map(|_| Some(dst)),
                    (false, false) => Ok(Some(dst)),
                }
            }
            None => {
                if to.entries.len() >= MAX_DIR_ENTRIES && parent != new_parent {
                    return errno(libc::ENOSPC);
                }
                Ok(None)
            }
        }
    }

    pub fn rename(
        &mut self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Outcome<()> {
        self.check_rename(parent, name, new_parent, new_name, no_replace)?;
        let now = SystemTime::now();
        let src = *self.dir(parent)?.entries.get(name).expect("checked");
        if self.dir(new_parent)?.entries.get(new_name) == Some(&src) {
            return Ok(());
        }
        if self.dir(new_parent)?.entries.contains_key(new_name) {
            self.detach(new_parent, new_name, now);
        }
        self.dir_mut(parent).entries.remove(name);
        self.dir_mut(new_parent)
            .entries
            .insert(new_name.to_string(), src);
        self.move_name(src, (parent, name), (new_parent, new_name));
        if let Some(n) = self.nodes.get_mut(&src) {
            advance(&mut n.ctime, now);
        }
        self.touch_dir(parent, now);
        self.touch_dir(new_parent, now);
        Ok(())
    }

    /// Whether `name` in `parent` and `new_name` in `new_parent` may swap places
    /// (RENAME_EXCHANGE): both exist, neither directory would land inside itself, and both
    /// stay within the depth bound. The two inodes.
    pub fn check_exchange(
        &self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Outcome<(u64, u64)> {
        let from = self.dir(parent)?;
        let to = self.dir(new_parent)?;
        let a = *from.entries.get(name).ok_or(Stop::Errno(libc::ENOENT))?;
        let b = *to.entries.get(new_name).ok_or(Stop::Errno(libc::ENOENT))?;
        if a == b {
            return Ok((a, b));
        }
        if self.kind(a) == Some(Kind::Dir) && self.is_ancestor(a, new_parent) {
            return errno(libc::EINVAL);
        }
        if self.kind(b) == Some(Kind::Dir) && self.is_ancestor(b, parent) {
            return errno(libc::EINVAL);
        }
        if self.depth(new_parent) + 1 + self.height(a) > MAX_TREE_DEPTH
            || self.depth(parent) + 1 + self.height(b) > MAX_TREE_DEPTH
        {
            return errno(libc::ENAMETOOLONG);
        }
        Ok((a, b))
    }

    /// Swap two entries atomically (RENAME_EXCHANGE): each name now names the other's inode.
    pub fn exchange(
        &mut self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Outcome<()> {
        let (a, b) = self.check_exchange(parent, name, new_parent, new_name)?;
        if a == b {
            return Ok(());
        }
        let now = SystemTime::now();
        self.dir_mut(parent).entries.insert(name.to_string(), b);
        self.dir_mut(new_parent)
            .entries
            .insert(new_name.to_string(), a);
        // Through a placeholder, so that two names of one directory swapping cannot confuse
        // which record is which.
        self.move_name(a, (parent, name), (0, ""));
        self.move_name(b, (new_parent, new_name), (parent, name));
        self.move_name(a, (0, ""), (new_parent, new_name));
        for ino in [a, b] {
            if let Some(n) = self.nodes.get_mut(&ino) {
                advance(&mut n.ctime, now);
            }
        }
        self.touch_dir(parent, now);
        self.touch_dir(new_parent, now);
        Ok(())
    }

    fn file(&self, ino: u64) -> Outcome<&FileBody> {
        match self.nodes.get(&ino).map(|n| &n.body) {
            None => errno(libc::ENOENT),
            Some(Body::File(f)) => Ok(f),
            Some(Body::Dir(_)) => errno(libc::EISDIR),
            Some(Body::Symlink(_) | Body::Special(..)) => errno(libc::EINVAL),
        }
    }

    /// Whether `length` bytes may be written at `offset`; the overlay bytes it would add.
    pub fn check_write(&self, ino: u64, offset: u64, length: usize) -> Outcome<u64> {
        let f = self.file(ino)?;
        if length == 0 {
            return Ok(0);
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or(Stop::Errno(libc::EFBIG))?;
        if end > MAX_FILE_SIZE {
            return errno(libc::EFBIG);
        }
        let new_pages = (offset / PAGE..=(end - 1) / PAGE)
            .filter(|p| !f.pages.contains_key(p))
            .count() as u64;
        let extra = new_pages * PAGE;
        if self.overlay_bytes + extra > self.max_overlay {
            return errno(libc::ENOSPC);
        }
        Ok(extra)
    }

    /// A page as the file shows it now, before any write lands on it.
    fn page_view(f: &FileBody, page: u64) -> Box<[u8]> {
        let mut buf = vec![0u8; PAGE as usize].into_boxed_slice();
        let start = page * PAGE;
        if start < f.base_limit {
            let n = PAGE.min(f.base_limit - start) as usize;
            let bytes = described_disk::read(&f.base, start, n);
            buf[..n].copy_from_slice(&bytes);
        }
        buf
    }

    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Outcome<u32> {
        let extra = self.check_write(ino, offset, data.len())?;
        if data.is_empty() {
            return Ok(0);
        }
        let now = SystemTime::now();
        let node = self.nodes.get_mut(&ino).expect("checked");
        let Body::File(f) = &mut node.body else {
            unreachable!("checked to be a file")
        };
        let end = offset + data.len() as u64;
        for page in offset / PAGE..=(end - 1) / PAGE {
            if !f.pages.contains_key(&page) {
                let view = Self::page_view(f, page);
                f.pages.insert(page, view);
            }
            let buf = f.pages.get_mut(&page).expect("inserted");
            let start = page * PAGE;
            let (s, e) = (offset.max(start), end.min(start + PAGE));
            buf[(s - start) as usize..(e - start) as usize]
                .copy_from_slice(&data[(s - offset) as usize..(e - offset) as usize]);
        }
        f.size = f.size.max(end);
        advance(&mut node.mtime, now);
        advance(&mut node.ctime, now);
        self.overlay_bytes += extra;
        Ok(data.len() as u32)
    }

    pub fn check_truncate(&self, ino: u64, size: u64) -> Outcome<()> {
        self.file(ino)?;
        if size > MAX_FILE_SIZE {
            return errno(libc::EFBIG);
        }
        Ok(())
    }

    /// The size a file has now.
    pub fn size(&self, ino: u64) -> Option<u64> {
        self.attr(ino).map(|a| a.size)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> Outcome<()> {
        self.check_truncate(ino, size)?;
        let now = SystemTime::now();
        let node = self.nodes.get_mut(&ino).expect("checked");
        let Body::File(f) = &mut node.body else {
            unreachable!("checked to be a file")
        };
        let mut freed = 0;
        if size < f.size {
            let keep = size.div_ceil(PAGE);
            let gone: Vec<u64> = f.pages.range(keep..).map(|(p, _)| *p).collect();
            for p in gone {
                f.pages.remove(&p);
                freed += PAGE;
            }
            if !size.is_multiple_of(PAGE) {
                if let Some(p) = f.pages.get_mut(&(size / PAGE)) {
                    p[(size % PAGE) as usize..].fill(0);
                }
            }
            f.base_limit = f.base_limit.min(size);
        }
        f.size = size;
        advance(&mut node.mtime, now);
        advance(&mut node.ctime, now);
        self.overlay_bytes -= freed;
        Ok(())
    }

    pub fn setattr(&mut self, ino: u64, changes: &Changes) -> Outcome<Attr> {
        let node = self.nodes.get_mut(&ino).ok_or(Stop::Errno(libc::ENOENT))?;
        if let Some(p) = changes.perm {
            node.perm = p & 0o7777;
        }
        if let Some(u) = changes.uid {
            node.uid = u;
        }
        if let Some(g) = changes.gid {
            node.gid = g;
        }
        if let Some(t) = changes.atime {
            node.atime = t;
        }
        if let Some(t) = changes.mtime {
            node.mtime = t;
        }
        advance(&mut node.ctime, SystemTime::now());
        Ok(self.attr(ino).expect("live"))
    }

    // ---------------------------------------------------------------- extended attributes

    fn node(&self, ino: u64) -> Outcome<&Node> {
        self.nodes.get(&ino).ok_or(Stop::Errno(libc::ENOENT))
    }

    /// An extended attribute's value: ENODATA when the node has none by that name, EOPNOTSUPP
    /// for a namespace the tree does not hold.
    pub fn getxattr(&self, ino: u64, name: &str) -> Outcome<&[u8]> {
        let n = self.node(ino)?;
        check_xattr_name(name)?;
        n.xattrs
            .get(name)
            .map(Vec::as_slice)
            .ok_or(Stop::Errno(libc::ENODATA))
    }

    /// The node's extended-attribute names, each followed by a NUL: listxattr(2)'s format.
    pub fn listxattr(&self, ino: u64) -> Outcome<Vec<u8>> {
        let n = self.node(ino)?;
        let mut out = Vec::new();
        for name in n.xattrs.keys() {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        Ok(out)
    }

    /// The node's extended-attribute names.
    pub fn xattr_names(&self, ino: u64) -> Vec<String> {
        self.nodes
            .get(&ino)
            .map(|n| n.xattrs.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether `name` may be set to a value of `len` bytes under `mode`; whether it exists now.
    /// EEXIST (XATTR_CREATE) and ENODATA (XATTR_REPLACE) as setxattr(2) says; E2BIG past
    /// [`MAX_XATTR_VALUE_BYTES`]; ENOSPC past [`MAX_XATTRS_PER_NODE`] or [`MAX_XATTR_BYTES`].
    pub fn check_setxattr(
        &self,
        ino: u64,
        name: &str,
        len: usize,
        mode: XattrMode,
    ) -> Outcome<bool> {
        let n = self.node(ino)?;
        check_xattr_name(name)?;
        if len > MAX_XATTR_VALUE_BYTES {
            return errno(libc::E2BIG);
        }
        let old = n.xattrs.get(name);
        match (mode, old.is_some()) {
            (XattrMode::Create, true) => return errno(libc::EEXIST),
            (XattrMode::Replace, false) => return errno(libc::ENODATA),
            _ => {}
        }
        if old.is_none() && n.xattrs.len() >= MAX_XATTRS_PER_NODE {
            return errno(libc::ENOSPC);
        }
        let freed = old.map_or(0, |v| xattr_cost(name, v));
        if self.xattr_bytes - freed + name.len() + len > MAX_XATTR_BYTES {
            return errno(libc::ENOSPC);
        }
        Ok(old.is_some())
    }

    pub fn setxattr(&mut self, ino: u64, name: &str, value: &[u8], mode: XattrMode) -> Outcome<()> {
        self.check_setxattr(ino, name, value.len(), mode)?;
        let n = self.nodes.get_mut(&ino).expect("checked");
        let freed = n
            .xattrs
            .insert(name.to_string(), value.to_vec())
            .map_or(0, |v| xattr_cost(name, &v));
        advance(&mut n.ctime, SystemTime::now());
        self.xattr_bytes = self.xattr_bytes - freed + xattr_cost(name, value);
        Ok(())
    }

    /// Whether `name` may be removed: ENODATA when there is none by that name.
    pub fn check_removexattr(&self, ino: u64, name: &str) -> Outcome<()> {
        self.getxattr(ino, name).map(|_| ())
    }

    pub fn removexattr(&mut self, ino: u64, name: &str) -> Outcome<()> {
        self.check_removexattr(ino, name)?;
        let n = self.nodes.get_mut(&ino).expect("checked");
        if let Some(v) = n.xattrs.remove(name) {
            self.xattr_bytes -= xattr_cost(name, &v);
        }
        advance(&mut n.ctime, SystemTime::now());
        Ok(())
    }

    // ---------------------------------------------------------------- fallocate

    /// The byte range a fallocate acts on: a punched hole stops at the end of the file.
    fn alloc_range(f: &FileBody, offset: u64, end: u64, how: Allocation) -> (u64, u64) {
        match how {
            Allocation::PunchHole => (offset, end.min(f.size)),
            _ => (offset, end),
        }
    }

    /// What `how` does to one page, given the range `[s, e)` it acts on.
    fn page_op(f: &FileBody, page: u64, s: u64, e: u64, how: Allocation) -> PageOp {
        let start = page * PAGE;
        let stop = start + PAGE;
        let (a, b) = (s.max(start), e.min(stop));
        let present = f.pages.contains_key(&page);
        let zero = PageOp::Zero((a - start) as usize, (b - start) as usize);
        match how {
            Allocation::Allocate { .. } if present => PageOp::Nothing,
            Allocation::Allocate { .. } => PageOp::Materialize,
            Allocation::ZeroRange { .. } => zero,
            Allocation::PunchHole => {
                let whole = a == start && b == stop;
                if whole && start >= f.base_limit {
                    // Nothing described beneath it: without its page it reads as zeroes.
                    if present {
                        PageOp::Drop
                    } else {
                        PageOp::Nothing
                    }
                } else if present || a < f.base_limit {
                    zero
                } else {
                    PageOp::Nothing
                }
            }
        }
    }

    /// Whether a fallocate may happen: EINVAL for an empty range, EFBIG past the file bound,
    /// ENOSPC when the pages it would add do not fit in the overlay. The overlay bytes it adds
    /// and frees.
    pub fn check_fallocate(
        &self,
        ino: u64,
        offset: u64,
        length: u64,
        how: Allocation,
    ) -> Outcome<(u64, u64)> {
        let f = self.file(ino)?;
        if length == 0 {
            return errno(libc::EINVAL);
        }
        let end = offset.checked_add(length).ok_or(Stop::Errno(libc::EFBIG))?;
        if end > MAX_FILE_SIZE {
            return errno(libc::EFBIG);
        }
        let (s, e) = Self::alloc_range(f, offset, end, how);
        let (mut added, mut freed) = (0u64, 0u64);
        if s < e {
            for page in s / PAGE..=(e - 1) / PAGE {
                let present = f.pages.contains_key(&page);
                match Self::page_op(f, page, s, e, how) {
                    PageOp::Materialize | PageOp::Zero(..) if !present => added += PAGE,
                    PageOp::Drop => freed += PAGE,
                    _ => {}
                }
            }
        }
        if self.overlay_bytes + added > self.max_overlay + freed {
            return errno(libc::ENOSPC);
        }
        Ok((added, freed))
    }

    pub fn fallocate(
        &mut self,
        ino: u64,
        offset: u64,
        length: u64,
        how: Allocation,
    ) -> Outcome<()> {
        let (added, freed) = self.check_fallocate(ino, offset, length, how)?;
        let now = SystemTime::now();
        let end = offset + length;
        let node = self.nodes.get_mut(&ino).expect("checked");
        let Body::File(f) = &mut node.body else {
            unreachable!("checked to be a file")
        };
        let (s, e) = Self::alloc_range(f, offset, end, how);
        if s < e {
            for page in s / PAGE..=(e - 1) / PAGE {
                match Self::page_op(f, page, s, e, how) {
                    PageOp::Nothing => {}
                    PageOp::Materialize => {
                        let view = Self::page_view(f, page);
                        f.pages.insert(page, view);
                    }
                    PageOp::Zero(a, b) => {
                        if !f.pages.contains_key(&page) {
                            let view = Self::page_view(f, page);
                            f.pages.insert(page, view);
                        }
                        f.pages.get_mut(&page).expect("inserted")[a..b].fill(0);
                    }
                    PageOp::Drop => {
                        f.pages.remove(&page);
                    }
                }
            }
        }
        if !how.keep_size() {
            f.size = f.size.max(end);
        }
        advance(&mut node.mtime, now);
        advance(&mut node.ctime, now);
        self.overlay_bytes = self.overlay_bytes + added - freed;
        Ok(())
    }
}

/// Check a `{"entries": [...]}` description on its own, against an empty tree: what an answer
/// is held to before it is committed. Used to check an action's shape and by the fuzz target.
pub fn check_description(answer: &Json) -> Result<usize> {
    Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES).describe(ROOT, answer)
}
