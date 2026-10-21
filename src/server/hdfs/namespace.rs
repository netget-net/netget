//! The HDFS namespace: `src/server/described_tree.rs` (the tree FUSE serves) plus what HDFS adds
//! to it — owner and group names, replication, block size and generation stamp per file, files
//! open for writing with the blocks allocated to them, and block bytes a DataNode has received
//! but the NameNode has not yet committed. Everything here is a pure function of that state:
//! asking the model, and holding the lock across the question, is the NameNode's business.
//!
//! Blocks are not stored. A file's blocks are its content cut at its block size; block `i` of
//! the inode `ino` has the id `ino << 16 | i` and the file's generation stamp, and the DataNode
//! reads its bytes from the tree when asked. Written blocks are staged here as they arrive and
//! go into the tree's overlay, at the file's offsets, only when `complete` is allowed.
use super::proto::common::TokenProto;
use super::proto::hdfs::{
    datanode_info_proto::AdminState, hdfs_file_status_proto::FileType, ContentSummaryProto,
    DatanodeIdProto, DatanodeInfoProto, DirectoryListingProto, ExtendedBlockProto,
    FsPermissionProto, HdfsFileStatusProto, LocatedBlockProto, LocatedBlocksProto, QuotaUsageProto,
    StorageTypeProto,
};
use super::rpc::class;
use crate::server::described_tree::{self as tree, Changes, Kind, Outcome, Stop, Tree, ROOT};
use crate::utils::clock::{SystemTime, UNIX_EPOCH};
use anyhow::{bail, ensure, Context};
use serde_json::Value as Json;
use std::collections::HashMap;
use std::time::Duration;

/// HDFS numbers inodes from 16385 (the root); file ids here are the tree's inode plus this.
pub const INODE_ID_OFFSET: u64 = 16384;
/// A path's length (HDFS's `dfs.namenode.fs-limits.max-path-length` is 8000 too... in
/// characters; this counts bytes).
pub const MAX_PATH_BYTES: usize = 8000;
/// Entries one getListing page holds (HDFS's `dfs.ls.limit`).
pub const LISTING_LIMIT: usize = 1000;
/// The block sizes a file may have: a multiple of the 512-byte checksum chunk.
pub const MIN_BLOCK_SIZE: u64 = 64 * 1024;
pub const MAX_BLOCK_SIZE: u64 = tree::MAX_FILE_SIZE;
pub const DEFAULT_BLOCK_SIZE: u64 = 128 << 20;
/// Blocks one file may have.
pub const MAX_BLOCKS_PER_FILE: u64 = 16_384;
/// HDFS's own ceiling (`dfs.replication.max`).
pub const MAX_REPLICATION: u32 = 512;
/// Files open for writing at once.
pub const MAX_OPEN_FILES: usize = 256;
/// Owner and group names.
pub const MAX_PRINCIPAL_BYTES: usize = 256;
/// The generation stamp of every block of a file the model described.
pub const DESCRIBED_GENERATION: u64 = 1000;
/// The storage id this DataNode reports.
pub const STORAGE_ID: &str = "DS-netget-0001";

/// A refusal as a Hadoop client sees it: the exception class and its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thrown {
    pub class: &'static str,
    pub message: String,
}

impl Thrown {
    pub fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

/// Why an operation stopped: a directory to describe first, or a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Halt {
    Describe(u64),
    Thrown(Thrown),
}

pub type Step<T> = Result<T, Halt>;

fn thrown<T>(class: &'static str, message: impl Into<String>) -> Step<T> {
    Err(Halt::Thrown(Thrown::new(class, message)))
}

/// The exception for an errno the tree answered, about `path`.
pub fn thrown_for(code: i32, path: &str) -> Thrown {
    match code {
        libc::ENOENT => Thrown::new(
            class::FILE_NOT_FOUND,
            format!("File does not exist: {path}"),
        ),
        libc::ENOTDIR => Thrown::new(
            class::PARENT_NOT_DIRECTORY,
            format!("Parent path is not a directory: {path}"),
        ),
        libc::EEXIST => Thrown::new(class::ALREADY_EXISTS, format!("{path} already exists")),
        libc::ENOTEMPTY => Thrown::new(
            class::NOT_EMPTY,
            format!("`{path} is non empty': Directory is not empty"),
        ),
        libc::EISDIR => Thrown::new(class::FILE_NOT_FOUND, format!("Path is not a file: {path}")),
        libc::ENAMETOOLONG => Thrown::new(
            class::INVALID_PATH,
            format!("Invalid path name {path}: too deep or a name too long"),
        ),
        libc::ENOSPC => Thrown::new(
            class::NS_QUOTA,
            format!("The namespace is full: cannot add {path}"),
        ),
        libc::EFBIG => Thrown::new(class::IO, format!("{path}: the file would be too large")),
        libc::EINVAL => Thrown::new(class::INVALID_PATH, format!("Invalid path name {path}")),
        libc::EACCES | libc::EPERM => {
            Thrown::new(class::ACCESS_CONTROL, format!("Permission denied: {path}"))
        }
        _ => Thrown::new(
            class::IO,
            format!(
                "{path}: {}",
                crate::server::described_tree::errno_name(code)
            ),
        ),
    }
}

/// The errno a refused directory description is kept as, for an exception the model named.
pub fn errno_for_class(class_name: &str) -> i32 {
    match class_name {
        class::ACCESS_CONTROL => libc::EACCES,
        class::FILE_NOT_FOUND => libc::ENOENT,
        class::INVALID_PATH => libc::EINVAL,
        _ => libc::EIO,
    }
}

/// A tree outcome as a step, refusals naming `path`.
pub fn step<T>(o: Outcome<T>, path: &str) -> Step<T> {
    match o {
        Ok(v) => Ok(v),
        Err(Stop::Describe(d)) => Err(Halt::Describe(d)),
        Err(Stop::Errno(c)) => Err(Halt::Thrown(thrown_for(c, path))),
    }
}

/// A path's components, checked as HDFS checks a path name.
pub fn components(path: &str) -> Result<Vec<&str>, Thrown> {
    let invalid = |why: &str| {
        Thrown::new(
            class::INVALID_PATH,
            format!(
                "Invalid path name {}: {why}",
                crate::utils::sanitize::token(path, 256)
            ),
        )
    };
    if !path.starts_with('/') {
        return Err(invalid("not an absolute path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(invalid("longer than 8000 bytes"));
    }
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.len() > tree::MAX_TREE_DEPTH + 1 {
        return Err(invalid("deeper than the namespace allows"));
    }
    for c in &comps {
        if *c == "." || *c == ".." || c.contains(':') || c.contains('\0') {
            return Err(invalid("a component is ., .. or contains ':'"));
        }
        if c.len() > tree::MAX_NAME_BYTES {
            return Err(Thrown::new(
                "org.apache.hadoop.hdfs.protocol.FSLimitException$PathComponentTooLongException",
                format!(
                    "The maximum path component name limit of {} is exceeded",
                    tree::MAX_NAME_BYTES
                ),
            ));
        }
    }
    Ok(comps)
}

/// The canonical form of a path's components.
pub fn joined(comps: &[&str]) -> String {
    format!("/{}", comps.join("/"))
}

/// Settings fixed when the server starts.
#[derive(Clone, Debug)]
pub struct Settings {
    pub block_size: u64,
    pub replication: u16,
    pub owner: String,
    pub group: String,
    pub max_overlay: u64,
}

#[derive(Clone, Debug)]
struct Meta {
    owner: String,
    group: String,
    replication: u16,
    block_size: u64,
    generation: u64,
}

#[derive(Debug)]
struct OpenFile {
    client: String,
    blocks: Vec<u64>,
}

/// The block id of block `index` of inode `ino`.
pub fn block_id(ino: u64, index: u64) -> u64 {
    (ino << 16) | index
}

/// The inode and index a block id names.
pub fn split_block_id(id: u64) -> (u64, u64) {
    (id >> 16, id & 0xFFFF)
}

/// A file a DataNode may write a block of, as the NameNode allocated it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritableBlock {
    pub ino: u64,
    pub index: u64,
    pub block_size: u64,
}

/// A block a DataNode may read: its file, its first byte in the file and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadableBlock {
    pub ino: u64,
    pub file_offset: u64,
    pub len: u64,
}

pub enum MkdirsPlan {
    Exists,
    Create { parent: u64, names: Vec<String> },
}

pub struct CreatePlan {
    pub parent: u64,
    pub missing: Vec<String>,
    pub name: String,
    pub replaces: Option<u64>,
}

pub struct DeletePlan {
    pub parent: u64,
    pub name: String,
    pub kind: Kind,
    pub ino: u64,
}

pub struct RenamePlan {
    pub src_parent: u64,
    pub src_name: String,
    pub dst_parent: u64,
    pub dst_name: String,
    pub dst_path: String,
    pub replaces: bool,
    pub kind: Kind,
}

pub struct CompletePlan {
    pub ino: u64,
    pub length: u64,
    pub blocks: usize,
}

pub struct Namespace {
    pub tree: Tree,
    pub settings: Settings,
    pub pool_id: String,
    meta: HashMap<u64, Meta>,
    open: HashMap<u64, OpenFile>,
    received: HashMap<u64, Vec<u8>>,
    /// Bytes held by received blocks and blocks being received.
    reserved: u64,
    next_generation: u64,
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn principal(v: &Json, key: &str) -> anyhow::Result<Option<String>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => {
            ensure!(
                !s.is_empty()
                    && s.len() <= MAX_PRINCIPAL_BYTES
                    && !crate::utils::sanitize::has_controls(s)
                    && !s.contains([':', '/']),
                "{key} is a name of 1 to {MAX_PRINCIPAL_BYTES} bytes without ':', '/' or controls"
            );
            Ok(Some(s.clone()))
        }
        Some(_) => bail!("{key} is a name"),
    }
}

fn number(v: &Json, key: &str) -> anyhow::Result<Option<u64>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(n) => {
            Ok(Some(n.as_u64().with_context(|| {
                format!("{key} is a non-negative number")
            })?))
        }
    }
}

pub fn check_block_size(bs: u64) -> anyhow::Result<u64> {
    ensure!(
        (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) && bs.is_multiple_of(512),
        "a block size is a multiple of 512 from {MIN_BLOCK_SIZE} to {MAX_BLOCK_SIZE} bytes"
    );
    Ok(bs)
}

pub fn check_replication(r: u64) -> anyhow::Result<u16> {
    ensure!(
        (1..=MAX_REPLICATION as u64).contains(&r),
        "replication is 1 to {MAX_REPLICATION}"
    );
    Ok(r as u16)
}

/// The size a described file entry will have (what `described_tree` derives).
fn described_size(e: &Json) -> u64 {
    if let Some(s) = e.get("size").and_then(Json::as_u64) {
        return s;
    }
    if let Some(t) = e.get("text").and_then(Json::as_str) {
        return t.len() as u64;
    }
    if let Some(h) = e.get("hex").and_then(Json::as_str) {
        return (h.len() / 2) as u64;
    }
    0
}

/// Check the fields HDFS adds to a description — owner, group, replication, block_size —
/// before anything is committed. Iterative over nested entries; the tree's own walk bounds the
/// rest.
pub fn check_hdfs_fields(answer: &Json, default_block_size: u64) -> anyhow::Result<()> {
    let Some(top) = answer.get("entries").and_then(Json::as_array) else {
        bail!("entries is an array");
    };
    let mut work = vec![top];
    let mut seen = 0usize;
    while let Some(entries) = work.pop() {
        for e in entries {
            seen += 1;
            ensure!(
                seen <= tree::MAX_ENTRIES_PER_ANSWER,
                "one answer describes at most {} entries",
                tree::MAX_ENTRIES_PER_ANSWER
            );
            principal(e, "owner")?;
            principal(e, "group")?;
            if let Some(r) = number(e, "replication")? {
                check_replication(r)?;
            }
            let bs = match number(e, "block_size")? {
                Some(b) => check_block_size(b)?,
                None => default_block_size,
            };
            if e.get("kind").and_then(Json::as_str) == Some("file") {
                let blocks = described_size(e).div_ceil(bs);
                ensure!(
                    blocks <= MAX_BLOCKS_PER_FILE,
                    "a file has at most {MAX_BLOCKS_PER_FILE} blocks (size / block_size)"
                );
            }
            if let Some(nested) = e.get("entries").and_then(Json::as_array) {
                work.push(nested);
            }
        }
    }
    Ok(())
}

/// Check a whole `hdfs_directory` answer against an empty namespace: the tree's rules and
/// HDFS's. Used by the action executor and the fuzz target.
pub fn check_description(answer: &Json) -> anyhow::Result<usize> {
    check_hdfs_fields(answer, DEFAULT_BLOCK_SIZE)?;
    tree::check_description(answer)
}

impl Namespace {
    pub fn new(settings: Settings, pool_id: String) -> Self {
        let mut ns = Namespace {
            tree: Tree::new(0o755, 0, 0, settings.max_overlay),
            settings,
            pool_id,
            meta: HashMap::new(),
            open: HashMap::new(),
            received: HashMap::new(),
            reserved: 0,
            next_generation: DESCRIBED_GENERATION + 1,
        };
        let m = ns.default_meta();
        ns.meta.insert(ROOT, m);
        ns
    }

    fn default_meta(&self) -> Meta {
        Meta {
            owner: self.settings.owner.clone(),
            group: self.settings.group.clone(),
            replication: self.settings.replication,
            block_size: self.settings.block_size,
            generation: DESCRIBED_GENERATION,
        }
    }

    fn meta(&self, ino: u64) -> Meta {
        self.meta
            .get(&ino)
            .cloned()
            .unwrap_or_else(|| self.default_meta())
    }

    /// The owner and group of an inode.
    pub fn owner_of(&self, ino: u64) -> (String, String) {
        let m = self.meta(ino);
        (m.owner, m.group)
    }

    pub fn block_size_of(&self, ino: u64) -> u64 {
        self.meta(ino).block_size
    }

    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    pub fn open_files(&self) -> usize {
        self.open.len()
    }

    pub fn file_id(ino: u64) -> u64 {
        ino + INODE_ID_OFFSET
    }

    /// Commit a model's description of a pending directory, with HDFS's fields. A refused
    /// answer changes nothing.
    pub fn describe(&mut self, dir: u64, answer: &Json) -> anyhow::Result<usize> {
        check_hdfs_fields(answer, self.settings.block_size)?;
        let n = self.tree.describe(dir, answer)?;
        // The tree accepted it; record what HDFS adds, entry by entry.
        let Some(top) = answer.get("entries").and_then(Json::as_array) else {
            return Ok(n);
        };
        let mut work = vec![(dir, top)];
        while let Some((parent, entries)) = work.pop() {
            for e in entries {
                let Some(name) = e.get("name").and_then(Json::as_str) else {
                    continue;
                };
                let Ok(a) = self.tree.lookup(parent, name) else {
                    continue;
                };
                let mut m = self.default_meta();
                if let Ok(Some(o)) = principal(e, "owner") {
                    m.owner = o;
                }
                if let Ok(Some(g)) = principal(e, "group") {
                    m.group = g;
                }
                if let Ok(Some(r)) = number(e, "replication") {
                    m.replication = r as u16;
                }
                if let Ok(Some(b)) = number(e, "block_size") {
                    m.block_size = b;
                }
                self.meta.insert(a.ino, m);
                if let Some(nested) = e.get("entries").and_then(Json::as_array) {
                    work.push((a.ino, nested));
                }
            }
        }
        Ok(n)
    }

    /// The inode a path names, or the directory to describe on the way.
    pub fn lookup(&self, comps: &[&str]) -> Step<u64> {
        let mut at = ROOT;
        for (i, name) in comps.iter().enumerate() {
            let path = joined(&comps[..=i]);
            at = step(self.tree.lookup(at, name), &path)?.ino;
        }
        Ok(at)
    }

    /// Like [`lookup`], but a missing entry is `None` rather than a refusal.
    pub fn find(&self, comps: &[&str]) -> Step<Option<u64>> {
        match self.lookup(comps) {
            Ok(i) => Ok(Some(i)),
            Err(Halt::Thrown(t)) if t.class == class::FILE_NOT_FOUND => Ok(None),
            Err(h) => Err(h),
        }
    }

    pub fn kind(&self, ino: u64) -> Option<Kind> {
        self.tree.kind(ino)
    }

    /// A file's status as a Hadoop client reads it, with `name` as its path field.
    pub fn status(&self, ino: u64, name: &[u8]) -> Option<HdfsFileStatusProto> {
        let a = self.tree.attr(ino)?;
        let m = self.meta(ino);
        let (file_type, length, replication, block_size) = match a.kind {
            Kind::Dir => (FileType::IsDir, 0, 0, 0),
            Kind::Symlink => (FileType::IsSymlink, a.size, 0, 0),
            _ => (FileType::IsFile, a.size, m.replication as u32, m.block_size),
        };
        let children = match a.kind {
            Kind::Dir => self.tree.list(ino).map(|l| l.len() as i32).unwrap_or(0),
            _ => -1,
        };
        Some(HdfsFileStatusProto {
            file_type: file_type as i32,
            path: name.to_vec(),
            length,
            permission: FsPermissionProto {
                perm: a.perm as u32,
            },
            owner: m.owner,
            group: m.group,
            modification_time: millis(a.mtime),
            access_time: millis(a.atime),
            symlink: match a.kind {
                Kind::Symlink => self.tree.readlink(ino).ok().map(String::into_bytes),
                _ => None,
            },
            block_replication: Some(replication),
            blocksize: Some(block_size),
            locations: None,
            file_id: Some(Self::file_id(ino)),
            children_num: Some(children),
            storage_policy: Some(0),
            flags: Some(0),
            ..Default::default()
        })
    }

    /// Whether a file is open for writing.
    pub fn is_open(&self, ino: u64) -> bool {
        self.open.contains_key(&ino)
    }

    /// The blocks of a file covering `[offset, offset + length)`, located at `dn`.
    pub fn located_blocks(
        &self,
        ino: u64,
        offset: u64,
        length: u64,
        dn: &DatanodeInfoProto,
    ) -> LocatedBlocksProto {
        let size = self.tree.size(ino).unwrap_or(0);
        let m = self.meta(ino);
        if self.open.contains_key(&ino) {
            return LocatedBlocksProto {
                file_length: 0,
                blocks: vec![],
                under_construction: true,
                last_block: None,
                is_last_block_complete: false,
                ..Default::default()
            };
        }
        let bs = m.block_size.max(1);
        let count = size.div_ceil(bs);
        let located = |i: u64| self.located_block(ino, i, &m, size, dn);
        let end = offset.saturating_add(length).min(size);
        let blocks = if offset >= size {
            vec![]
        } else {
            (offset / bs..=(end.max(offset + 1) - 1) / bs)
                .filter(|i| *i < count)
                .map(located)
                .collect()
        };
        LocatedBlocksProto {
            file_length: size,
            blocks,
            under_construction: false,
            last_block: (count > 0).then(|| located(count - 1)),
            is_last_block_complete: true,
            ..Default::default()
        }
    }

    fn located_block(
        &self,
        ino: u64,
        index: u64,
        m: &Meta,
        size: u64,
        dn: &DatanodeInfoProto,
    ) -> LocatedBlockProto {
        let bs = m.block_size.max(1);
        let len = (size - (index * bs).min(size)).min(bs);
        self.locate(block_id(ino, index), m.generation, index * bs, len, dn)
    }

    fn locate(
        &self,
        id: u64,
        generation: u64,
        offset: u64,
        len: u64,
        dn: &DatanodeInfoProto,
    ) -> LocatedBlockProto {
        LocatedBlockProto {
            b: ExtendedBlockProto {
                pool_id: self.pool_id.clone(),
                block_id: id,
                generation_stamp: generation,
                num_bytes: Some(len),
            },
            offset,
            locs: vec![dn.clone()],
            corrupt: false,
            block_token: TokenProto::default(),
            is_cached: vec![false],
            storage_types: vec![StorageTypeProto::Disk as i32],
            storage_i_ds: vec![STORAGE_ID.into()],
            ..Default::default()
        }
    }

    /// One page of a directory's listing, after `start_after`.
    pub fn listing(
        &self,
        ino: u64,
        path: &str,
        start_after: &[u8],
        need_location: bool,
        dn: &DatanodeInfoProto,
    ) -> Step<DirectoryListingProto> {
        if self.tree.kind(ino) != Some(Kind::Dir) {
            let mut s = self.status(ino, b"").expect("live");
            if need_location && s.file_type == FileType::IsFile as i32 {
                s.locations = Some(self.located_blocks(ino, 0, u64::MAX, dn));
            }
            return Ok(DirectoryListingProto {
                partial_listing: vec![s],
                remaining_entries: 0,
            });
        }
        let entries = step(self.tree.list(ino), path)?;
        let after: Vec<_> = entries
            .into_iter()
            .filter(|(_, _, name)| name.as_bytes() > start_after)
            .collect();
        let page: Vec<HdfsFileStatusProto> = after
            .iter()
            .take(LISTING_LIMIT)
            .filter_map(|(child, kind, name)| {
                let mut s = self.status(*child, name.as_bytes())?;
                if need_location && *kind == Kind::File {
                    s.locations = Some(self.located_blocks(*child, 0, u64::MAX, dn));
                }
                Some(s)
            })
            .collect();
        Ok(DirectoryListingProto {
            remaining_entries: after.len().saturating_sub(page.len()) as u32,
            partial_listing: page,
        })
    }

    /// Lengths, counts and space under `ino`; a directory below it may need describing first.
    pub fn content_summary(&self, ino: u64, path: &str) -> Step<ContentSummaryProto> {
        let mut length = 0u64;
        let mut files = 0u64;
        let mut dirs = 0u64;
        let mut space = 0u64;
        let mut work = vec![ino];
        while let Some(at) = work.pop() {
            match self.tree.kind(at) {
                Some(Kind::Dir) => {
                    dirs += 1;
                    for (child, _, _) in step(self.tree.list(at), path)? {
                        work.push(child);
                    }
                }
                Some(Kind::File) => {
                    let size = self.tree.size(at).unwrap_or(0);
                    files += 1;
                    length += size;
                    space += size * self.meta(at).replication as u64;
                }
                Some(_) => files += 1,
                None => {}
            }
        }
        Ok(ContentSummaryProto {
            length,
            file_count: files,
            directory_count: dirs,
            quota: u64::MAX,
            space_consumed: space,
            space_quota: u64::MAX,
            ..Default::default()
        })
    }

    pub fn quota_usage(&self, ino: u64, path: &str) -> Step<QuotaUsageProto> {
        let s = self.content_summary(ino, path)?;
        Ok(QuotaUsageProto {
            file_and_directory_count: s.file_count + s.directory_count,
            quota: u64::MAX,
            space_consumed: s.space_consumed,
            space_quota: u64::MAX,
            type_quota_infos: None,
        })
    }

    /// Whether `user` may do `mode` (FsAction bits: 4 read, 2 write, 1 execute) on `ino`,
    /// from the mode bits: the owner's when `user` owns it, the group's when the group is
    /// named after `user`, everyone's otherwise. The configured owner is the superuser.
    pub fn may(&self, ino: u64, user: &str, mode: u32) -> bool {
        let Some(a) = self.tree.attr(ino) else {
            return false;
        };
        let m = self.meta(ino);
        if user == self.settings.owner {
            return true;
        }
        let bits = if user == m.owner {
            (a.perm >> 6) & 7
        } else if user == m.group {
            (a.perm >> 3) & 7
        } else {
            a.perm & 7
        } as u32;
        bits & mode == mode
    }

    /// Walk to a directory that must exist (or, with `create_parent`, the deepest existing
    /// one and the names missing below it).
    fn parent_of(&self, comps: &[&str], create_parent: bool) -> Step<(u64, Vec<String>)> {
        let mut at = ROOT;
        for (i, name) in comps.iter().enumerate() {
            let path = joined(&comps[..=i]);
            match self.tree.lookup(at, name) {
                Ok(a) if a.kind == Kind::Dir => at = a.ino,
                Ok(_) => {
                    return thrown(
                        class::PARENT_NOT_DIRECTORY,
                        format!("Parent path is not a directory: {path}"),
                    )
                }
                Err(Stop::Describe(d)) => return Err(Halt::Describe(d)),
                Err(Stop::Errno(libc::ENOENT)) => {
                    if !create_parent {
                        return thrown(
                            class::FILE_NOT_FOUND,
                            format!("Parent directory doesn't exist: {path}"),
                        );
                    }
                    step(self.tree.check_new_entry(at, name), &path)?;
                    let missing: Vec<String> = comps[i..].iter().map(|s| s.to_string()).collect();
                    if self.tree.depth(at) + missing.len() > tree::MAX_TREE_DEPTH {
                        return Err(Halt::Thrown(thrown_for(libc::ENAMETOOLONG, &joined(comps))));
                    }
                    return Ok((at, missing));
                }
                Err(Stop::Errno(c)) => return Err(Halt::Thrown(thrown_for(c, &path))),
            }
        }
        Ok((at, vec![]))
    }

    pub fn plan_mkdirs(&self, comps: &[&str], create_parent: bool) -> Step<MkdirsPlan> {
        if comps.is_empty() {
            return Ok(MkdirsPlan::Exists);
        }
        let path = joined(comps);
        let (parent, missing) = self.parent_of(&comps[..comps.len() - 1], create_parent)?;
        let last = comps[comps.len() - 1];
        if missing.is_empty() {
            match self.tree.lookup(parent, last) {
                Ok(a) if a.kind == Kind::Dir => return Ok(MkdirsPlan::Exists),
                Ok(_) => {
                    return thrown(
                        class::ALREADY_EXISTS,
                        format!("Path is not a directory: {path}"),
                    )
                }
                Err(Stop::Errno(libc::ENOENT)) => {
                    step(self.tree.check_new_entry(parent, last), &path)?;
                }
                Err(e) => return step(Err(e), &path),
            }
        }
        let mut names = missing;
        names.push(last.to_string());
        Ok(MkdirsPlan::Create { parent, names })
    }

    fn make_dirs(&mut self, parent: u64, names: &[String], perm: u16, owner: &str) -> Step<u64> {
        let mut at = parent;
        for name in names {
            let path = self.tree.child_path(at, name);
            at = step(self.tree.mkdir(at, name, perm, 0, 0), &path)?.ino;
            let mut m = self.default_meta();
            m.owner = owner.to_string();
            self.meta.insert(at, m);
        }
        Ok(at)
    }

    pub fn apply_mkdirs(&mut self, plan: &MkdirsPlan, perm: u16, owner: &str) -> Step<()> {
        if let MkdirsPlan::Create { parent, names } = plan {
            self.make_dirs(*parent, names, perm, owner)?;
        }
        Ok(())
    }

    pub fn plan_create(
        &self,
        comps: &[&str],
        overwrite: bool,
        create_parent: bool,
        client: &str,
    ) -> Step<CreatePlan> {
        let path = joined(comps);
        let Some((last, dirs)) = comps.split_last() else {
            return thrown(class::ALREADY_EXISTS, "/ already exists as a directory");
        };
        let (parent, missing) = self.parent_of(dirs, create_parent)?;
        let mut replaces = None;
        if missing.is_empty() {
            match self.tree.lookup(parent, last) {
                Ok(a) if a.kind == Kind::Dir => {
                    return thrown(
                        class::ALREADY_EXISTS,
                        format!("{path} already exists as a directory"),
                    )
                }
                Ok(a) if a.kind == Kind::File => {
                    if let Some(o) = self.open.get(&a.ino) {
                        if o.client != client || !overwrite {
                            return thrown(
                                class::ALREADY_BEING_CREATED,
                                format!(
                                    "Failed to CREATE_FILE {path} for {client}: {path} is being created by {}",
                                    o.client
                                ),
                            );
                        }
                    }
                    if !overwrite {
                        return thrown(
                            class::ALREADY_EXISTS,
                            format!("{path} for client {client} already exists"),
                        );
                    }
                    replaces = Some(a.ino);
                }
                Ok(_) => return thrown(class::ALREADY_EXISTS, format!("{path} already exists")),
                Err(Stop::Errno(libc::ENOENT)) => {
                    step(self.tree.check_new_entry(parent, last), &path)?;
                }
                Err(e) => return step(Err(e), &path),
            }
        }
        if self.open.len() >= MAX_OPEN_FILES && replaces.is_none_or(|i| !self.open.contains_key(&i))
        {
            return thrown(
                class::IO,
                format!("{MAX_OPEN_FILES} files are already open for writing"),
            );
        }
        Ok(CreatePlan {
            parent,
            missing,
            name: last.to_string(),
            replaces,
        })
    }

    /// Forget what HDFS keeps about removed inodes, and the bytes their blocks held.
    fn forget(&mut self, inos: &[u64]) {
        for ino in inos {
            self.meta.remove(ino);
            if let Some(o) = self.open.remove(ino) {
                for b in o.blocks {
                    if let Some(d) = self.received.remove(&b) {
                        self.reserved = self.reserved.saturating_sub(d.len() as u64);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_create(
        &mut self,
        plan: &CreatePlan,
        perm: u16,
        owner: &str,
        replication: u16,
        block_size: u64,
        client: &str,
    ) -> Step<u64> {
        let parent = self.make_dirs(plan.parent, &plan.missing, 0o755, owner)?;
        let path = self.tree.child_path(parent, &plan.name);
        if let Some(old) = plan.replaces {
            step(self.tree.unlink(parent, &plan.name), &path)?;
            self.forget(&[old]);
        }
        let a = step(self.tree.create(parent, &plan.name, perm, 0, 0), &path)?;
        let generation = self.next_generation;
        self.next_generation += 1;
        self.meta.insert(
            a.ino,
            Meta {
                owner: owner.to_string(),
                group: self.settings.group.clone(),
                replication,
                block_size,
                generation,
            },
        );
        self.open.insert(
            a.ino,
            OpenFile {
                client: client.to_string(),
                blocks: vec![],
            },
        );
        Ok(a.ino)
    }

    /// The file a write call names: by file id when the client sent one, else by path.
    pub fn file_for(&self, comps: &[&str], file_id: Option<u64>) -> Step<u64> {
        let path = joined(comps);
        let ino = match file_id {
            Some(id) if id > INODE_ID_OFFSET => {
                let ino = id - INODE_ID_OFFSET;
                if self.tree.kind(ino).is_none() {
                    return thrown(
                        class::FILE_NOT_FOUND,
                        format!("File does not exist: {path} (inode {id})"),
                    );
                }
                ino
            }
            _ => self.lookup(comps)?,
        };
        if self.tree.kind(ino) != Some(Kind::File) {
            return thrown(class::FILE_NOT_FOUND, format!("Path is not a file: {path}"));
        }
        Ok(ino)
    }

    fn lease(&self, ino: u64, client: &str, path: &str) -> Step<&OpenFile> {
        match self.open.get(&ino) {
            None => thrown(
                class::LEASE_EXPIRED,
                format!("No lease on {path}: File is not open for writing"),
            ),
            Some(o) if o.client != client => thrown(
                class::LEASE_EXPIRED,
                format!(
                    "No lease on {path}: {client} does not hold the lease (holder: {})",
                    o.client
                ),
            ),
            Some(o) => Ok(o),
        }
    }

    /// Allocate the next block of an open file.
    pub fn add_block(
        &mut self,
        ino: u64,
        path: &str,
        client: &str,
        previous: Option<&ExtendedBlockProto>,
        dn: &DatanodeInfoProto,
    ) -> Step<LocatedBlockProto> {
        let m = self.meta(ino);
        let o = self.lease(ino, client, path)?;
        match (o.blocks.last(), previous) {
            (None, None) => {}
            (None, Some(p)) => {
                return thrown(
                    class::IO,
                    format!(
                        "{path} has no block yet, but the request names block {}",
                        p.block_id
                    ),
                )
            }
            (Some(last), p) => {
                let p_id = p.map(|p| p.block_id);
                if p_id != Some(*last) {
                    return thrown(
                        class::IO,
                        format!("{path}: the previous block is {last}, not {p_id:?}"),
                    );
                }
                let got = self.received.get(last).map(|d| d.len() as u64);
                if got != Some(m.block_size) {
                    return thrown(
                        class::IO,
                        format!(
                            "{path}: block {last} is not complete ({} of {} bytes received)",
                            got.unwrap_or(0),
                            m.block_size
                        ),
                    );
                }
            }
        }
        let index = o.blocks.len() as u64;
        if index + 1 > MAX_BLOCKS_PER_FILE || index * m.block_size >= tree::MAX_FILE_SIZE {
            return thrown(
                class::QUOTA,
                format!(
                    "{path}: a file holds at most {MAX_BLOCKS_PER_FILE} blocks and {} bytes",
                    tree::MAX_FILE_SIZE
                ),
            );
        }
        let id = block_id(ino, index);
        self.open.get_mut(&ino).expect("leased").blocks.push(id);
        Ok(self.locate(id, m.generation, index * m.block_size, 0, dn))
    }

    /// A block of a file `client` holds open, located again with its generation stamp
    /// unchanged (updateBlockForPipeline: there is one DataNode and no recovery to re-stamp).
    pub fn block_for_pipeline(
        &self,
        b: &ExtendedBlockProto,
        client: &str,
        dn: &DatanodeInfoProto,
    ) -> Result<LocatedBlockProto, Thrown> {
        let (ino, index) = split_block_id(b.block_id);
        let path = self.tree.path(ino);
        let o = match self.lease(ino, client, &path) {
            Ok(o) => o,
            Err(Halt::Thrown(t)) => return Err(t),
            Err(Halt::Describe(_)) => unreachable!("a lease check describes nothing"),
        };
        if b.pool_id != self.pool_id || !o.blocks.contains(&b.block_id) {
            return Err(Thrown::new(
                class::IO,
                format!(
                    "Block {} is not a block of {path} being written",
                    b.block_id
                ),
            ));
        }
        let m = self.meta(ino);
        if b.generation_stamp != m.generation {
            return Err(Thrown::new(
                class::IO,
                format!(
                    "Block {} has generation stamp {}, not {}",
                    b.block_id, m.generation, b.generation_stamp
                ),
            ));
        }
        let len = b
            .num_bytes
            .unwrap_or_else(|| self.received.get(&b.block_id).map_or(0, |d| d.len() as u64));
        Ok(self.locate(b.block_id, m.generation, index * m.block_size, len, dn))
    }

    /// Give back the last block allocated to an open file.
    pub fn abandon_block(&mut self, ino: u64, path: &str, client: &str, id: u64) -> Step<()> {
        let last = self.lease(ino, client, path)?.blocks.last().copied();
        if last == Some(id) {
            self.open.get_mut(&ino).expect("leased").blocks.pop();
            if let Some(d) = self.received.remove(&id) {
                self.reserved = self.reserved.saturating_sub(d.len() as u64);
            }
        }
        Ok(())
    }

    /// Whether `complete` may go ahead: every block received, the last one as long as the
    /// client says and the others full.
    pub fn plan_complete(
        &self,
        ino: u64,
        path: &str,
        client: &str,
        last: Option<&ExtendedBlockProto>,
    ) -> Step<CompletePlan> {
        let m = self.meta(ino);
        let o = self.lease(ino, client, path)?;
        match (o.blocks.last(), last) {
            (None, _) => {}
            (Some(l), Some(b)) if b.block_id == *l => {}
            (Some(l), b) => {
                return thrown(
                    class::IO,
                    format!(
                        "{path}: the last block is {l}, not {:?}",
                        b.map(|b| b.block_id)
                    ),
                )
            }
        }
        let mut length = 0u64;
        for (i, id) in o.blocks.iter().enumerate() {
            let Some(d) = self.received.get(id) else {
                return thrown(
                    class::IO,
                    format!("{path}: block {id} has not been written to the DataNode"),
                );
            };
            let is_last = i + 1 == o.blocks.len();
            if !is_last && d.len() as u64 != m.block_size {
                return thrown(class::IO, format!("{path}: block {id} is short"));
            }
            if is_last {
                let said = last.and_then(|b| b.num_bytes).unwrap_or(d.len() as u64);
                if said != d.len() as u64 {
                    return thrown(
                        class::IO,
                        format!(
                            "{path}: the client says block {id} holds {said} bytes; the DataNode received {}",
                            d.len()
                        ),
                    );
                }
            }
            length += d.len() as u64;
        }
        Ok(CompletePlan {
            ino,
            length,
            blocks: o.blocks.len(),
        })
    }

    /// The first `max` bytes a completion would commit.
    pub fn staged_preview(&self, ino: u64, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(o) = self.open.get(&ino) {
            for id in &o.blocks {
                if let Some(d) = self.received.get(id) {
                    let take = (max - out.len()).min(d.len());
                    out.extend_from_slice(&d[..take]);
                }
                if out.len() >= max {
                    break;
                }
            }
        }
        out
    }

    /// Commit the received blocks into the file and close it.
    pub fn apply_complete(&mut self, ino: u64, path: &str) -> Step<()> {
        let o = self.open.get(&ino).expect("planned");
        let mut data = Vec::new();
        for id in &o.blocks {
            if let Some(d) = self.received.get(id) {
                data.extend_from_slice(d);
            }
        }
        if !data.is_empty() {
            match self.tree.check_write(ino, 0, data.len()) {
                Ok(_) => {}
                Err(Stop::Errno(libc::ENOSPC)) => {
                    self.discard(ino);
                    return thrown(
                        class::QUOTA,
                        format!(
                            "The DiskSpace quota of {path} is exceeded: the overlay holds {} of {} bytes",
                            self.tree.overlay_bytes(),
                            self.tree.max_overlay()
                        ),
                    );
                }
                Err(e) => {
                    self.discard(ino);
                    return step(Err(e), path);
                }
            }
            step(self.tree.write(ino, 0, &data), path)?;
        }
        self.discard(ino);
        Ok(())
    }

    /// Close an open file without committing what was received for it.
    pub fn discard(&mut self, ino: u64) {
        if let Some(o) = self.open.remove(&ino) {
            for b in o.blocks {
                if let Some(d) = self.received.remove(&b) {
                    self.reserved = self.reserved.saturating_sub(d.len() as u64);
                }
            }
        }
    }

    /// Recover a lease: close the file, discarding what was not completed. True when closed.
    pub fn recover_lease(&mut self, ino: u64) -> bool {
        self.discard(ino);
        true
    }

    pub fn plan_delete(&self, comps: &[&str], recursive: bool) -> Step<Option<DeletePlan>> {
        let Some((last, dirs)) = comps.split_last() else {
            return Ok(None);
        };
        let path = joined(comps);
        let Some(ino) = self.find(comps)? else {
            return Ok(None);
        };
        let parent = self.lookup(dirs)?;
        let kind = self.tree.kind(ino).unwrap_or(Kind::File);
        if kind == Kind::Dir && !recursive {
            let entries = step(self.tree.list(ino), &path)?;
            if !entries.is_empty() {
                return thrown(
                    class::NOT_EMPTY,
                    format!("`{path} is non empty': Directory is not empty"),
                );
            }
        }
        Ok(Some(DeletePlan {
            parent,
            name: last.to_string(),
            kind,
            ino,
        }))
    }

    pub fn apply_delete(&mut self, plan: &DeletePlan) -> Step<usize> {
        let path = self.tree.child_path(plan.parent, &plan.name);
        let removed = step(self.tree.remove_subtree(plan.parent, &plan.name), &path)?;
        self.forget(&removed);
        Ok(removed.len())
    }

    /// Plan a rename. `overwrite: None` is the old `rename` (false rather than an exception for
    /// most refusals, and a directory destination receives the source inside it);
    /// `Some(_)` is `rename2`. `Ok(None)`: the old rename answers false.
    pub fn plan_rename(
        &self,
        src: &[&str],
        dst: &[&str],
        overwrite: Option<bool>,
    ) -> Step<Option<RenamePlan>> {
        let old = overwrite.is_none();
        let src_path = joined(src);
        let Some((src_name, src_dirs)) = src.split_last() else {
            return if old {
                Ok(None)
            } else {
                thrown(class::IO, "The source / cannot be renamed")
            };
        };
        let src_ino = match self.find(src)? {
            Some(i) => i,
            None if old => return Ok(None),
            None => {
                return thrown(
                    class::FILE_NOT_FOUND,
                    format!("rename source {src_path} is not found."),
                )
            }
        };
        let src_parent = self.lookup(src_dirs)?;
        let kind = self.tree.kind(src_ino).unwrap_or(Kind::File);
        let mut dst: Vec<&str> = dst.to_vec();
        if old {
            if let Some(d) = self.find(&dst)? {
                if self.tree.kind(d) == Some(Kind::Dir) && d != src_ino {
                    dst.push(src_name);
                } else {
                    return Ok(None);
                }
            }
        }
        let dst_path = joined(&dst);
        let Some((dst_name, dst_dirs)) = dst.split_last() else {
            return if old {
                Ok(None)
            } else {
                thrown(class::IO, "The destination / cannot be replaced")
            };
        };
        let dst_parent = match self.lookup(dst_dirs) {
            Ok(p) if self.tree.kind(p) == Some(Kind::Dir) => p,
            Ok(_) if old => return Ok(None),
            Ok(_) => {
                return thrown(
                    class::PARENT_NOT_DIRECTORY,
                    format!("rename destination parent {} is a file.", joined(dst_dirs)),
                )
            }
            Err(Halt::Thrown(_)) if old => return Ok(None),
            Err(Halt::Thrown(t)) if t.class == class::FILE_NOT_FOUND => {
                return thrown(
                    class::FILE_NOT_FOUND,
                    format!("rename destination parent {} not found.", joined(dst_dirs)),
                )
            }
            Err(h) => return Err(h),
        };
        let existing = match self.tree.lookup(dst_parent, dst_name) {
            Ok(a) => Some(a),
            Err(Stop::Errno(libc::ENOENT)) => None,
            Err(e) => return step(Err(e), &dst_path),
        };
        if let Some(a) = &existing {
            if a.ino == src_ino {
                return if old {
                    Ok(None)
                } else {
                    thrown(
                        class::ALREADY_EXISTS,
                        format!("The source {src_path} and destination {dst_path} are the same"),
                    )
                };
            }
            if old {
                return Ok(None);
            }
            if overwrite != Some(true) {
                return thrown(
                    class::ALREADY_EXISTS,
                    format!("rename destination {dst_path} already exists."),
                );
            }
            if (a.kind == Kind::Dir) != (kind == Kind::Dir) {
                return thrown(
                    class::IO,
                    format!(
                        "Source {src_path} and destination {dst_path} must both be directories"
                    ),
                );
            }
        }
        match self
            .tree
            .check_rename(src_parent, src_name, dst_parent, dst_name, false)
        {
            Ok(_) => {}
            Err(Stop::Errno(_)) if old => return Ok(None),
            Err(Stop::Errno(libc::EINVAL)) => {
                return thrown(
                    class::IO,
                    format!(
                    "Rename destination {dst_path} is a directory or file under source {src_path}"
                ),
                )
            }
            Err(Stop::Errno(libc::ENOTEMPTY)) => {
                return thrown(
                    class::IO,
                    format!("rename destination directory is not empty: {dst_path}"),
                )
            }
            Err(e) => return step(Err(e), &dst_path),
        }
        Ok(Some(RenamePlan {
            src_parent,
            src_name: src_name.to_string(),
            dst_parent,
            dst_name: dst_name.to_string(),
            dst_path,
            replaces: existing.is_some(),
            kind,
        }))
    }

    pub fn apply_rename(&mut self, plan: &RenamePlan) -> Step<()> {
        let replaced = if plan.replaces {
            self.tree
                .lookup(plan.dst_parent, &plan.dst_name)
                .ok()
                .map(|a| a.ino)
        } else {
            None
        };
        step(
            self.tree.rename(
                plan.src_parent,
                &plan.src_name,
                plan.dst_parent,
                &plan.dst_name,
                false,
            ),
            &plan.dst_path,
        )?;
        if let Some(r) = replaced {
            self.forget(&[r]);
        }
        Ok(())
    }

    pub fn set_permission(&mut self, ino: u64, perm: u16, path: &str) -> Step<()> {
        step(
            self.tree.setattr(
                ino,
                &Changes {
                    perm: Some(perm & 0o7777),
                    ..Default::default()
                },
            ),
            path,
        )?;
        Ok(())
    }

    pub fn set_owner(&mut self, ino: u64, owner: Option<&str>, group: Option<&str>) {
        let mut m = self.meta(ino);
        if let Some(o) = owner {
            m.owner = o.to_string();
        }
        if let Some(g) = group {
            m.group = g.to_string();
        }
        self.meta.insert(ino, m);
        let _ = self.tree.setattr(ino, &Changes::default());
    }

    /// Times in milliseconds; `None` leaves one unchanged.
    pub fn set_times(
        &mut self,
        ino: u64,
        mtime: Option<u64>,
        atime: Option<u64>,
        path: &str,
    ) -> Step<()> {
        let at = |ms: u64| UNIX_EPOCH + Duration::from_millis(ms);
        step(
            self.tree.setattr(
                ino,
                &Changes {
                    mtime: mtime.map(at),
                    atime: atime.map(at),
                    ..Default::default()
                },
            ),
            path,
        )?;
        Ok(())
    }

    pub fn set_replication(&mut self, ino: u64, replication: u16) {
        let mut m = self.meta(ino);
        m.replication = replication;
        self.meta.insert(ino, m);
    }

    // ------------------------------------------------------------- the DataNode's view

    /// Whether a block may be written now: allocated, the last of an open file, held by
    /// `client`, and not received yet.
    pub fn writable_block(
        &self,
        b: &ExtendedBlockProto,
        client: &str,
    ) -> Result<WritableBlock, String> {
        if b.pool_id != self.pool_id {
            return Err(format!("block pool {} is not this DataNode's", b.pool_id));
        }
        let (ino, index) = split_block_id(b.block_id);
        let Some(o) = self.open.get(&ino) else {
            return Err(format!(
                "block {} belongs to no file open for writing",
                b.block_id
            ));
        };
        if o.client != client {
            return Err(format!(
                "{client} does not hold the lease on block {}",
                b.block_id
            ));
        }
        if o.blocks.last() != Some(&b.block_id) {
            return Err(format!(
                "block {} is not the file's newest block",
                b.block_id
            ));
        }
        if self.received.contains_key(&b.block_id) {
            return Err(format!("block {} has already been written", b.block_id));
        }
        let m = self.meta(ino);
        if b.generation_stamp != m.generation {
            return Err(format!(
                "block {} has generation stamp {}, not {}",
                b.block_id, m.generation, b.generation_stamp
            ));
        }
        Ok(WritableBlock {
            ino,
            index,
            block_size: m.block_size,
        })
    }

    /// Hold `n` more bytes for a block being received; false when the overlay cannot take them.
    pub fn reserve(&mut self, n: u64) -> bool {
        if self.reserved + n + self.tree.overlay_bytes() > self.tree.max_overlay() {
            return false;
        }
        self.reserved += n;
        true
    }

    pub fn release(&mut self, n: u64) {
        self.reserved = self.reserved.saturating_sub(n);
    }

    /// A block arrived whole; its bytes stay reserved until the file completes or goes.
    pub fn block_received(
        &mut self,
        b: &ExtendedBlockProto,
        client: &str,
        data: Vec<u8>,
    ) -> Result<(), String> {
        if let Err(e) = self.writable_block(b, client) {
            self.release(data.len() as u64);
            return Err(e);
        }
        self.received.insert(b.block_id, data);
        Ok(())
    }

    /// Whether a block may be read: a complete file's block with the right generation stamp.
    pub fn readable_block(&self, b: &ExtendedBlockProto) -> Result<ReadableBlock, String> {
        if b.pool_id != self.pool_id {
            return Err(format!("block pool {} is not this DataNode's", b.pool_id));
        }
        let (ino, index) = split_block_id(b.block_id);
        if self.tree.kind(ino) != Some(Kind::File) {
            return Err(format!("block {} belongs to no file", b.block_id));
        }
        if self.open.contains_key(&ino) {
            return Err(format!("block {} is being written", b.block_id));
        }
        let m = self.meta(ino);
        if b.generation_stamp != m.generation {
            return Err(format!(
                "block {} has generation stamp {}, not {}",
                b.block_id, m.generation, b.generation_stamp
            ));
        }
        let size = self.tree.size(ino).unwrap_or(0);
        let start = index.saturating_mul(m.block_size);
        if start >= size {
            return Err(format!("block {} is past the end of its file", b.block_id));
        }
        Ok(ReadableBlock {
            ino,
            file_offset: start,
            len: (size - start).min(m.block_size),
        })
    }

    /// The DataNode as the NameNode reports it, reached at `ip`:`xfer_port`.
    pub fn datanode(
        ip: &str,
        xfer_port: u16,
        uuid: &str,
        capacity: u64,
        used: u64,
    ) -> DatanodeInfoProto {
        DatanodeInfoProto {
            id: DatanodeIdProto {
                ip_addr: ip.into(),
                host_name: ip.into(),
                datanode_uuid: uuid.into(),
                xfer_port: xfer_port as u32,
                info_port: 0,
                ipc_port: 0,
                info_secure_port: Some(0),
            },
            capacity: Some(capacity),
            dfs_used: Some(used),
            remaining: Some(capacity.saturating_sub(used)),
            block_pool_used: Some(used),
            last_update: Some(millis(SystemTime::now())),
            xceiver_count: Some(0),
            location: Some("/default-rack".into()),
            admin_state: Some(AdminState::Normal as i32),
            ..Default::default()
        }
    }
}
