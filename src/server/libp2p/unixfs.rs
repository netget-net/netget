//! UnixFS DAGs, both ways: building the blocks of a file or directory the model describes,
//! exactly as Kubo's `ipfs add` builds them, so its root CID is Kubo's; serving those blocks
//! from the description ([`Store`]); and walking a DAG a peer serves, block by verified block
//! ([`Walk`]).
//!
//! **Building.** A description uses `described_disk`'s vocabulary for content: a file is
//! `{text}`, `{hex}`, or `{size, extents: [{offset, text|hex|fill, length}]}`; a directory is
//! `{entries: [{name, kind: file|dir|symlink, …}]}` (FUSE's and HDFS's tree shape), and a
//! symlink is `{kind: symlink, target}`. Rust chunks each file with Kubo's fixed-size chunker
//! (`size-262144` by default) and lays it out balanced (at most 174 links per node), with
//! UnixFS leaves under CIDv0 or raw leaves under CIDv1. Directories are basic (unsharded)
//! directories; one whose node would reach Kubo's HAMT threshold (256 KiB) is refused rather
//! than built differently from Kubo.
//!
//! **Serving.** Only the description is kept. A leaf's bytes are read back out of it when a
//! peer wants the leaf, and every block is hashed again before it is sent.
//!
//! **Walking.** [`Walk`] takes verified blocks (the caller computes each CID from the bytes)
//! and says which CIDs it needs next, in file order, with a bounded window, a bounded number
//! of blocks and a bounded depth. It is iterative: a DAG cannot buy stack depth.
use super::ipfs::{self, Cid, Link, PbNode, UnixFs, DAG_PB, RAW};
use crate::server::described_disk::{self, Extent};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Kubo's default chunker, `size-262144`.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
/// Chunk sizes a description may ask for (Kubo's own maximum is 2 MiB less 256 bytes; NetGet
/// stops at 1 MiB, the size the `unixfs-v1-2025` profile uses).
pub const MIN_CHUNK_SIZE: usize = 256;
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;
/// Kubo's default `--max-file-links` (`Import.UnixFSFileMaxLinks`), and the most allowed.
pub const DEFAULT_MAX_LINKS: usize = 174;
pub const MAX_FILE_LINKS: usize = 1024;
/// Bytes one `ipfs_add` may describe, over every file in it.
pub const MAX_ADD_BYTES: u64 = 256 * 1024 * 1024;
/// Blocks one `ipfs_add` may produce.
pub const MAX_ADD_BLOCKS: usize = 65_536;
/// Entries (files, directories, symlinks) one `ipfs_add` may describe.
pub const MAX_ADD_ENTRIES: usize = 16_384;
/// Entries one directory may hold, and the encoded size its node must stay under: Kubo turns a
/// directory into a HAMT shard at 256 KiB (`Import.UnixFSHAMTDirectorySizeThreshold`), and
/// NetGet builds basic directories only, so it refuses one that Kubo would shard.
pub const MAX_DIR_ENTRIES: usize = 4096;
pub const HAMT_THRESHOLD: usize = 256 * 1024;
/// Directories below the root of an add.
pub const MAX_DIR_DEPTH: usize = 24;
/// Levels in any DAG NetGet builds or walks, root to leaf.
pub const MAX_DAG_DEPTH: usize = 32;
/// Bytes in a name, and in a symlink's target.
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_SYMLINK_TARGET: usize = 4095;
/// What the host keeps across every add: blocks, roots, and explicit content bytes.
pub const MAX_STORE_BLOCKS: usize = 262_144;
pub const MAX_STORE_ROOTS: usize = 256;
pub const MAX_STORE_DESCRIBED: usize = 4 * described_disk::MAX_CONTENT;
/// A want-have for a block no longer than this is answered with the block itself, as boxo's
/// engine does (`maxBlockSizeReplaceHasWithBlock`).
pub const HAVE_AS_BLOCK: usize = 1024;

/// How `ipfs add` lays a file out: Kubo's flags `--cid-version`, `--raw-leaves`,
/// `--chunker=size-N` and `--max-file-links`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub cid_version: u8,
    pub raw_leaves: bool,
    pub chunk_size: usize,
    pub max_links: usize,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            cid_version: 0,
            raw_leaves: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_links: DEFAULT_MAX_LINKS,
        }
    }
}

impl Profile {
    /// From an action: `cid_version` 0 (default) or 1; `raw_leaves` defaults to true under
    /// CIDv1, as Kubo's does.
    pub fn from_json(v: &Value) -> Result<Profile> {
        let version = match &v["cid_version"] {
            Value::Null => None,
            n => Some(
                n.as_u64()
                    .filter(|n| *n <= 1)
                    .context("cid_version is 0 or 1")? as u8,
            ),
        };
        let raw_leaves = match &v["raw_leaves"] {
            Value::Null => None,
            b => Some(b.as_bool().context("raw_leaves is a boolean")?),
        };
        // Raw leaves are always CIDv1 `raw` blocks; the version names the dag-pb nodes, so
        // `--raw-leaves` alone gives a Qm… root over bafk… leaves, as Kubo 0.43 does.
        let cid_version = version.unwrap_or(0);
        let raw_leaves = raw_leaves.unwrap_or(cid_version == 1);
        let chunk_size = match &v["chunk_size"] {
            Value::Null => DEFAULT_CHUNK_SIZE,
            n => n
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(n))
                .with_context(|| {
                    format!("chunk_size is {MIN_CHUNK_SIZE} to {MAX_CHUNK_SIZE} bytes")
                })?,
        };
        let max_links = match &v["max_links"] {
            Value::Null => DEFAULT_MAX_LINKS,
            n => n
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| (2..=MAX_FILE_LINKS).contains(n))
                .with_context(|| format!("max_links is 2 to {MAX_FILE_LINKS}"))?,
        };
        Ok(Profile {
            cid_version,
            raw_leaves,
            chunk_size,
            max_links,
        })
    }

    /// The Kubo command line that adds the same thing with the same CIDs.
    pub fn kubo_flags(&self) -> Vec<String> {
        let mut f = vec![format!("--cid-version={}", self.cid_version)];
        f.push(format!("--raw-leaves={}", self.raw_leaves));
        f.push(format!("--chunker=size-{}", self.chunk_size));
        f.push(format!("--max-file-links={}", self.max_links));
        f
    }

    fn node_cid(&self, bytes: &[u8]) -> Cid {
        Cid {
            version: self.cid_version,
            ..Cid::v1(DAG_PB, bytes)
        }
    }
}

/// A file's content as the model described it: its size and extents (zeroes elsewhere).
#[derive(Debug, PartialEq)]
pub struct Content {
    pub size: u64,
    pub extents: Vec<Extent>,
}

impl Content {
    pub fn read(&self, offset: u64, len: usize) -> Vec<u8> {
        described_disk::read(&self.extents, offset, len)
    }
    fn explicit_bytes(&self) -> usize {
        self.extents
            .iter()
            .map(|e| match &e.content {
                described_disk::Content::Bytes(b) => b.len(),
                described_disk::Content::Fill(_) => 0,
            })
            .sum()
    }
}

/// A file's content from `{text}`, `{hex}` or `{size, extents}`.
pub fn parse_content(v: &Value) -> Result<Content> {
    let inline = match (v.get("text"), v.get("hex")) {
        (Some(Value::String(t)), None) => Some(t.as_bytes().to_vec()),
        (None, Some(Value::String(h))) => Some(hex::decode(h).context("hex is not hex")?),
        (None, None) => None,
        (Some(_), Some(_)) => bail!("a file has text or hex, not both"),
        _ => bail!("text and hex are strings"),
    };
    let has_extents = v.get("extents").is_some_and(|x| !x.is_null());
    ensure!(
        !(inline.is_some() && has_extents),
        "a file has text, hex or extents, not more than one"
    );
    let given = match v.get("size") {
        None | Some(Value::Null) => None,
        Some(s) => Some(s.as_u64().context("size is a number of bytes")?),
    };
    ensure!(
        !has_extents || given.is_some(),
        "a file described by extents gives its size"
    );
    let inline_len = inline.as_ref().map_or(0, Vec::len);
    ensure!(
        inline_len <= described_disk::MAX_CONTENT,
        "a file's text or hex is at most {} bytes",
        described_disk::MAX_CONTENT
    );
    let size = given.unwrap_or(inline_len as u64);
    ensure!(
        size <= MAX_ADD_BYTES,
        "a file is at most {MAX_ADD_BYTES} bytes"
    );
    ensure!(
        inline_len as u64 <= size,
        "size {size} is smaller than the file's text or hex"
    );
    let extents = match inline {
        Some(b) if !b.is_empty() => vec![Extent {
            offset: 0,
            length: b.len() as u64,
            content: described_disk::Content::Bytes(b),
        }],
        Some(_) => Vec::new(),
        None => described_disk::parse_extents(v, size)?,
    };
    Ok(Content { size, extents })
}

/// A name as a directory entry may carry it.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

enum Body {
    File(Arc<Content>),
    Dir,
    Symlink(String),
}

/// One described entry; children come after their directory, so building in reverse order
/// finds every child built before its parent.
struct Item {
    parent: Option<usize>,
    name: String,
    body: Body,
}

/// A description, checked: the add's root (a file, a directory or a symlink) and everything
/// under it. Bounds are checked while reading, before anything is hashed.
pub struct Description {
    items: Vec<Item>,
    pub profile: Profile,
    pub name: String,
}

impl Description {
    pub fn kind(&self) -> &'static str {
        match self.items[0].body {
            Body::File(_) => "file",
            Body::Dir => "directory",
            Body::Symlink(_) => "symlink",
        }
    }
    pub fn total_bytes(&self) -> u64 {
        self.items
            .iter()
            .map(|i| match &i.body {
                Body::File(c) => c.size,
                _ => 0,
            })
            .sum()
    }
    pub fn explicit_bytes(&self) -> usize {
        self.items
            .iter()
            .map(|i| match &i.body {
                Body::File(c) => c.explicit_bytes(),
                _ => 0,
            })
            .sum()
    }
}

/// Read an `ipfs_add` description. The root is a directory when it has `entries` (or says
/// `kind: dir`), a symlink when it says so, and otherwise a file.
pub fn parse(v: &Value) -> Result<Description> {
    ensure!(v.is_object(), "a description is an object");
    let profile = Profile::from_json(v)?;
    let name = match v.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(n) => {
            let n = n.as_str().context("name is text")?;
            ensure!(
                n.len() <= MAX_NAME_BYTES,
                "name is at most {MAX_NAME_BYTES} bytes"
            );
            n.to_string()
        }
    };
    let mut items: Vec<Item> = Vec::new();
    let mut total: u64 = 0;
    let mut explicit: usize = 0;
    // (the directory these entries belong to, the entry, its directory depth)
    let mut work: Vec<(Option<usize>, String, &Value, usize)> = vec![(None, name.clone(), v, 0)];
    while let Some((parent, entry_name, e, depth)) = work.pop() {
        ensure!(
            items.len() < MAX_ADD_ENTRIES,
            "one add describes at most {MAX_ADD_ENTRIES} entries"
        );
        let has_entries = e.get("entries").is_some_and(|x| !x.is_null());
        let kind = match e.get("kind").and_then(Value::as_str) {
            Some(k) => k,
            None if has_entries => "dir",
            None => "file",
        };
        let body = match kind {
            "file" => {
                ensure!(!has_entries, "a file has no entries");
                let c = parse_content(e)?;
                total += c.size;
                explicit += c.explicit_bytes();
                ensure!(
                    total <= MAX_ADD_BYTES,
                    "one add is at most {MAX_ADD_BYTES} bytes"
                );
                ensure!(
                    explicit <= described_disk::MAX_CONTENT,
                    "one add's text and hex are at most {} bytes",
                    described_disk::MAX_CONTENT
                );
                Body::File(Arc::new(c))
            }
            "dir" | "directory" => {
                ensure!(
                    depth <= MAX_DIR_DEPTH,
                    "directories nest at most {MAX_DIR_DEPTH} deep"
                );
                let entries: &[Value] = match e.get("entries") {
                    None | Some(Value::Null) => &[],
                    Some(Value::Array(a)) => a,
                    Some(_) => bail!("entries is an array"),
                };
                ensure!(
                    entries.len() <= MAX_DIR_ENTRIES,
                    "a directory holds at most {MAX_DIR_ENTRIES} entries"
                );
                let me = items.len();
                let mut names = HashSet::new();
                for child in entries {
                    let n = child
                        .get("name")
                        .and_then(Value::as_str)
                        .context("each entry has a name")?;
                    ensure!(
                        valid_name(n),
                        "a name is 1 to {MAX_NAME_BYTES} bytes, not . or .., without / or NUL"
                    );
                    ensure!(names.insert(n), "{n:?} appears twice in one directory");
                    work.push((Some(me), n.to_string(), child, depth + 1));
                }
                Body::Dir
            }
            "symlink" => {
                let t = e
                    .get("target")
                    .and_then(Value::as_str)
                    .context("a symlink has a target")?;
                ensure!(
                    !t.is_empty() && t.len() <= MAX_SYMLINK_TARGET && !t.contains('\0'),
                    "a symlink target is 1 to {MAX_SYMLINK_TARGET} bytes without NUL"
                );
                Body::Symlink(t.to_string())
            }
            other => bail!("kind is file, dir or symlink, not {other:?}"),
        };
        items.push(Item {
            parent,
            name: entry_name,
            body,
        });
    }
    Ok(Description {
        items,
        profile,
        name,
    })
}

/// Where a stored block's bytes come from.
#[derive(Clone, Debug)]
pub enum Source {
    /// An interior node, a directory or a symlink: its encoded bytes.
    Node(Arc<[u8]>),
    /// A leaf: a range of a described file, raw or wrapped as a UnixFS file node.
    Chunk {
        content: Arc<Content>,
        offset: u64,
        len: usize,
        raw: bool,
    },
}

impl Source {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Source::Node(b) => b.to_vec(),
            Source::Chunk {
                content,
                offset,
                len,
                raw,
            } => {
                let data = content.read(*offset, *len);
                if *raw {
                    data
                } else {
                    ipfs::unixfs_file_block(&data)
                }
            }
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Source::Node(b) => b.len(),
            Source::Chunk { len, raw, .. } if *raw => *len,
            Source::Chunk { len, .. } => leaf_len(*len),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The encoded size of a UnixFS leaf holding `n` bytes, without building it.
fn leaf_len(n: usize) -> usize {
    fn varint_len(mut v: u64) -> usize {
        let mut l = 1;
        while v >= 0x80 {
            v >>= 7;
            l += 1;
        }
        l
    }
    // Data{Type=2, Data=n bytes (omitted when empty), filesize=n}
    let data =
        2 + if n > 0 {
            1 + varint_len(n as u64) + n
        } else {
            0
        } + 1
            + varint_len(n as u64);
    1 + varint_len(data as u64) + data
}

/// What one add produced: its root, and every block.
pub struct Built {
    pub root: Cid,
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub depth: usize,
    pub blocks: Vec<(Cid, Source)>,
    pub explicit: usize,
}

impl Built {
    pub fn summary(&self) -> Value {
        json!({"root": self.root.to_string(), "name": self.name, "kind": self.kind,
               "size": self.size, "blocks": self.blocks.len(), "depth": self.depth})
    }
}

/// A built node: its CID, the size of its whole DAG (a link's Tsize), its file bytes, and
/// its depth (a leaf is 0).
#[derive(Clone, Copy)]
struct Made {
    cid: Cid,
    tsize: u64,
    file_size: u64,
    depth: usize,
}

struct Builder {
    profile: Profile,
    blocks: Vec<(Cid, Source)>,
}

impl Builder {
    fn push(&mut self, cid: Cid, source: Source) -> Result<()> {
        ensure!(
            self.blocks.len() < MAX_ADD_BLOCKS,
            "one add produces at most {MAX_ADD_BLOCKS} blocks"
        );
        self.blocks.push((cid, source));
        Ok(())
    }

    fn node(&mut self, node: PbNode) -> Result<(Cid, usize)> {
        let bytes = ipfs::encode_pb_node(&node);
        ensure!(
            bytes.len() <= ipfs::MAX_BLOCK,
            "a node would be {} bytes, over the {}-byte block limit",
            bytes.len(),
            ipfs::MAX_BLOCK
        );
        let cid = self.profile.node_cid(&bytes);
        let len = bytes.len();
        self.push(cid, Source::Node(bytes.into()))?;
        Ok((cid, len))
    }

    fn leaf(&mut self, content: &Arc<Content>, offset: u64, len: usize) -> Result<Made> {
        let data = content.read(offset, len);
        let (cid, block_len) = if self.profile.raw_leaves {
            (Cid::v1(RAW, &data), data.len())
        } else {
            let block = ipfs::unixfs_file_block(&data);
            (self.profile.node_cid(&block), block.len())
        };
        self.push(
            cid,
            Source::Chunk {
                content: content.clone(),
                offset,
                len,
                raw: self.profile.raw_leaves,
            },
        )?;
        Ok(Made {
            cid,
            tsize: block_len as u64,
            file_size: len as u64,
            depth: 0,
        })
    }

    /// Kubo's balanced layout: leaves of `chunk_size` bytes, packed `max_links` to a node, a
    /// level at a time, until one node is left. (go-unixfs builds it top down; the two give
    /// the same tree: every node but the last at a level is full, and a last node with one
    /// child still exists.) An empty file is one empty leaf.
    fn file(&mut self, content: &Arc<Content>) -> Result<Made> {
        let chunk = self.profile.chunk_size as u64;
        let mut level = Vec::new();
        if content.size == 0 {
            level.push(self.leaf(content, 0, 0)?);
        }
        let mut offset = 0;
        while offset < content.size {
            let len = chunk.min(content.size - offset) as usize;
            level.push(self.leaf(content, offset, len)?);
            offset += len as u64;
        }
        while level.len() > 1 {
            let mut up = Vec::with_capacity(level.len() / self.profile.max_links + 1);
            for group in level.chunks(self.profile.max_links) {
                let depth = group[0].depth + 1;
                ensure!(
                    depth <= MAX_DAG_DEPTH,
                    "a file's DAG would be deeper than {MAX_DAG_DEPTH}"
                );
                let file_size = group.iter().map(|m| m.file_size).sum();
                let node = PbNode {
                    links: group
                        .iter()
                        .map(|m| Link {
                            cid: m.cid,
                            name: String::new(),
                            size: m.tsize,
                        })
                        .collect(),
                    data: Some(ipfs::encode_unixfs(&UnixFs {
                        kind: "file".into(),
                        data: Vec::new(),
                        file_size: Some(file_size),
                        block_sizes: group.iter().map(|m| m.file_size).collect(),
                    })),
                };
                let children: u64 = group.iter().map(|m| m.tsize).sum();
                let (cid, len) = self.node(node)?;
                up.push(Made {
                    cid,
                    tsize: len as u64 + children,
                    file_size,
                    depth,
                });
            }
            level = up;
        }
        Ok(level[0])
    }

    fn symlink(&mut self, target: &str) -> Result<Made> {
        let (cid, len) = self.node(PbNode {
            links: Vec::new(),
            data: Some(ipfs::encode_unixfs(&UnixFs {
                kind: "symlink".into(),
                data: target.as_bytes().to_vec(),
                file_size: None,
                block_sizes: Vec::new(),
            })),
        })?;
        Ok(Made {
            cid,
            tsize: len as u64,
            file_size: 0,
            depth: 0,
        })
    }

    /// A basic directory: links sorted by name, `Data` naming the type alone (Kubo stores no
    /// mode or mtime unless asked to).
    fn directory(&mut self, mut children: Vec<(String, Made)>) -> Result<Made> {
        children.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let node = PbNode {
            links: children
                .iter()
                .map(|(name, m)| Link {
                    cid: m.cid,
                    name: name.clone(),
                    size: m.tsize,
                })
                .collect(),
            data: Some(ipfs::encode_unixfs(&UnixFs {
                kind: "directory".into(),
                data: Vec::new(),
                file_size: None,
                block_sizes: Vec::new(),
            })),
        };
        // boxo's estimate (each link's name and CID) and the node itself: either reaching
        // the threshold could make Kubo shard, so neither may.
        let estimate: usize = node
            .links
            .iter()
            .map(|l| l.name.len() + l.cid.to_bytes().len())
            .sum();
        let encoded = ipfs::encode_pb_node(&node).len();
        ensure!(
            estimate.max(encoded) < HAMT_THRESHOLD,
            "a directory this large ({} entries, {encoded} bytes) would be a HAMT shard in Kubo, which NetGet does not build",
            node.links.len()
        );
        let depth = children.iter().map(|(_, m)| m.depth + 1).max().unwrap_or(0);
        ensure!(
            depth <= MAX_DAG_DEPTH,
            "the DAG would be deeper than {MAX_DAG_DEPTH}"
        );
        let below: u64 = children.iter().map(|(_, m)| m.tsize).sum();
        let (cid, len) = self.node(node)?;
        Ok(Made {
            cid,
            tsize: len as u64 + below,
            file_size: 0,
            depth,
        })
    }
}

/// Build every block of a description. CPU-bound (it hashes every byte); callers on an async
/// runtime run it with `spawn_blocking`.
pub fn build(d: &Description) -> Result<Built> {
    let mut b = Builder {
        profile: d.profile,
        blocks: Vec::new(),
    };
    let mut made: Vec<Option<Made>> = vec![None; d.items.len()];
    let mut children: HashMap<usize, Vec<(String, Made)>> = HashMap::new();
    for i in (0..d.items.len()).rev() {
        let item = &d.items[i];
        let m = match &item.body {
            Body::File(c) => b.file(c)?,
            Body::Symlink(t) => b.symlink(t)?,
            Body::Dir => b.directory(children.remove(&i).unwrap_or_default())?,
        };
        if let Some(p) = item.parent {
            children.entry(p).or_default().push((item.name.clone(), m));
        }
        made[i] = Some(m);
    }
    let root = made[0].context("an empty description")?;
    Ok(Built {
        root: root.cid,
        name: d.name.clone(),
        kind: d.kind(),
        size: d.total_bytes(),
        depth: root.depth,
        blocks: b.blocks,
        explicit: d.explicit_bytes(),
    })
}

/// Parse and build in one step.
pub fn add(v: &Value) -> Result<Built> {
    build(&parse(v)?)
}

/// One add the host serves.
#[derive(Clone, Debug)]
pub struct Added {
    pub root: Cid,
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub blocks: usize,
}

/// The blocks a host serves from descriptions, keyed by codec and digest (so a CIDv0 want and
/// a CIDv1 want for one block both find it). Bounded in blocks, roots and explicit bytes; an
/// add over a bound is refused whole.
#[derive(Default)]
pub struct Store {
    blocks: HashMap<(u64, [u8; 32]), Source>,
    roots: Vec<Added>,
    described: usize,
}

impl Store {
    pub fn insert(&mut self, built: Built) -> Result<Added> {
        ensure!(
            self.roots.len() < MAX_STORE_ROOTS,
            "the host serves at most {MAX_STORE_ROOTS} adds"
        );
        let new = built
            .blocks
            .iter()
            .filter(|(c, _)| !self.blocks.contains_key(&(c.codec, c.digest)))
            .map(|(c, _)| (c.codec, c.digest))
            .collect::<HashSet<_>>()
            .len();
        ensure!(
            self.blocks.len() + new <= MAX_STORE_BLOCKS,
            "the host serves at most {MAX_STORE_BLOCKS} blocks"
        );
        ensure!(
            self.described + built.explicit <= MAX_STORE_DESCRIBED,
            "the host keeps at most {MAX_STORE_DESCRIBED} described bytes"
        );
        self.described += built.explicit;
        let added = Added {
            root: built.root,
            name: built.name,
            kind: built.kind,
            size: built.size,
            blocks: built.blocks.len(),
        };
        for (cid, source) in built.blocks {
            self.blocks.insert((cid.codec, cid.digest), source);
        }
        self.roots.push(added.clone());
        Ok(added)
    }
    /// Whether the store holds the block a CID names, and its size.
    pub fn has(&self, cid: &Cid) -> Option<usize> {
        self.blocks.get(&(cid.codec, cid.digest)).map(Source::len)
    }
    /// The block's bytes, read back out of its description and hashed again: bytes that do
    /// not hash to the CID are never returned.
    pub fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        let bytes = self.blocks.get(&(cid.codec, cid.digest))?.bytes();
        cid.matches(&bytes).then_some(bytes)
    }
    pub fn roots(&self) -> &[Added] {
        &self.roots
    }
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// A host's store, shared by its connections: each one learns of every add through
/// [`Shared::subscribe`], so content added on one connection reaches wants remembered on
/// another.
pub struct Shared {
    store: std::sync::Mutex<Store>,
    changed: tokio::sync::watch::Sender<u64>,
}

impl Default for Shared {
    fn default() -> Self {
        Shared {
            store: Default::default(),
            changed: tokio::sync::watch::channel(0).0,
        }
    }
}

impl Shared {
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }
    pub fn with<R>(&self, f: impl FnOnce(&Store) -> R) -> R {
        f(&self.store.lock().unwrap_or_else(|e| e.into_inner()))
    }
    /// Keep a built add and tell every connection.
    pub fn insert(&self, built: Built) -> Result<Added> {
        let added = self
            .store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(built)?;
        self.changed.send_modify(|g| *g += 1);
        Ok(added)
    }
}

// ---------------------------------------------------------------------------------------
// Walking a DAG a peer serves.

/// Blocks one walk may fetch.
pub const MAX_WALK_BLOCKS: usize = 8192;
/// File bytes one walk may read (it keeps only what it shows, and a hash of the rest).
pub const MAX_WALK_BYTES: u64 = 1024 * 1024 * 1024;
/// Wants one walk keeps outstanding at once, and so blocks it may hold waiting for their
/// turn.
pub const WALK_WINDOW: usize = 32;
/// Directory entries a listing describes (each costs one block).
pub const MAX_LISTED: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Root,
    /// A block of the file being read.
    Part,
    /// A directory entry's root, read for its kind and size.
    Entry(usize),
}

/// One directory entry a walk lists.
#[derive(Clone, Debug, PartialEq)]
pub struct Listed {
    pub name: String,
    pub cid: Cid,
    pub tsize: u64,
    /// file, directory, symlink, raw, hamt-shard; None when not looked at.
    pub kind: Option<String>,
    pub size: Option<u64>,
}

/// What a finished walk found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Walked {
    /// file, directory, symlink (a raw block reads as a file).
    pub kind: String,
    /// A file's bytes, as many as the walk was asked to keep.
    pub data: Vec<u8>,
    /// A file's whole size, as read (and checked against what its root says).
    pub size: u64,
    /// SHA-256 of the whole file.
    pub sha256: [u8; 32],
    pub entries: Vec<Listed>,
    pub target: Option<String>,
    pub blocks: usize,
    pub depth: usize,
}

/// A bounded, iterative walk of the DAG under one root. The caller fetches what
/// [`Walk::wants`] names and hands each block over with [`Walk::give`] under the CID its
/// bytes hash to; [`Walk::step`] consumes them in order.
pub struct Walk {
    root: Cid,
    keep: usize,
    /// What to read next, in order: CID, depth, role.
    queue: VecDeque<(Cid, usize, Role)>,
    /// Blocks that arrived before their turn (at most the window).
    arrived: HashMap<(u64, [u8; 32]), Vec<u8>>,
    /// CIDs asked for and not yet arrived.
    asked: HashSet<(u64, [u8; 32])>,
    enqueued: usize,
    out: Walked,
    hasher: sha2::Sha256,
    declared_size: Option<u64>,
    done: bool,
}

impl Walk {
    pub fn new(root: Cid, keep: usize) -> Walk {
        Walk {
            root,
            keep,
            queue: VecDeque::from([(root, 0, Role::Root)]),
            arrived: HashMap::new(),
            asked: HashSet::new(),
            enqueued: 1,
            out: Walked::default(),
            hasher: <sha2::Sha256 as sha2::Digest>::new(),
            declared_size: None,
            done: false,
        }
    }

    pub fn root(&self) -> Cid {
        self.root
    }

    /// CIDs to ask for now: the next ones in order not yet asked, up to the window.
    pub fn wants(&mut self) -> Vec<Cid> {
        let mut out = Vec::new();
        for (cid, _, _) in self.queue.iter().take(WALK_WINDOW) {
            let key = (cid.codec, cid.digest);
            if self.arrived.contains_key(&key) {
                continue;
            }
            // The empty raw block is named by its own content, and Kubo 0.43 answers
            // DONT_HAVE for it (an empty file under raw leaves): it is not asked for.
            if cid.codec == RAW && cid.matches(&[]) {
                self.arrived.insert(key, Vec::new());
                continue;
            }
            if self.asked.insert(key) {
                out.push(*cid);
            }
        }
        out
    }

    /// Whether the next block in order is here, so [`Walk::step`] can go on without waiting.
    pub fn ready(&self) -> bool {
        self.queue
            .front()
            .is_some_and(|(c, _, _)| self.arrived.contains_key(&(c.codec, c.digest)))
    }

    /// CIDs asked for and still outstanding (to ask again, or to cancel).
    pub fn outstanding(&self) -> Vec<Cid> {
        self.queue
            .iter()
            .take(WALK_WINDOW)
            .filter(|(c, _, _)| self.asked.contains(&(c.codec, c.digest)))
            .map(|(c, _, _)| *c)
            .collect()
    }

    /// Whether a block with this CID is one the walk is waiting for.
    pub fn is_wanted(&self, cid: &Cid) -> bool {
        self.asked.contains(&(cid.codec, cid.digest))
    }

    /// A block whose bytes the caller hashed to `cid`. Refused unless it was asked for.
    pub fn give(&mut self, cid: &Cid, data: Vec<u8>) -> Result<()> {
        let key = (cid.codec, cid.digest);
        ensure!(self.asked.remove(&key), "{cid} was not asked for");
        ensure!(
            cid.matches(&data),
            "a block given as {cid} does not hash to it"
        );
        self.arrived.insert(key, data);
        Ok(())
    }

    /// Consume what has arrived, in order. Some(result) when the walk is complete; an error
    /// when the DAG breaks a bound or does not decode.
    pub fn step(&mut self) -> Result<Option<&Walked>> {
        while let Some(&(cid, depth, role)) = self.queue.front() {
            let key = (cid.codec, cid.digest);
            let Some(data) = self.arrived.get(&key).cloned() else {
                return Ok(None);
            };
            self.queue.pop_front();
            // A file of repeated chunks names one leaf many times: keep the block while the
            // window still needs it.
            if !self
                .queue
                .iter()
                .take(WALK_WINDOW)
                .any(|(c, _, _)| (c.codec, c.digest) == key)
            {
                self.arrived.remove(&key);
            }
            self.out.blocks += 1;
            self.out.depth = self.out.depth.max(depth);
            self.take(cid, depth, role, &data)?;
        }
        if !self.done {
            if self.out.kind == "file" {
                if let Some(declared) = self.declared_size {
                    ensure!(
                        declared == self.out.size,
                        "the file's root says {declared} bytes, its leaves hold {}",
                        self.out.size
                    );
                }
                self.out.sha256 = sha2::Digest::finalize(self.hasher.clone()).into();
            }
            self.done = true;
        }
        Ok(Some(&self.out))
    }

    fn enqueue_front(&mut self, items: Vec<(Cid, usize, Role)>) -> Result<()> {
        self.enqueued += items.len();
        ensure!(
            self.enqueued <= MAX_WALK_BLOCKS,
            "the DAG has more than {MAX_WALK_BLOCKS} blocks"
        );
        for it in items.into_iter().rev() {
            ensure!(
                it.1 <= MAX_DAG_DEPTH,
                "the DAG is deeper than {MAX_DAG_DEPTH}"
            );
            self.queue.push_front(it);
        }
        Ok(())
    }

    fn file_bytes(&mut self, b: &[u8]) -> Result<()> {
        self.out.size += b.len() as u64;
        ensure!(
            self.out.size <= MAX_WALK_BYTES,
            "the file is over {MAX_WALK_BYTES} bytes"
        );
        sha2::Digest::update(&mut self.hasher, b);
        let room = self.keep.saturating_sub(self.out.data.len());
        self.out.data.extend_from_slice(&b[..b.len().min(room)]);
        Ok(())
    }

    fn take(&mut self, cid: Cid, depth: usize, role: Role, data: &[u8]) -> Result<()> {
        let d = ipfs::describe(&cid, data)?;
        // A raw block is file bytes; a dag-pb block is whatever its UnixFS type says.
        let kind = match d.codec {
            "raw" => "raw block".to_string(),
            _ => d
                .unixfs_type
                .clone()
                .context("a dag-pb block with no UnixFS data")?,
        };
        if let Role::Entry(i) = role {
            let e = &mut self.out.entries[i];
            e.size = match kind.as_str() {
                "raw block" => Some(data.len() as u64),
                "file" | "raw" => d.file_size.or(Some(d.content.len() as u64)),
                "symlink" => Some(d.content.len() as u64),
                _ => None,
            };
            e.kind = Some(match kind.as_str() {
                "raw block" | "raw" => "file".into(),
                _ => kind,
            });
            return Ok(());
        }
        match (role, kind.as_str()) {
            (Role::Root, "raw block") => {
                self.out.kind = "file".into();
                self.file_bytes(data)
            }
            (Role::Root, "file" | "raw") => {
                self.out.kind = "file".into();
                self.declared_size = d.file_size;
                self.file_part(depth, &d)
            }
            (Role::Part, "raw block") => self.file_bytes(data),
            (Role::Part, "file" | "raw") => self.file_part(depth, &d),
            (Role::Root, "directory") => {
                self.out.kind = "directory".into();
                ensure!(
                    d.links.len() <= MAX_DIR_ENTRIES,
                    "a directory with more than {MAX_DIR_ENTRIES} entries"
                );
                let mut look = Vec::new();
                for l in &d.links {
                    ensure!(valid_name(&l.name), "a directory entry named {:?}", l.name);
                    l.cid.supported()?;
                    if look.len() < MAX_LISTED {
                        look.push((l.cid, depth + 1, Role::Entry(self.out.entries.len())));
                    }
                    self.out.entries.push(Listed {
                        name: l.name.clone(),
                        cid: l.cid,
                        tsize: l.size,
                        kind: None,
                        size: None,
                    });
                }
                self.enqueue_front(look)
            }
            (Role::Root, "symlink") => {
                self.out.kind = "symlink".into();
                self.out.target = Some(String::from_utf8_lossy(&d.content).into_owned());
                Ok(())
            }
            (Role::Root, "hamt-shard") => {
                bail!("{cid} is a HAMT-sharded directory, which NetGet does not walk")
            }
            (_, k) => bail!("{cid}: a {k} node where a file's part was expected"),
        }
    }

    fn file_part(&mut self, depth: usize, d: &ipfs::Described) -> Result<()> {
        if d.links.is_empty() {
            return self.file_bytes(&d.content);
        }
        ensure!(
            d.content.is_empty(),
            "a file node with both links and data is not something ipfs add writes"
        );
        let mut parts = Vec::with_capacity(d.links.len());
        for l in &d.links {
            l.cid.supported()?;
            parts.push((l.cid, depth + 1, Role::Part));
        }
        self.enqueue_front(parts)
    }
}
