//! FUSE local filesystem (Linux and macOS): a directory on this machine whose every file
//! operation the model answers. The kernel is the client; there is no network and no NetGet
//! client role.
//!
//! How the mount is made is the backend's business: on Linux (`linux.rs`) the setuid
//! `fusermount3` mounts `/dev/fuse`; on macOS (`macos.rs`) FUSE-T's `go-nfsv4` serves the mount
//! to the kernel's NFS client and relays each request to fuser in the FUSE wire format. Either
//! way fuser speaks the protocol and everything below is the same.
//!
//! Lookups, getattr, readdir, read and readlink are answered on fuser's thread from the
//! described tree (`src/server/described_tree.rs`). Anything that needs the model — a directory
//! nobody has described yet, or any change — is queued (bounded) for this mount's one worker
//! task, which asks one decision at a time under a deadline and replies to the kernel itself. A request still waiting when the deadline passes is answered EIO, so a
//! process doing I/O on the mount never blocks for longer than `decision_timeout_secs`.
pub mod actions;
pub mod appledouble;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;

pub use backend::is_fuse_mounted;
#[cfg(target_os = "macos")]
pub use macos::{fuse_t_installed, log_path as fuse_t_log_path};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::server::described_tree::{
    self as tree, Allocation, Attr, Changes, Kind, Stop, Tree, XattrMode,
};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::sanitize;
use crate::utils::wire_failure::WireFailure;
use anyhow::{ensure, Context, Result};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, SessionACL, TimeOrNow, WriteFlags,
};
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

/// Whether AppleDouble sidecars (`._x`) are accepted and discarded (`appledouble.rs`): macOS
/// only, where a FUSE-T mount has no named attributes and macOS keeps extended attributes in
/// those files. On Linux a `._x` name is an ordinary name in the tree.
const SIDECARS: bool = cfg!(target_os = "macos");

fn sidecar_name(name: &OsStr) -> bool {
    SIDECARS && appledouble::is_appledouble(name.as_encoded_bytes())
}

fn sidecar_ino(ino: u64) -> bool {
    SIDECARS && appledouble::Sidecars::owns(ino)
}

/// The errno an AppleDouble (`._x`) name gets on macOS where it is not a regular file (mkdir,
/// symlink, link, a FIFO or device): `ENOTSUP`. Regular `._x` files are sidecars and are
/// accepted. Never reached on Linux.
#[cfg(target_os = "macos")]
const APPLEDOUBLE_ERRNO: i32 = libc::ENOTSUP;
#[cfg(not(target_os = "macos"))]
const APPLEDOUBLE_ERRNO: i32 = libc::EPERM;

/// How long a process waits for the model before its system call fails with EIO.
pub const DEFAULT_DECISION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_DECISION_TIMEOUT_SECS: u64 = 600;
/// Requests waiting for the model; past it a request fails with EBUSY at once.
pub const MAX_PENDING: usize = 64;
/// The largest write the kernel may send in one request (its max_write).
pub const MAX_WRITE_BYTES: u32 = 128 * 1024;
/// How long the kernel may cache an entry or attributes.
const TTL: Duration = Duration::from_secs(1);
/// The mount helper coming up, and the kernel's INIT.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of a write shown to the model.
const DATA_PREVIEW: usize = 512;
/// Descriptions one request may need before it can be decided (a rename needs two).
const MAX_DESCRIBES_PER_REQUEST: usize = 4;

struct Settings {
    mount_point: PathBuf,
    read_only: bool,
    allow_other: bool,
    timeout: Duration,
    max_overlay: u64,
}

fn settings(ctx: &SpawnContext) -> Result<Settings> {
    let params = ctx
        .startup_params
        .as_ref()
        .context("mount_point is required: the directory the filesystem appears at")?;
    let mount_point = PathBuf::from(params.get_string("mount_point")?);
    ensure!(mount_point.is_absolute(), "mount_point is an absolute path");
    let secs = params
        .get_optional_u64("decision_timeout_secs")?
        .unwrap_or(DEFAULT_DECISION_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_DECISION_TIMEOUT_SECS).contains(&secs),
        "decision_timeout_secs is 1 to {MAX_DECISION_TIMEOUT_SECS}"
    );
    let max_overlay = params
        .get_optional_u64("max_overlay_bytes")?
        .unwrap_or(tree::DEFAULT_MAX_OVERLAY_BYTES);
    ensure!(
        max_overlay <= tree::MAX_OVERLAY_LIMIT,
        "max_overlay_bytes is at most {}",
        tree::MAX_OVERLAY_LIMIT
    );
    Ok(Settings {
        mount_point,
        read_only: params.get_optional_bool("read_only")?.unwrap_or(false),
        allow_other: params.get_optional_bool("allow_other")?.unwrap_or(false),
        timeout: Duration::from_secs(secs),
        max_overlay,
    })
}

// ------------------------------------------------------------------ mounting

/// Owns the mount: dropping it unmounts (the backend's `Mount`) and removes the mount point if
/// this server created it. Held by the worker task, so `stop_server` aborting that task
/// unmounts.
struct MountGuard {
    mount_point: PathBuf,
    created_dir: bool,
    mount: Option<backend::Mount>,
    status_tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        drop(self.mount.take());
        if self.created_dir {
            let _ = std::fs::remove_dir(&self.mount_point);
        }
        Log::new(Some(&self.status_tx))
            .info(format!("FUSE unmounted {}", self.mount_point.display()));
    }
}

/// Who may use the mount, and fuser's settings: one session thread.
fn session_config(allow_other: bool) -> (SessionACL, fuser::Config) {
    let acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    let mut config = fuser::Config::default();
    config.n_threads = Some(1);
    (acl, config)
}

/// Make sure the mount point is an empty directory: an existing one, or a new one in an
/// existing directory. Returns whether it was created.
fn prepare_mount_point(p: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(p) {
        Ok(m) => {
            ensure!(m.is_dir(), "mount_point {} is not a directory", p.display());
            ensure!(
                !is_fuse_mounted(p),
                "something is already mounted at {}",
                p.display()
            );
            let mut entries = std::fs::read_dir(p)
                .with_context(|| format!("reading mount_point {}", p.display()))?;
            ensure!(
                entries.next().is_none(),
                "mount_point {} is not empty",
                p.display()
            );
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(p).with_context(|| {
                format!(
                    "creating mount_point {} (its parent must exist)",
                    p.display()
                )
            })?;
            Ok(true)
        }
        Err(e) => Err(e).with_context(|| format!("mount_point {}", p.display())),
    }
}

// ------------------------------------------------------------------ requests

#[derive(Clone, Copy, Debug)]
struct Who {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl Who {
    fn of(req: &Request) -> Self {
        Who {
            pid: req.pid(),
            uid: req.uid(),
            gid: req.gid(),
        }
    }

    fn fields(&self) -> serde_json::Map<String, Value> {
        let process = if self.pid == 0 {
            String::new()
        } else {
            std::fs::read_to_string(format!("/proc/{}/comm", self.pid))
                .map(|s| sanitize::token(&s, 32))
                .unwrap_or_default()
        };
        let mut m = serde_json::Map::new();
        m.insert("pid".into(), json!(self.pid));
        m.insert("uid".into(), json!(self.uid));
        m.insert("gid".into(), json!(self.gid));
        m.insert("process".into(), json!(process));
        m
    }
}

/// A request the fuser thread could not answer from the tree, with the reply it owes.
enum Job {
    Lookup {
        parent: u64,
        name: String,
        reply: ReplyEntry,
    },
    Readdir {
        ino: u64,
        offset: u64,
        reply: ReplyDirectory,
    },
    Create {
        parent: u64,
        name: String,
        mode: u32,
        flags: i32,
        reply: ReplyCreate,
    },
    Mknod {
        parent: u64,
        name: String,
        mode: u32,
        kind: Kind,
        rdev: u32,
        reply: ReplyEntry,
    },
    Mkdir {
        parent: u64,
        name: String,
        mode: u32,
        reply: ReplyEntry,
    },
    Symlink {
        parent: u64,
        name: String,
        target: String,
        reply: ReplyEntry,
    },
    Unlink {
        parent: u64,
        name: String,
        reply: ReplyEmpty,
    },
    Rmdir {
        parent: u64,
        name: String,
        reply: ReplyEmpty,
    },
    Rename {
        parent: u64,
        name: String,
        new_parent: u64,
        new_name: String,
        no_replace: bool,
        exchange: bool,
        reply: ReplyEmpty,
    },
    Link {
        ino: u64,
        new_parent: u64,
        new_name: String,
        reply: ReplyEntry,
    },
    Setxattr {
        ino: u64,
        name: String,
        value: Vec<u8>,
        mode: XattrMode,
        reply: ReplyEmpty,
    },
    Removexattr {
        ino: u64,
        name: String,
        reply: ReplyEmpty,
    },
    Fallocate {
        ino: u64,
        offset: u64,
        length: u64,
        how: Allocation,
        mode: i32,
        reply: ReplyEmpty,
    },
    Write {
        ino: u64,
        offset: u64,
        data: Vec<u8>,
        flags: i32,
        reply: ReplyWrite,
    },
    Setattr {
        ino: u64,
        size: Option<u64>,
        changes: Changes,
        reply: ReplyAttr,
    },
}

impl Job {
    fn name(&self) -> &'static str {
        match self {
            Job::Lookup { .. } => "lookup",
            Job::Readdir { .. } => "readdir",
            Job::Create { .. } | Job::Mknod { .. } => "create",
            Job::Mkdir { .. } => "mkdir",
            Job::Symlink { .. } => "symlink",
            Job::Unlink { .. } => "unlink",
            Job::Rmdir { .. } => "rmdir",
            Job::Rename { .. } => "rename",
            Job::Link { .. } => "link",
            Job::Setxattr { .. } => "setxattr",
            Job::Removexattr { .. } => "removexattr",
            Job::Fallocate { .. } => "fallocate",
            Job::Write { .. } => "write",
            Job::Setattr { size: Some(_), .. } => "truncate",
            Job::Setattr { .. } => "setattr",
        }
    }

    /// Answer the request with an errno.
    fn fail(self, code: i32) {
        let e = Errno::from_i32(code);
        match self {
            Job::Lookup { reply, .. }
            | Job::Mknod { reply, .. }
            | Job::Mkdir { reply, .. }
            | Job::Symlink { reply, .. }
            | Job::Link { reply, .. } => reply.error(e),
            Job::Readdir { reply, .. } => reply.error(e),
            Job::Create { reply, .. } => reply.error(e),
            Job::Unlink { reply, .. }
            | Job::Rmdir { reply, .. }
            | Job::Rename { reply, .. }
            | Job::Setxattr { reply, .. }
            | Job::Removexattr { reply, .. }
            | Job::Fallocate { reply, .. } => reply.error(e),
            Job::Write { reply, .. } => reply.error(e),
            Job::Setattr { reply, .. } => reply.error(e),
        }
    }
}

struct Pending {
    job: Job,
    who: Who,
    arrived: tokio::time::Instant,
}

fn file_type(k: Kind) -> FileType {
    match k {
        Kind::File => FileType::RegularFile,
        Kind::Dir => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
        Kind::Fifo => FileType::NamedPipe,
        Kind::Socket => FileType::Socket,
        Kind::CharDevice => FileType::CharDevice,
        Kind::BlockDevice => FileType::BlockDevice,
    }
}

fn file_attr(a: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(a.ino),
        size: a.size,
        blocks: a.blocks,
        atime: a.atime,
        mtime: a.mtime,
        ctime: a.ctime,
        crtime: a.ctime,
        kind: file_type(a.kind),
        perm: a.perm,
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        rdev: a.rdev,
        blksize: tree::PAGE as u32,
        flags: 0,
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The first bytes of a write as text when they are text, else as hex, never raw.
fn preview(data: &[u8]) -> (String, &'static str, bool) {
    let cut = &data[..data.len().min(DATA_PREVIEW)];
    let text = match std::str::from_utf8(cut) {
        Ok(s) => Some(s),
        // A character cut in half at the end of the preview is still text.
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&cut[..e.valid_up_to()]).ok(),
        Err(_) => None,
    };
    match text {
        Some(s) if sanitize::multiline(s) == s => (s.to_string(), "utf8", data.len() > s.len()),
        _ => {
            let n = data.len().min(DATA_PREVIEW / 2);
            (hex::encode(&data[..n]), "hex", data.len() > n)
        }
    }
}

// ------------------------------------------------------------------ the fuser side

struct FuseFs {
    tree: Arc<Mutex<Tree>>,
    queue: mpsc::Sender<Pending>,
    read_only: bool,
    status_tx: tokio::sync::mpsc::UnboundedSender<String>,
    mount_label: String,
    /// macOS: the AppleDouble sidecars, kept apart from the tree and never shown to the model.
    sidecars: Mutex<appledouble::Sidecars>,
}

fn lock(t: &Mutex<Tree>) -> std::sync::MutexGuard<'_, Tree> {
    t.lock().unwrap_or_else(|p| p.into_inner())
}

impl FuseFs {
    fn enqueue(&self, req: &Request, job: Job) {
        let pending = Pending {
            job,
            who: Who::of(req),
            arrived: tokio::time::Instant::now(),
        };
        match self.queue.try_send(pending) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(p)) => {
                Log::new(Some(&self.status_tx)).error(format!(
                    "FUSE {} operation={} decision=fail_closed_saturated {MAX_PENDING} requests \
                     already wait for the model; answered EBUSY",
                    self.mount_label,
                    p.job.name()
                ));
                p.job.fail(libc::EBUSY);
            }
            // The server was stopped while a process still had the (lazily unmounted) mount.
            Err(mpsc::error::TrySendError::Closed(p)) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "FUSE {} operation={} decision=fail_closed_stopped the server is stopped; \
                     answered EIO",
                    self.mount_label,
                    p.job.name()
                ));
                p.job.fail(libc::EIO);
            }
        }
    }

    /// macOS only: whether `name` is an AppleDouble name (`._x`) for something other than a
    /// regular file — a directory, symlink or hard link — refused [`APPLEDOUBLE_ERRNO`] without
    /// asking. A regular `._x` file is a sidecar, accepted and discarded (`appledouble.rs`).
    /// Never on Linux.
    fn apple_double(&self, op: &str, name: &OsStr) -> bool {
        if !sidecar_name(name) {
            return false;
        }
        Log::new(Some(&self.status_tx)).info(format!(
            "FUSE {} operation={op} decision=protocol_refusal {} is an AppleDouble name, which \
             only a regular file (a sidecar) may have; answered {}",
            self.mount_label,
            sanitize::token(&name.to_string_lossy(), 255),
            tree::errno_name(APPLEDOUBLE_ERRNO)
        ));
        true
    }

    fn sidecars(&self) -> std::sync::MutexGuard<'_, appledouble::Sidecars> {
        self.sidecars.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Create (or find) the sidecar `name` in `parent` for the caller, without asking the
    /// model: macOS metadata on this volume is accepted and discarded.
    fn accept_sidecar(
        &self,
        req: &Request,
        op: &str,
        parent: u64,
        name: &OsStr,
    ) -> Result<Attr, i32> {
        let name = name.to_string_lossy();
        let made = self
            .sidecars()
            .create(parent, &name, req.uid(), req.gid(), SystemTime::now());
        match &made {
            Ok(a) => Log::new(Some(&self.status_tx)).debug(format!(
                "FUSE {} operation={op} decision=protocol_accept appledouble {} (inode {}); its \
                 bytes are discarded",
                self.mount_label,
                sanitize::token(&name, 255),
                a.ino
            )),
            Err(c) => Log::new(Some(&self.status_tx)).info(format!(
                "FUSE {} operation={op} decision=protocol_refusal appledouble {}: {} sidecars \
                 already; answered {}",
                self.mount_label,
                sanitize::token(&name, 255),
                appledouble::MAX_SIDECARS,
                tree::errno_name(*c)
            )),
        }
        made
    }

    fn refuse_read_only(&self, op: &str) -> Errno {
        Log::new(Some(&self.status_tx)).info(format!(
            "FUSE {} operation={op} decision=read_only answered EROFS",
            self.mount_label
        ));
        Errno::EROFS
    }
}

fn name_of(name: &OsStr) -> Option<String> {
    name.to_str().map(str::to_string)
}

/// A rename's flags as (exchange, no_replace), or None for EINVAL. A whiteout is overlayfs's
/// marker for a deleted lower entry, which this tree has no notion of; EXCHANGE with NOREPLACE
/// contradicts itself. Both are EINVAL, as from a filesystem that does not support them, and the
/// model is not asked.
#[cfg(target_os = "linux")]
fn rename_mode(flags: RenameFlags) -> Option<(bool, bool)> {
    let exchange = flags.contains(RenameFlags::RENAME_EXCHANGE);
    let no_replace = flags.contains(RenameFlags::RENAME_NOREPLACE);
    let known = RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_NOREPLACE;
    if !(flags - known).is_empty() || (exchange && no_replace) {
        None
    } else {
        Some((exchange, no_replace))
    }
}

/// On macOS a rename carries no flags: FUSE-T's NFS server has no renamex_np, so RENAME_SWAP
/// and RENAME_EXCL never reach a FUSE-T daemon. Anything else is EINVAL, unasked.
#[cfg(target_os = "macos")]
fn rename_mode(flags: RenameFlags) -> Option<(bool, bool)> {
    flags.is_empty().then_some((false, false))
}

impl Filesystem for FuseFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let _ = config.set_max_write(MAX_WRITE_BYTES);
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        // The kernel leaves NAME_MAX to the filesystem.
        if name.len() > tree::MAX_NAME_BYTES {
            return reply.error(Errno::ENAMETOOLONG);
        }
        if sidecar_name(name) {
            let found = self.sidecars().lookup(parent.0, &name.to_string_lossy());
            return match found {
                Some(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                None => reply.error(Errno::ENOENT),
            };
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::ENOENT);
        };
        let answer = lock(&self.tree).lookup(parent.0, &name);
        match answer {
            Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(c)),
            Err(Stop::Describe(_)) => self.enqueue(
                req,
                Job::Lookup {
                    parent: parent.0,
                    name,
                    reply,
                },
            ),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if sidecar_ino(ino.0) {
            let a = self.sidecars().attr(ino.0);
            return match a {
                Some(a) => reply.attr(&TTL, &file_attr(&a)),
                None => reply.error(Errno::ENOENT),
            };
        }
        match lock(&self.tree).attr(ino.0) {
            Some(a) => reply.attr(&TTL, &file_attr(&a)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if sidecar_ino(ino.0) {
            // Only a size changes a sidecar; mode, owner and times stay as they are.
            if size.is_some() && self.read_only {
                return reply.error(self.refuse_read_only("setattr"));
            }
            let a = self.sidecars().setattr(ino.0, size, SystemTime::now());
            return match a {
                Ok(a) => reply.attr(&TTL, &file_attr(&a)),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        let when = |t: TimeOrNow| match t {
            TimeOrNow::SpecificTime(t) => t,
            TimeOrNow::Now => SystemTime::now(),
        };
        let changes = Changes {
            perm: mode.map(|m| (m & 0o7777) as u16),
            uid,
            gid,
            atime: atime.map(when),
            mtime: mtime.map(when),
        };
        if changes == Changes::default() && size.is_none() {
            return match lock(&self.tree).attr(ino.0) {
                Some(a) => reply.attr(&TTL, &file_attr(&a)),
                None => reply.error(Errno::ENOENT),
            };
        }
        if self.read_only {
            return reply.error(self.refuse_read_only("setattr"));
        }
        self.enqueue(
            req,
            Job::Setattr {
                ino: ino.0,
                size,
                changes,
                reply,
            },
        );
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match lock(&self.tree).readlink(ino.0) {
            Ok(t) => reply.data(t.as_bytes()),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(c)),
            Err(Stop::Describe(_)) => reply.error(Errno::EIO),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        // A FIFO, socket or device node is only a name here: the kernel serves its I/O (and the
        // mount is nodev, so a device node cannot be opened through it).
        // `mode_t` is 16 bits on macOS and 32 on Linux, so the casts are needed on one of them.
        #[allow(clippy::unnecessary_cast)]
        let kind = match mode & libc::S_IFMT as u32 {
            m if m == libc::S_IFREG as u32 => Kind::File,
            m if m == libc::S_IFIFO as u32 => Kind::Fifo,
            m if m == libc::S_IFSOCK as u32 => Kind::Socket,
            m if m == libc::S_IFCHR as u32 => Kind::CharDevice,
            m if m == libc::S_IFBLK as u32 => Kind::BlockDevice,
            _ => return reply.error(Errno::EINVAL),
        };
        if self.read_only {
            return reply.error(self.refuse_read_only("create"));
        }
        if sidecar_name(name) {
            if kind != Kind::File {
                self.apple_double("create", name);
                return reply.error(Errno::from_i32(APPLEDOUBLE_ERRNO));
            }
            return match self.accept_sidecar(req, "create", parent.0, name) {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Mknod {
                parent: parent.0,
                name,
                mode: mode & !umask,
                kind,
                rdev,
                reply,
            },
        );
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("mkdir"));
        }
        if self.apple_double("mkdir", name) {
            return reply.error(Errno::from_i32(APPLEDOUBLE_ERRNO));
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Mkdir {
                parent: parent.0,
                name,
                mode: mode & !umask,
                reply,
            },
        );
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            return reply.error(self.refuse_read_only("unlink"));
        }
        if sidecar_name(name) {
            let gone = self.sidecars().unlink(parent.0, &name.to_string_lossy());
            return match gone {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::ENOENT);
        };
        self.enqueue(
            req,
            Job::Unlink {
                parent: parent.0,
                name,
                reply,
            },
        );
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            return reply.error(self.refuse_read_only("rmdir"));
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::ENOENT);
        };
        self.enqueue(
            req,
            Job::Rmdir {
                parent: parent.0,
                name,
                reply,
            },
        );
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("symlink"));
        }
        if self.apple_double("symlink", link_name) {
            return reply.error(Errno::from_i32(APPLEDOUBLE_ERRNO));
        }
        let (Some(name), Some(target)) = (name_of(link_name), target.to_str()) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Symlink {
                parent: parent.0,
                name,
                target: target.to_string(),
                reply,
            },
        );
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("rename"));
        }
        match (sidecar_name(name), sidecar_name(newname)) {
            (false, false) => {}
            (true, true) => {
                let moved = self.sidecars().rename(
                    parent.0,
                    &name.to_string_lossy(),
                    newparent.0,
                    &newname.to_string_lossy(),
                    SystemTime::now(),
                );
                return match moved {
                    Ok(()) => reply.ok(),
                    Err(c) => reply.error(Errno::from_i32(c)),
                };
            }
            // A sidecar becoming an ordinary file, or the reverse, would move a name between
            // the discarded side and the tree the model decides about.
            _ => {
                Log::new(Some(&self.status_tx)).info(format!(
                    "FUSE {} operation=rename decision=protocol_refusal between an AppleDouble \
                     name and another; answered EPERM",
                    self.mount_label
                ));
                return reply.error(Errno::EPERM);
            }
        }
        let Some((exchange, no_replace)) = rename_mode(flags) else {
            Log::new(Some(&self.status_tx)).info(format!(
                "FUSE {} operation=rename decision=protocol_refusal flags {:#x} (whiteout, or \
                 exchange with noreplace) answered EINVAL",
                self.mount_label,
                flags.bits()
            ));
            return reply.error(Errno::EINVAL);
        };
        let (Some(name), Some(new_name)) = (name_of(name), name_of(newname)) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Rename {
                parent: parent.0,
                name,
                new_parent: newparent.0,
                new_name,
                no_replace,
                exchange,
                reply,
            },
        );
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("link"));
        }
        if self.apple_double("link", newname) {
            return reply.error(Errno::from_i32(APPLEDOUBLE_ERRNO));
        }
        if sidecar_ino(ino.0) {
            return reply.error(Errno::EPERM);
        }
        if newname.len() > tree::MAX_NAME_BYTES {
            return reply.error(Errno::ENAMETOOLONG);
        }
        let Some(new_name) = name_of(newname) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Link {
                ino: ino.0,
                new_parent: newparent.0,
                new_name,
                reply,
            },
        );
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if sidecar_ino(ino.0) {
            let live = self.sidecars().attr(ino.0).is_some();
            return if live {
                reply.opened(FileHandle(0), FopenFlags::empty())
            } else {
                reply.error(Errno::ENOENT)
            };
        }
        let mut t = lock(&self.tree);
        match t.kind(ino.0) {
            None => return reply.error(Errno::ENOENT),
            Some(Kind::Dir) => return reply.error(Errno::EISDIR),
            Some(_) => {}
        }
        if self.read_only && flags.acc_mode() != fuser::OpenAccMode::O_RDONLY {
            drop(t);
            return reply.error(self.refuse_read_only("open"));
        }
        t.opened(ino.0);
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if sidecar_ino(ino.0) {
            let zeroes = self.sidecars().read(ino.0, offset, size);
            return match zeroes {
                Ok(z) => reply.data(&z),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        match lock(&self.tree).read(ino.0, offset, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(c)),
            Err(Stop::Describe(_)) => reply.error(Errno::EIO),
        }
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("write"));
        }
        if sidecar_ino(ino.0) {
            let written =
                self.sidecars()
                    .write(ino.0, offset, data.len() as u32, SystemTime::now());
            return match written {
                Ok(n) => reply.written(n),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        self.enqueue(
            req,
            Job::Write {
                ino: ino.0,
                offset,
                data: data.to_vec(),
                flags: flags.0,
                reply,
            },
        );
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Every accepted write is already in the overlay: nothing to flush.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        lock(&self.tree).released(ino.0);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        let listing = {
            let t = lock(&self.tree);
            t.list(ino.0).map(|l| (t.parent(ino.0).unwrap_or(1), l))
        };
        match listing {
            Ok((parent, entries)) => fill(ino.0, parent, entries, offset, reply),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(c)),
            Err(Stop::Describe(_)) => self.enqueue(
                req,
                Job::Readdir {
                    ino: ino.0,
                    offset,
                    reply,
                },
            ),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let t = lock(&self.tree);
        let blocks = t.max_overlay() / tree::PAGE;
        let free = (t.max_overlay() - t.overlay_bytes().min(t.max_overlay())) / tree::PAGE;
        let files = tree::MAX_NODES as u64;
        let ffree = files.saturating_sub(t.node_count() as u64);
        reply.statfs(
            blocks,
            free,
            free,
            files,
            ffree,
            tree::PAGE as u32,
            tree::MAX_NAME_BYTES as u32,
            tree::PAGE as u32,
        );
    }

    fn setxattr(
        &self,
        req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("setxattr"));
        }
        let mode = match flags {
            0 => XattrMode::Either,
            libc::XATTR_CREATE => XattrMode::Create,
            libc::XATTR_REPLACE => XattrMode::Replace,
            _ => return reply.error(Errno::EINVAL),
        };
        // `position` is macOS's resource-fork offset; Linux always sends 0.
        if position != 0 {
            return reply.error(Errno::EINVAL);
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EOPNOTSUPP);
        };
        self.enqueue(
            req,
            Job::Setxattr {
                ino: ino.0,
                name,
                value: value.to_vec(),
                mode,
                reply,
            },
        );
    }

    /// Answered from the tree at no model cost. A size of 0 asks for the value's length; a
    /// buffer too small for it is ERANGE; a name the node does not have is ENODATA.
    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        if sidecar_ino(ino.0) {
            return reply.error(Errno::from_i32(xattr_errno(libc::ENODATA)));
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EOPNOTSUPP);
        };
        let t = lock(&self.tree);
        match t.getxattr(ino.0, &name) {
            Ok(v) => xattr_reply(v, size, reply),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(xattr_errno(c))),
            Err(Stop::Describe(_)) => reply.error(Errno::EIO),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        if sidecar_ino(ino.0) {
            return xattr_reply(&[], size, reply);
        }
        let list = lock(&self.tree).listxattr(ino.0);
        match list {
            Ok(v) => xattr_reply(&v, size, reply),
            Err(Stop::Errno(c)) => reply.error(Errno::from_i32(c)),
            Err(Stop::Describe(_)) => reply.error(Errno::EIO),
        }
    }

    fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            return reply.error(self.refuse_read_only("removexattr"));
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EOPNOTSUPP);
        };
        self.enqueue(
            req,
            Job::Removexattr {
                ino: ino.0,
                name,
                reply,
            },
        );
    }

    fn fallocate(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("fallocate"));
        }
        if sidecar_ino(ino.0) {
            return reply.error(Errno::EOPNOTSUPP);
        }
        let Some(how) = Allocation::from_mode(mode) else {
            Log::new(Some(&self.status_tx)).info(format!(
                "FUSE {} operation=fallocate decision=protocol_refusal mode {mode:#x} is not \
                 implemented; answered EOPNOTSUPP",
                self.mount_label
            ));
            return reply.error(Errno::EOPNOTSUPP);
        };
        self.enqueue(
            req,
            Job::Fallocate {
                ino: ino.0,
                offset,
                length,
                how,
                mode,
                reply,
            },
        );
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if self.read_only {
            return reply.error(self.refuse_read_only("create"));
        }
        if sidecar_name(name) {
            return match self.accept_sidecar(req, "create", parent.0, name) {
                Ok(a) => reply.created(
                    &TTL,
                    &file_attr(&a),
                    Generation(0),
                    FileHandle(0),
                    FopenFlags::empty(),
                ),
                Err(c) => reply.error(Errno::from_i32(c)),
            };
        }
        let Some(name) = name_of(name) else {
            return reply.error(Errno::EINVAL);
        };
        self.enqueue(
            req,
            Job::Create {
                parent: parent.0,
                name,
                mode: mode & !umask,
                flags,
                reply,
            },
        );
    }
}

/// The errno for an extended attribute that is not there. The tree says ENODATA, which is what
/// Linux's xattr calls return; macOS's return ENOATTR, and ENODATA there means something else.
fn xattr_errno(code: i32) -> i32 {
    #[cfg(target_os = "macos")]
    if code == libc::ENODATA {
        return libc::ENOATTR;
    }
    code
}

/// An extended attribute's value or the name list: its length when `size` is 0, ERANGE when it
/// does not fit in `size`.
fn xattr_reply(v: &[u8], size: u32, reply: ReplyXattr) {
    if size == 0 {
        reply.size(v.len() as u32);
    } else if v.len() > size as usize {
        reply.error(Errno::ERANGE);
    } else {
        reply.data(v);
    }
}

/// A directory listing from `offset`: `.`, `..`, then the entries in name order.
fn fill(
    ino: u64,
    parent: u64,
    entries: Vec<(u64, Kind, String)>,
    offset: u64,
    mut reply: ReplyDirectory,
) {
    let all = [
        (ino, Kind::Dir, ".".to_string()),
        (parent.max(1), Kind::Dir, "..".to_string()),
    ]
    .into_iter()
    // macOS: sidecars and any described `._` name are never listed (`appledouble.rs`).
    .chain(
        entries
            .into_iter()
            .filter(|(_, _, n)| !(SIDECARS && appledouble::is_appledouble(n.as_bytes()))),
    );
    for (i, (child, kind, name)) in all.enumerate().skip(offset as usize) {
        if reply.add(INodeNo(child), (i + 1) as u64, file_type(kind), &name) {
            break;
        }
    }
    reply.ok();
}

// ------------------------------------------------------------------ the worker

/// Why a model decision did not produce an answer.
enum Failure {
    Deadline,
    Llm(WireFailure),
    Silent,
    Invalid(String),
}

impl Failure {
    fn errno(&self) -> i32 {
        match self {
            Failure::Llm(WireFailure::Overloaded) => libc::EAGAIN,
            _ => libc::EIO,
        }
    }
    fn decision(&self) -> &'static str {
        match self {
            Failure::Deadline => "fail_closed_deadline",
            Failure::Llm(_) => "fail_closed_llm_error",
            Failure::Silent => "model_silent",
            Failure::Invalid(_) => "fail_closed_invalid_reply",
        }
    }
    fn detail(&self) -> String {
        match self {
            Failure::Deadline => "no answer before decision_timeout_secs".into(),
            Failure::Llm(_) => "the model backend failed".into(),
            Failure::Silent => "no answer".into(),
            Failure::Invalid(why) => why.clone(),
        }
    }
}

struct Worker {
    ctx: Arc<SpawnContext>,
    tree: Arc<Mutex<Tree>>,
    connection: ConnectionId,
    label: String,
    timeout: Duration,
}

impl Worker {
    fn outcome(&self, op: &str, path: &str, decision: &str, detail: &str) {
        let summary = format!(
            "FUSE {} operation={op} path={} decision={decision} {}",
            self.label,
            sanitize::token(path, 512),
            sanitize::strip_controls(detail)
        );
        let log = Log::new(Some(&self.ctx.status_tx));
        if decision.starts_with("fail_closed_") || decision == "model_silent" {
            log.error(summary);
        } else if decision == "protocol_refusal" || decision == "model_reject" {
            log.info(summary);
        } else {
            log.debug(summary);
        }
    }

    async fn run(self, mut rx: mpsc::Receiver<Pending>, guard: MountGuard) {
        while let Some(p) = rx.recv().await {
            let deadline = p.arrived + self.timeout;
            self.handle(p, deadline).await;
        }
        // The kernel ended the session (unmounted from outside): tidy up.
        drop(guard);
    }

    /// One model call that must produce exactly one answer of an allowed type.
    async fn ask(
        &self,
        event: &Event,
        allowed: &[&str],
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Value, Failure> {
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        let call = call_llm(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.server_id,
            Some(self.connection),
            event,
            &actions::FuseProtocol,
        );
        let result = match tokio::time::timeout_at(deadline, call).await {
            Err(_) => return Err(Failure::Deadline),
            Ok(Err(e)) => return Err(Failure::Llm(WireFailure::classify(&e))),
            Ok(Ok(r)) => r,
        };
        let mut answers = Vec::new();
        let why = result.failure_summary();
        let mut queue = result.protocol_results;
        while let Some(r) = queue.pop() {
            match r {
                ActionResult::Custom { data, .. } => answers.push(data),
                ActionResult::Multiple(items) => queue.extend(items),
                _ => {}
            }
        }
        if answers.is_empty() && result.failures.is_empty() {
            return Err(Failure::Silent);
        }
        if answers.len() != 1 || !result.failures.is_empty() {
            return Err(Failure::Invalid(match why {
                Some(why) => format!("not exactly one valid answer: {why}"),
                None => "not exactly one valid answer".into(),
            }));
        }
        let answer = answers.remove(0);
        let kind = answer["type"].as_str().unwrap_or_default();
        if !allowed.contains(&kind) {
            return Err(Failure::Invalid(format!(
                "{kind} does not answer this event (expected {})",
                allowed.join(" or ")
            )));
        }
        Ok(answer)
    }

    /// Ask the model to describe a pending directory and commit the answer.
    async fn describe(
        &self,
        dir: u64,
        operation: &str,
        name: Option<&str>,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let (path, depth) = {
            let t = lock(&self.tree);
            match t.dir_state(dir) {
                Some(tree::DirState::Pending(_)) => {}
                // Described (or refused) while this request waited.
                _ => return Ok(()),
            }
            (t.path(dir), t.depth(dir))
        };
        // A request that waited out its deadline in the queue never reached the model, so it
        // is not one of the directory's attempts.
        if tokio::time::Instant::now() >= deadline {
            self.outcome(
                "describe",
                &path,
                "fail_closed_deadline",
                "the deadline passed while the request waited; answered EIO",
            );
            return Err(libc::EIO);
        }
        let mut fields = who.fields();
        fields.insert("path".into(), json!(path));
        fields.insert("depth".into(), json!(depth));
        fields.insert("operation".into(), json!(operation));
        if let Some(n) = name {
            fields.insert("name".into(), json!(n));
        }
        let event = Event::new(&actions::DESCRIBE_EVENT, Value::Object(fields));
        let answer = self
            .ask(&event, &[actions::DIRECTORY, actions::DENY], deadline)
            .await;
        let mut t = lock(&self.tree);
        match answer {
            Ok(a) if a["type"] == actions::DENY => {
                let code = tree::errno_named(a["error"].as_str().unwrap_or_default())
                    .unwrap_or(libc::EACCES);
                t.description_refused(dir, code);
                drop(t);
                self.outcome(
                    "describe",
                    &path,
                    "model_reject",
                    &format!("answered {}", tree::errno_name(code)),
                );
                Err(code)
            }
            Ok(a) => match t.describe(dir, &a) {
                Ok(n) => {
                    drop(t);
                    self.outcome("describe", &path, "model_answer", &format!("{n} entries"));
                    Ok(())
                }
                Err(e) => {
                    let failed = t.description_failed(dir);
                    drop(t);
                    self.outcome(
                        "describe",
                        &path,
                        "fail_closed_invalid_reply",
                        &format!(
                            "{e:#}; answered EIO{}",
                            if failed {
                                ", and the directory has failed for good"
                            } else {
                                ""
                            }
                        ),
                    );
                    Err(libc::EIO)
                }
            },
            Err(f) => {
                let failed = t.description_failed(dir);
                drop(t);
                self.outcome(
                    "describe",
                    &path,
                    f.decision(),
                    &format!(
                        "{}; answered {}{}",
                        f.detail(),
                        tree::errno_name(f.errno()),
                        if failed {
                            ", and the directory has failed for good"
                        } else {
                            ""
                        }
                    ),
                );
                Err(f.errno())
            }
        }
    }

    /// Run a check against the tree, describing whatever directory it needs first.
    async fn settle<T>(
        &self,
        op: &str,
        name: Option<&str>,
        who: Who,
        deadline: tokio::time::Instant,
        check: impl Fn(&Tree) -> tree::Outcome<T>,
    ) -> std::result::Result<T, i32> {
        for _ in 0..MAX_DESCRIBES_PER_REQUEST {
            let r = check(&lock(&self.tree));
            match r {
                Ok(v) => return Ok(v),
                Err(Stop::Errno(c)) => return Err(c),
                Err(Stop::Describe(dir)) => {
                    let operation = if op == "readdir" { "readdir" } else { "lookup" };
                    self.describe(dir, operation, name, who, deadline).await?;
                }
            }
        }
        Err(libc::EIO)
    }

    /// Ask whether a change may happen: Ok to apply it, or the errno to answer.
    async fn decide(
        &self,
        op: &str,
        path: &str,
        event_type: &'static EventType,
        mut fields: serde_json::Map<String, Value>,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        fields.extend(who.fields());
        fields.insert("path".into(), json!(path));
        let event = Event::new(event_type, Value::Object(fields));
        match self
            .ask(&event, &[actions::ALLOW, actions::DENY], deadline)
            .await
        {
            Ok(a) if a["type"] == actions::ALLOW => Ok(()),
            Ok(a) => {
                let code = tree::errno_named(a["error"].as_str().unwrap_or_default())
                    .unwrap_or(libc::EACCES);
                self.outcome(
                    op,
                    path,
                    "model_reject",
                    &format!("answered {}", tree::errno_name(code)),
                );
                Err(code)
            }
            Err(f) => {
                self.outcome(
                    op,
                    path,
                    f.decision(),
                    &format!("{}; answered {}", f.detail(), tree::errno_name(f.errno())),
                );
                Err(f.errno())
            }
        }
    }

    /// A refusal the tree made before the model was asked.
    fn refused(&self, op: &str, path: &str, code: i32) -> i32 {
        self.outcome(
            op,
            path,
            "protocol_refusal",
            &format!("answered {}", tree::errno_name(code)),
        );
        code
    }

    async fn handle(&self, p: Pending, deadline: tokio::time::Instant) {
        let who = p.who;
        match p.job {
            Job::Lookup {
                parent,
                name,
                reply,
            } => match self
                .settle("lookup", Some(&name), who, deadline, |t| {
                    t.lookup(parent, &name)
                })
                .await
            {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Readdir { ino, offset, reply } => match self
                .settle("readdir", None, who, deadline, |t| {
                    t.list(ino).map(|l| (t.parent(ino).unwrap_or(1), l))
                })
                .await
            {
                Ok((parent, entries)) => fill(ino, parent, entries, offset, reply),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Create {
                parent,
                name,
                mode,
                flags,
                reply,
            } => match self
                .new_entry(
                    Kind::File,
                    parent,
                    &name,
                    mode,
                    Some(flags),
                    0,
                    who,
                    deadline,
                )
                .await
            {
                Ok(a) => {
                    lock(&self.tree).opened(a.ino);
                    reply.created(
                        &TTL,
                        &file_attr(&a),
                        Generation(0),
                        FileHandle(0),
                        FopenFlags::empty(),
                    )
                }
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Mknod {
                parent,
                name,
                mode,
                kind,
                rdev,
                reply,
            } => match self
                .new_entry(kind, parent, &name, mode, None, rdev, who, deadline)
                .await
            {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Mkdir {
                parent,
                name,
                mode,
                reply,
            } => match self
                .new_entry(Kind::Dir, parent, &name, mode, None, 0, who, deadline)
                .await
            {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Symlink {
                parent,
                name,
                target,
                reply,
            } => match self.symlink(parent, &name, &target, who, deadline).await {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Unlink {
                parent,
                name,
                reply,
            } => match self.remove(false, parent, &name, who, deadline).await {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Rmdir {
                parent,
                name,
                reply,
            } => match self.remove(true, parent, &name, who, deadline).await {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Rename {
                parent,
                name,
                new_parent,
                new_name,
                no_replace,
                exchange,
                reply,
            } => match self
                .rename(
                    parent, &name, new_parent, &new_name, no_replace, exchange, who, deadline,
                )
                .await
            {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Link {
                ino,
                new_parent,
                new_name,
                reply,
            } => match self.link(ino, new_parent, &new_name, who, deadline).await {
                Ok(a) => reply.entry(&TTL, &file_attr(&a), Generation(0)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Setxattr {
                ino,
                name,
                value,
                mode,
                reply,
            } => match self.setxattr(ino, &name, &value, mode, who, deadline).await {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(xattr_errno(c))),
            },
            Job::Removexattr { ino, name, reply } => {
                match self.removexattr(ino, &name, who, deadline).await {
                    Ok(()) => reply.ok(),
                    Err(c) => reply.error(Errno::from_i32(xattr_errno(c))),
                }
            }
            Job::Fallocate {
                ino,
                offset,
                length,
                how,
                mode,
                reply,
            } => match self
                .fallocate(ino, offset, length, how, mode, who, deadline)
                .await
            {
                Ok(()) => reply.ok(),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Write {
                ino,
                offset,
                data,
                flags,
                reply,
            } => match self.write(ino, offset, &data, flags, who, deadline).await {
                Ok(n) => reply.written(n),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
            Job::Setattr {
                ino,
                size,
                changes,
                reply,
            } => match self.setattr(ino, size, &changes, who, deadline).await {
                Ok(a) => reply.attr(&TTL, &file_attr(&a)),
                Err(c) => reply.error(Errno::from_i32(c)),
            },
        }
    }

    /// create, mknod and mkdir: check, ask, apply.
    #[allow(clippy::too_many_arguments)]
    async fn new_entry(
        &self,
        kind: Kind,
        parent: u64,
        name: &str,
        mode: u32,
        flags: Option<i32>,
        rdev: u32,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Attr, i32> {
        let op = if kind == Kind::Dir { "mkdir" } else { "create" };
        let path = lock(&self.tree).child_path(parent, name);
        if let Err(c) = self
            .settle(op, Some(name), who, deadline, |t| {
                t.check_new_entry(parent, name)
            })
            .await
        {
            return Err(self.refused(op, &path, c));
        }
        let perm = (mode & 0o7777) as u16;
        let mut fields = serde_json::Map::new();
        fields.insert("mode".into(), json!(perm));
        if let Some(f) = flags {
            fields.insert("flags".into(), json!(f));
        }
        if kind != Kind::Dir {
            fields.insert("kind".into(), json!(kind.name()));
        }
        if matches!(kind, Kind::CharDevice | Kind::BlockDevice) {
            fields.insert("rdev".into(), json!(rdev));
        }
        let event_type: &'static EventType = if op == "mkdir" {
            &actions::MKDIR_EVENT
        } else {
            &actions::CREATE_EVENT
        };
        self.decide(op, &path, event_type, fields, who, deadline)
            .await?;
        let applied = {
            let mut t = lock(&self.tree);
            match kind {
                Kind::Dir => t.mkdir(parent, name, perm, who.uid, who.gid),
                Kind::File => t.create(parent, name, perm, who.uid, who.gid),
                _ => t.mknod(parent, name, kind, perm, rdev, who.uid, who.gid),
            }
        };
        self.applied(op, &path, applied)
    }

    /// Report how applying an allowed change went.
    fn applied<T>(&self, op: &str, path: &str, r: tree::Outcome<T>) -> std::result::Result<T, i32> {
        match r {
            Ok(v) => {
                self.outcome(op, path, "model_answer", "applied");
                Ok(v)
            }
            // The tree changed between the check and the answer (another request won).
            Err(Stop::Errno(c)) => Err(self.refused(op, path, c)),
            Err(Stop::Describe(_)) => Err(self.refused(op, path, libc::EIO)),
        }
    }

    async fn symlink(
        &self,
        parent: u64,
        name: &str,
        target: &str,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Attr, i32> {
        let path = lock(&self.tree).child_path(parent, name);
        if let Err(c) = self
            .settle("symlink", Some(name), who, deadline, |t| {
                t.check_symlink(parent, name, target)
            })
            .await
        {
            return Err(self.refused("symlink", &path, c));
        }
        let mut fields = serde_json::Map::new();
        fields.insert("target".into(), json!(target));
        self.decide(
            "symlink",
            &path,
            &actions::SYMLINK_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = lock(&self.tree).symlink(parent, name, target, who.uid, who.gid);
        self.applied("symlink", &path, r)
    }

    async fn remove(
        &self,
        dir: bool,
        parent: u64,
        name: &str,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let op = if dir { "rmdir" } else { "unlink" };
        let path = lock(&self.tree).child_path(parent, name);
        let ino = match self
            .settle(op, Some(name), who, deadline, |t| {
                if dir {
                    t.check_rmdir(parent, name)
                } else {
                    t.check_unlink(parent, name)
                }
            })
            .await
        {
            Ok(ino) => ino,
            Err(c) => return Err(self.refused(op, &path, c)),
        };
        let mut fields = serde_json::Map::new();
        let event_type: &'static EventType = if dir {
            &actions::RMDIR_EVENT
        } else {
            let (kind, links) = {
                let t = lock(&self.tree);
                (
                    t.kind(ino).unwrap_or(Kind::File),
                    t.attr(ino).map_or(1, |a| a.nlink),
                )
            };
            fields.insert("kind".into(), json!(kind.name()));
            fields.insert("links".into(), json!(links));
            &actions::UNLINK_EVENT
        };
        self.decide(op, &path, event_type, fields, who, deadline)
            .await?;
        let r = {
            let mut t = lock(&self.tree);
            if dir {
                t.rmdir(parent, name)
            } else {
                t.unlink(parent, name)
            }
        };
        self.applied(op, &path, r)
    }

    #[allow(clippy::too_many_arguments)]
    async fn rename(
        &self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        no_replace: bool,
        exchange: bool,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let (path, new_path) = {
            let t = lock(&self.tree);
            (
                t.child_path(parent, name),
                t.child_path(new_parent, new_name),
            )
        };
        let replaces = match self
            .settle("rename", Some(name), who, deadline, |t| {
                if exchange {
                    t.check_exchange(parent, name, new_parent, new_name)
                        .map(|_| false)
                } else {
                    t.check_rename(parent, name, new_parent, new_name, no_replace)
                        .map(|r| r.is_some())
                }
            })
            .await
        {
            Ok(r) => r,
            Err(c) => return Err(self.refused("rename", &path, c)),
        };
        let kind = {
            let t = lock(&self.tree);
            t.lookup(parent, name)
                .map(|a| a.kind.name())
                .unwrap_or("file")
        };
        let mut fields = serde_json::Map::new();
        fields.insert("new_path".into(), json!(new_path));
        fields.insert("kind".into(), json!(kind));
        fields.insert("replaces".into(), json!(replaces));
        fields.insert("exchange".into(), json!(exchange));
        self.decide(
            "rename",
            &path,
            &actions::RENAME_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = {
            let mut t = lock(&self.tree);
            if exchange {
                t.exchange(parent, name, new_parent, new_name)
            } else {
                t.rename(parent, name, new_parent, new_name, no_replace)
            }
        };
        self.applied("rename", &path, r)
    }

    async fn link(
        &self,
        ino: u64,
        new_parent: u64,
        new_name: &str,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Attr, i32> {
        let path = lock(&self.tree).child_path(new_parent, new_name);
        if let Err(c) = self
            .settle("link", Some(new_name), who, deadline, |t| {
                t.check_link(ino, new_parent, new_name)
            })
            .await
        {
            return Err(self.refused("link", &path, c));
        }
        let (existing, kind, links) = {
            let t = lock(&self.tree);
            let a = t.attr(ino);
            (
                t.path(ino),
                a.as_ref().map_or(Kind::File, |a| a.kind),
                a.map_or(0, |a| a.nlink),
            )
        };
        let mut fields = serde_json::Map::new();
        fields.insert("existing_path".into(), json!(existing));
        fields.insert("kind".into(), json!(kind.name()));
        fields.insert("links".into(), json!(links));
        self.decide("link", &path, &actions::LINK_EVENT, fields, who, deadline)
            .await?;
        let r = lock(&self.tree).link(ino, new_parent, new_name);
        self.applied("link", &path, r)
    }

    #[allow(clippy::too_many_arguments)]
    async fn setxattr(
        &self,
        ino: u64,
        name: &str,
        value: &[u8],
        mode: XattrMode,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let (path, check) = {
            let t = lock(&self.tree);
            (t.path(ino), t.check_setxattr(ino, name, value.len(), mode))
        };
        let replaces = match check {
            Ok(r) => r,
            Err(Stop::Errno(c)) => return Err(self.refused("setxattr", &path, c)),
            Err(Stop::Describe(_)) => return Err(self.refused("setxattr", &path, libc::EIO)),
        };
        let (shown, encoding, truncated) = preview(value);
        let mut fields = serde_json::Map::new();
        fields.insert("name".into(), json!(name));
        fields.insert("value".into(), json!(shown));
        fields.insert("encoding".into(), json!(encoding));
        fields.insert("value_truncated".into(), json!(truncated));
        fields.insert("length".into(), json!(value.len()));
        fields.insert("mode".into(), json!(mode.name()));
        fields.insert("replaces".into(), json!(replaces));
        self.decide(
            "setxattr",
            &path,
            &actions::SETXATTR_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = lock(&self.tree).setxattr(ino, name, value, mode);
        self.applied("setxattr", &path, r)
    }

    async fn removexattr(
        &self,
        ino: u64,
        name: &str,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let (path, check) = {
            let t = lock(&self.tree);
            (t.path(ino), t.check_removexattr(ino, name))
        };
        match check {
            Ok(()) => {}
            Err(Stop::Errno(c)) => return Err(self.refused("removexattr", &path, c)),
            Err(Stop::Describe(_)) => return Err(self.refused("removexattr", &path, libc::EIO)),
        }
        let mut fields = serde_json::Map::new();
        fields.insert("name".into(), json!(name));
        self.decide(
            "removexattr",
            &path,
            &actions::REMOVEXATTR_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = lock(&self.tree).removexattr(ino, name);
        self.applied("removexattr", &path, r)
    }

    #[allow(clippy::too_many_arguments)]
    async fn fallocate(
        &self,
        ino: u64,
        offset: u64,
        length: u64,
        how: Allocation,
        mode: i32,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), i32> {
        let (path, size_before, check) = {
            let t = lock(&self.tree);
            (
                t.path(ino),
                t.size(ino).unwrap_or(0),
                t.check_fallocate(ino, offset, length, how),
            )
        };
        match check {
            Ok(_) => {}
            Err(Stop::Errno(c)) => return Err(self.refused("fallocate", &path, c)),
            Err(Stop::Describe(_)) => return Err(self.refused("fallocate", &path, libc::EIO)),
        }
        let mut fields = serde_json::Map::new();
        fields.insert("offset".into(), json!(offset));
        fields.insert("length".into(), json!(length));
        fields.insert("operation".into(), json!(how.name()));
        fields.insert("keep_size".into(), json!(how.keep_size()));
        fields.insert("mode".into(), json!(mode));
        fields.insert("size_before".into(), json!(size_before));
        self.decide(
            "fallocate",
            &path,
            &actions::FALLOCATE_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = lock(&self.tree).fallocate(ino, offset, length, how);
        self.applied("fallocate", &path, r)
    }

    async fn write(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
        flags: i32,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<u32, i32> {
        let (path, size_before, check) = {
            let t = lock(&self.tree);
            (
                t.path(ino),
                t.size(ino).unwrap_or(0),
                t.check_write(ino, offset, data.len()),
            )
        };
        if let Err(Stop::Errno(c)) = check {
            return Err(self.refused("write", &path, c));
        }
        let (shown, encoding, truncated) = preview(data);
        let mut fields = serde_json::Map::new();
        fields.insert("offset".into(), json!(offset));
        fields.insert("length".into(), json!(data.len()));
        fields.insert("size_before".into(), json!(size_before));
        fields.insert("data".into(), json!(shown));
        fields.insert("encoding".into(), json!(encoding));
        fields.insert("data_truncated".into(), json!(truncated));
        fields.insert("flags".into(), json!(flags));
        self.decide("write", &path, &actions::WRITE_EVENT, fields, who, deadline)
            .await?;
        let r = lock(&self.tree).write(ino, offset, data);
        self.applied("write", &path, r)
    }

    async fn setattr(
        &self,
        ino: u64,
        size: Option<u64>,
        changes: &Changes,
        who: Who,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Attr, i32> {
        let (path, size_before, check) = {
            let t = lock(&self.tree);
            let check = match (t.attr(ino), size) {
                (None, _) => Err(Stop::Errno(libc::ENOENT)),
                (Some(_), Some(s)) => t.check_truncate(ino, s),
                (Some(_), None) => Ok(()),
            };
            (t.path(ino), t.size(ino).unwrap_or(0), check)
        };
        let op = if size.is_some() {
            "truncate"
        } else {
            "setattr"
        };
        if let Err(Stop::Errno(c)) = check {
            return Err(self.refused(op, &path, c));
        }
        let mut fields = serde_json::Map::new();
        let event_type: &'static EventType = match size {
            Some(s) => {
                fields.insert("size".into(), json!(s));
                fields.insert("size_before".into(), json!(size_before));
                &actions::TRUNCATE_EVENT
            }
            None => &actions::SETATTR_EVENT,
        };
        if let Some(m) = changes.perm {
            fields.insert("mode".into(), json!(m));
        }
        if let Some(u) = changes.uid {
            fields.insert("owner_uid".into(), json!(u));
        }
        if let Some(g) = changes.gid {
            fields.insert("owner_gid".into(), json!(g));
        }
        if let Some(t) = changes.atime {
            fields.insert("atime".into(), json!(unix_secs(t)));
        }
        if let Some(t) = changes.mtime {
            fields.insert("mtime".into(), json!(unix_secs(t)));
        }
        self.decide(op, &path, event_type, fields, who, deadline)
            .await?;
        let r = {
            let mut t = lock(&self.tree);
            match size {
                Some(s) => t.truncate(ino, s).and_then(|_| t.setattr(ino, changes)),
                None => t.setattr(ino, changes),
            }
        };
        self.applied(op, &path, r)
    }
}

// ------------------------------------------------------------------ spawn

/// Register the mount as the server's one connection, so the core keeps the history the
/// protocol declares and the dashboard shows a peer row. A mount has no addresses; both are
/// the `127.0.0.1:0` placeholder the other local servers use.
async fn register_session(ctx: &SpawnContext, mount_point: &Path) -> ConnectionId {
    let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    ctx.state
        .add_connection_to_server(
            ctx.server_id,
            ConnectionState {
                id,
                remote_addr: addr,
                local_addr: addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(json!({
                    "mount_point": mount_point.to_string_lossy(),
                    "peer": "the kernel's FUSE driver",
                })),
            },
        )
        .await;
    id
}

/// Whether the mount point is now the root of a different filesystem than its parent.
fn mount_is_live(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(m), Some(parent)) = (std::fs::metadata(p), p.parent()) else {
        return false;
    };
    std::fs::metadata(parent).is_ok_and(|pm| pm.dev() != m.dev())
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let s = settings(&ctx)?;
    backend::preflight()?;
    let created_dir = prepare_mount_point(&s.mount_point)?;
    let mount_point = s.mount_point.canonicalize()?;
    let label = sanitize::token(&mount_point.to_string_lossy(), 256);
    // SAFETY: geteuid/getegid have no preconditions.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let tree = Arc::new(Mutex::new(Tree::new(0o755, uid, gid, s.max_overlay)));
    let (tx, rx) = mpsc::channel(MAX_PENDING);

    let fs = FuseFs {
        tree: tree.clone(),
        queue: tx,
        read_only: s.read_only,
        status_tx: ctx.status_tx.clone(),
        mount_label: label.clone(),
        sidecars: Mutex::new(appledouble::Sidecars::new()),
    };
    let mount = backend::start(
        &mount_point,
        s.read_only,
        s.allow_other,
        fs,
        &label,
        &ctx.status_tx,
    )
    .await;
    let mount = match mount {
        Ok(m) => m,
        Err(e) => {
            if created_dir {
                let _ = std::fs::remove_dir(&mount_point);
            }
            return Err(e);
        }
    };
    let guard = MountGuard {
        mount_point: mount_point.clone(),
        created_dir,
        mount: Some(mount),
        status_tx: ctx.status_tx.clone(),
    };

    let mp = mount_point.clone();
    let live = tokio::time::timeout(
        MOUNT_TIMEOUT,
        tokio::task::spawn_blocking(move || mount_is_live(&mp)),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(false);
    ensure!(
        live && is_fuse_mounted(&mount_point),
        "the FUSE mount at {} did not come up",
        mount_point.display()
    );

    let connection = register_session(&ctx, &mount_point).await;
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "FUSE mounted at {}{}",
        mount_point.display(),
        if s.read_only { " (read-only)" } else { "" }
    ));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let worker = Worker {
        ctx: Arc::new(ctx),
        tree,
        connection,
        label,
        timeout: s.timeout,
    };
    state
        .spawn_server_task(server_id, worker.run(rx, guard))
        .await;
    Ok(([127, 0, 0, 1], 0).into())
}
