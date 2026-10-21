//! FUSE local filesystem (Linux): a directory on this machine whose every file operation the
//! model answers. The kernel is the client; there is no network and no NetGet client role.
//!
//! `fusermount3` (setuid) mounts `/dev/fuse` at the mount point with `auto_unmount`, so the
//! mount goes when this process does however it ends; fuser speaks the kernel protocol on the
//! descriptor it hands back. Lookups, getattr, readdir, read and readlink are answered on fuser's
//! thread from the described tree (`src/server/described_tree.rs`). Anything that needs the
//! model — a directory nobody has described yet, or any change — is queued (bounded) for this
//! mount's one worker task, which asks one decision at a time under a deadline and replies to
//! the kernel itself. A request still waiting when the deadline passes is answered EIO, so a
//! process doing I/O on the mount never blocks for longer than `decision_timeout_secs`.
pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::server::described_tree::{self as tree, Attr, Changes, Kind, Stop, Tree};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::sanitize;
use crate::utils::wire_failure::WireFailure;
use anyhow::{bail, ensure, Context, Result};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, SessionACL, TimeOrNow, WriteFlags,
};
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

/// How long a process waits for the model before its system call fails with EIO.
pub const DEFAULT_DECISION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_DECISION_TIMEOUT_SECS: u64 = 600;
/// Requests waiting for the model; past it a request fails with EBUSY at once.
pub const MAX_PENDING: usize = 64;
/// The largest write the kernel may send in one request (its max_write).
pub const MAX_WRITE_BYTES: u32 = 128 * 1024;
/// How long the kernel may cache an entry or attributes.
const TTL: Duration = Duration::from_secs(1);
/// fusermount3 handing back the descriptor, and the kernel's INIT.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of a write shown to the model.
const DATA_PREVIEW: usize = 512;
/// Descriptions one request may need before it can be decided (a rename needs two).
const MAX_DESCRIBES_PER_REQUEST: usize = 4;
const FUSERMOUNT: &str = "fusermount3";

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

/// What fusermount3 hands back: the /dev/fuse descriptor, and (auto_unmount) the socket it
/// watches and the helper itself, which unmounts when the socket closes with the mount dead.
struct Mounted {
    fd: OwnedFd,
    watch: UnixStream,
    helper: Child,
}

/// Receive the descriptor fusermount3 sends over the socket (one byte, SCM_RIGHTS).
fn receive_fd(sock: &UnixStream) -> std::io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    // u64 words keep the control buffer aligned for cmsghdr.
    let mut control = vec![0u64; space.div_ceil(8)];
    // SAFETY: an all-zero msghdr is a valid empty header; the pointers set below outlive the
    // recvmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    loop {
        // SAFETY: msg points at live buffers sized as declared.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n > 0 {
            break;
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fusermount3 closed the socket without sending a descriptor",
            ));
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    // SAFETY: msg was filled by recvmsg; CMSG_FIRSTHDR/CMSG_DATA stay inside `control`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(std::io::Error::other(
                "fusermount3 sent no descriptor (no SCM_RIGHTS message)",
            ));
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
        if fd < 0 {
            return Err(std::io::Error::other(
                "fusermount3 sent an invalid descriptor",
            ));
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Mount through fusermount3, as libfuse does: a socket pair, `_FUSE_COMMFD` naming our end in
/// the helper, and the /dev/fuse descriptor coming back over it. Blocking.
fn mount(mount_point: &Path, options: &str) -> Result<Mounted> {
    let (ours, theirs) = UnixStream::pair()?;
    let theirs_fd = theirs.as_raw_fd();
    let mut cmd = Command::new(FUSERMOUNT);
    cmd.arg("-o")
        .arg(options)
        .arg("--")
        .arg(mount_point)
        .env("_FUSE_COMMFD", theirs_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: only fcntl, which is async-signal-safe, runs between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(theirs_fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(theirs_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut helper = cmd.spawn().with_context(|| {
        format!(
            "running {FUSERMOUNT}: install it with apt-get install fuse3 (Debian/Ubuntu) or dnf \
             install fuse3"
        )
    })?;
    drop(theirs);
    ours.set_read_timeout(Some(MOUNT_TIMEOUT))?;
    match receive_fd(&ours) {
        Ok(fd) => {
            ours.set_read_timeout(None)?;
            // The helper stays to unmount when this process goes; drain what it says.
            if let Some(mut err) = helper.stderr.take() {
                std::thread::spawn(move || {
                    let mut s = String::new();
                    let _ = std::io::Read::read_to_string(&mut err, &mut s);
                    if !s.trim().is_empty() {
                        tracing::debug!("fusermount3: {}", sanitize::multiline(s.trim()));
                    }
                });
            }
            Ok(Mounted {
                fd,
                watch: ours,
                helper,
            })
        }
        Err(e) => {
            drop(ours);
            let out = helper.wait_with_output();
            let said = out
                .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_default();
            bail!(
                "{FUSERMOUNT} could not mount {}: {} ({e})",
                mount_point.display(),
                sanitize::strip_controls(&said)
            )
        }
    }
}

/// `/proc/self/mountinfo` escapes these in a mount point.
fn mountinfo_escape(p: &Path) -> String {
    let mut out = String::new();
    for b in p.as_os_str().as_encoded_bytes() {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.push_str(&format!("\\{b:03o}")),
            _ => out.push(*b as char),
        }
    }
    out
}

/// Whether a FUSE filesystem is mounted at `p` in this process's mount namespace.
pub fn is_fuse_mounted(p: &Path) -> bool {
    let want = mountinfo_escape(p);
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .any(|l| {
            let mut halves = l.splitn(2, " - ");
            let (left, right) = (halves.next().unwrap_or(""), halves.next().unwrap_or(""));
            left.split(' ').nth(4) == Some(want.as_str()) && right.starts_with("fuse")
        })
}

/// fusermount3 -u, and if the mount is busy, a lazy unmount (-z): it leaves the tree at once
/// and goes when the last process using it lets go.
fn unmount(p: &Path) {
    if !is_fuse_mounted(p) {
        return;
    }
    let run = |lazy: bool| {
        let mut c = Command::new(FUSERMOUNT);
        c.arg("-u").arg("-q");
        if lazy {
            c.arg("-z");
        }
        let _ = c
            .arg("--")
            .arg(p)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    run(false);
    if is_fuse_mounted(p) {
        run(true);
    }
}

/// Owns the mount: dropping it unmounts, closes the auto_unmount socket, and removes the mount
/// point if this server created it. Held by the worker task, so `stop_server` aborting that
/// task unmounts.
struct MountGuard {
    mount_point: PathBuf,
    created_dir: bool,
    watch: Option<UnixStream>,
    helper: Option<Child>,
    watchdog: Option<Child>,
    session: Option<fuser::BackgroundSession>,
    status_tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        unmount(&self.mount_point);
        // Stopped on purpose: the watchdog's job is done, and killing it before its pipe closes
        // keeps it from unmounting whatever is at this path later.
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.kill();
            std::thread::spawn(move || {
                let _ = watchdog.wait();
            });
        }
        drop(self.watch.take());
        if let Some(mut helper) = self.helper.take() {
            // It exits once it sees the socket close; reap it without waiting here.
            std::thread::spawn(move || {
                let _ = helper.wait();
            });
        }
        // The session thread ends by itself when the kernel ends the connection.
        drop(self.session.take());
        if self.created_dir {
            let _ = std::fs::remove_dir(&self.mount_point);
        }
        Log::new(Some(&self.status_tx))
            .info(format!("FUSE unmounted {}", self.mount_point.display()));
    }
}

/// A process in a session of its own that lazily unmounts `mount_point` when this process is
/// gone, however it went.
///
/// fusermount3's `auto_unmount` is meant to do this, and on fuse3 3.17 and later it does. Before
/// that (Ubuntu 24.04 ships 3.14) its check runs as root and opens the mount point to see
/// whether the daemon died; a mount made without `allow_other` refuses root with EACCES rather
/// than answering ENOTCONN, so the check concludes the daemon is alive and leaves the dead
/// mount behind. The watchdog runs as this user, who owns the mount: `sh` blocks reading a pipe
/// whose only writer is this process, the read returns at end of file when this process is gone
/// (SIGKILL included, since the kernel closes the descriptor), and it execs `fusermount3 -u -z`.
/// A normal stop unmounts first and then kills the watchdog before closing the pipe.
fn spawn_watchdog(mount_point: &Path) -> std::io::Result<Child> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("read -r _ || true; exec fusermount3 -u -q -z -- \"$1\"")
        .arg("netget-fuse-watchdog")
        .arg(mount_point)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only setsid, which is async-signal-safe, runs between fork and exec. A session
    // of its own keeps a terminal's Ctrl+C or a kill of this process group from reaching it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
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
            | Job::Symlink { reply, .. } => reply.error(e),
            Job::Readdir { reply, .. } => reply.error(e),
            Job::Create { reply, .. } => reply.error(e),
            Job::Unlink { reply, .. } | Job::Rmdir { reply, .. } | Job::Rename { reply, .. } => {
                reply.error(e)
            }
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
        let kind = match mode & libc::S_IFMT {
            libc::S_IFREG => Kind::File,
            libc::S_IFIFO => Kind::Fifo,
            libc::S_IFSOCK => Kind::Socket,
            libc::S_IFCHR => Kind::CharDevice,
            libc::S_IFBLK => Kind::BlockDevice,
            _ => return reply.error(Errno::EINVAL),
        };
        if self.read_only {
            return reply.error(self.refuse_read_only("create"));
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
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return reply.error(Errno::EINVAL);
        }
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
                no_replace: flags.contains(RenameFlags::RENAME_NOREPLACE),
                reply,
            },
        );
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Hard links: not implemented (every node has one parent and one name).
        reply.error(Errno::EPERM);
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
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
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::from_i32(libc::ENOTSUP));
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::from_i32(libc::ENODATA));
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::from_i32(libc::ENODATA));
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
    .chain(entries);
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
                reply,
            } => match self
                .rename(
                    parent, &name, new_parent, &new_name, no_replace, who, deadline,
                )
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
            let kind = lock(&self.tree).kind(ino).unwrap_or(Kind::File);
            fields.insert("kind".into(), json!(kind.name()));
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
                t.check_rename(parent, name, new_parent, new_name, no_replace)
            })
            .await
        {
            Ok(r) => r.is_some(),
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
        self.decide(
            "rename",
            &path,
            &actions::RENAME_EVENT,
            fields,
            who,
            deadline,
        )
        .await?;
        let r = lock(&self.tree).rename(parent, name, new_parent, new_name, no_replace);
        self.applied("rename", &path, r)
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
    ensure!(
        Path::new("/dev/fuse").exists(),
        "/dev/fuse does not exist: load the module (modprobe fuse) and install fuse3 \
         (apt-get install fuse3)"
    );
    let created_dir = prepare_mount_point(&s.mount_point)?;
    let mount_point = s.mount_point.canonicalize()?;
    let label = sanitize::token(&mount_point.to_string_lossy(), 256);
    // SAFETY: geteuid/getegid have no preconditions.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let tree = Arc::new(Mutex::new(Tree::new(0o755, uid, gid, s.max_overlay)));
    let (tx, rx) = mpsc::channel(MAX_PENDING);

    let mut options = String::from("fsname=netget,subtype=netget,default_permissions,auto_unmount");
    if s.read_only {
        options.push_str(",ro");
    }
    if s.allow_other {
        options.push_str(",allow_other");
    }
    let mp = mount_point.clone();
    let mounted = tokio::task::spawn_blocking(move || mount(&mp, &options))
        .await
        .context("the mount task failed")?;
    let mounted = match mounted {
        Ok(m) => m,
        Err(e) => {
            if created_dir {
                let _ = std::fs::remove_dir(&mount_point);
            }
            return Err(e);
        }
    };
    let mut guard = MountGuard {
        mount_point: mount_point.clone(),
        created_dir,
        watch: Some(mounted.watch),
        helper: Some(mounted.helper),
        watchdog: None,
        session: None,
        status_tx: ctx.status_tx.clone(),
    };

    match spawn_watchdog(&mount_point) {
        Ok(w) => guard.watchdog = Some(w),
        Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
            "FUSE {label}: no unmount watchdog ({e}); if this process is killed, only \
             fusermount3's auto_unmount (fuse3 3.17 or later) removes the mount"
        )),
    }

    let fs = FuseFs {
        tree: tree.clone(),
        queue: tx,
        read_only: s.read_only,
        status_tx: ctx.status_tx.clone(),
        mount_label: label.clone(),
    };
    let acl = if s.allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    let mut config = fuser::Config::default();
    config.n_threads = Some(1);
    let fd = mounted.fd;
    // The INIT handshake: the kernel sends it as soon as the mount exists.
    let session = tokio::time::timeout(
        MOUNT_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            fuser::Session::from_fd(fs, fd, acl, config).and_then(|s| s.spawn())
        }),
    )
    .await
    .context("the kernel did not start the FUSE session within 30 s")?
    .context("the FUSE session task failed")?
    .context("the FUSE session handshake failed")?;
    guard.session = Some(session);

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
