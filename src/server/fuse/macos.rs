//! The macOS backend: FUSE-T, found and started at runtime and never linked.
//!
//! FUSE-T has no kernel extension. Its `go-nfsv4` serves the mount point to macOS's own NFSv4
//! client over loopback TCP and turns every NFS call into FUSE requests, which it sends to the
//! daemon over a stream socket in the FUSE wire format — the libfuse2 profile of it (ABI 7.19
//! with macFUSE's extra fields), which is what fuser speaks on macOS. So NetGet does here what
//! FUSE-T's own Go libraries (its forks of go-fuse, jacobsa/fuse and bazil.org/fuse) do, and
//! what its libfuse does inside `fuse_kern_mount`: two socket pairs, `go-nfsv4` started in a
//! session of its own with `_FUSE_COMMFD` (the request stream), `_FUSE_MONFD` (the control
//! socket) and `_FUSE_COMMVERS=2`, then `mount` written on the control socket, after which
//! `go-nfsv4` sends FUSE_INIT, mounts NFS at the mount point and answers a 32-bit status.
//! `unmount` on the same socket makes it run `umount -f` and close the stream.
//!
//! FUSE-T's libfuse is not used, though it is libfuse3-compatible: its Darwin mount code keeps
//! the helper's pid and control socket in process-wide statics, so a second mount in one process
//! overwrites the first's and stopping one tears down the other's control socket, and it forks
//! a multi-threaded process and calls `setenv` and `freopen` before `exec`. NetGet runs any
//! number of mounts in one process, so it starts the helper itself, one per mount.
//!
//! **The relay.** fuser reads requests with one `read(2)` each, which is what `/dev/fuse`
//! guarantees; a stream socket does not, so two requests can arrive in one read or one across
//! two. Three threads per mount keep fuser on the guarantee it was written for: one reads each
//! request off the stream (its 40-byte header, then the length the header gives) and hands it
//! to fuser as one datagram over a `SOCK_DGRAM` pair; one takes each reply datagram fuser
//! writes and queues it; one writes the queue to the stream. The middle one never blocks on
//! anything but its read, because macOS answers a send to a full Unix datagram socket with
//! ENOBUFS rather than waiting — a reply fuser could not send would be lost and its NFS call
//! would never be answered. The relay also edits one thing: the INIT reply's flags, from which
//! it clears case-insensitivity, volume rename and extended times. fuser asks for all three on
//! macOS unconditionally; the tree is case-sensitive and implements neither of the others.
//!
//! **Stopping.** `unmount` on the control socket, the mount table watched until it is gone,
//! `umount -f` and `diskutil unmount force` if it is not, then the relay shut down, which ends
//! fuser's session thread. **A killed process.** `go-nfsv4` notices its stream closing and
//! runs `umount -f` itself, but that was measured to fail ("exit status 1") while the NFS
//! client still had a call in flight, after which `go-nfsv4` exits anyway and leaves an NFS
//! mount whose server is gone — `ls` of it hangs. So, as on Linux, a watchdog in a session of
//! its own blocks reading a pipe only this process writes, and at end of file unmounts the
//! mount point (forcibly, retrying for 30 s) until the mount table no longer lists it.
use super::{session_config, FuseFs, MAX_WRITE_BYTES, MOUNT_TIMEOUT};
use crate::logging::emit::Log;
use anyhow::{bail, ensure, Context, Result};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Names the FUSE-T server instead of [`SERVER_DEFAULT`], as it does for FUSE-T's own libraries.
pub const SERVER_ENV: &str = "FUSE_NFSSRV_PATH";
/// Where the FUSE-T cask links its NFS server.
pub const SERVER_DEFAULT: &str = "/usr/local/bin/go-nfsv4";
/// What to do when it is missing.
pub const INSTALL_HINT: &str = "install FUSE-T: brew install --cask macos-fuse-t/cask/fuse-t";
/// What the mount is called (`fuse-t:/netget` in the mount table, the volume name in Finder).
const VOLUME_NAME: &str = "netget";
/// A FUSE request's fixed header.
const IN_HEADER: usize = 40;
/// A FUSE reply's fixed header.
const OUT_HEADER: usize = 16;
/// The largest request relayed to fuser. A write is at most `MAX_WRITE_BYTES` plus its
/// headers; anything larger (a big extended attribute value) is answered E2BIG by the relay.
const MAX_MESSAGE: usize = 1024 * 1024;
/// Socket buffers on both pairs: room for many requests and replies in flight. macOS caps a
/// socket buffer a little under `kern.ipc.maxsockbuf` (8 MiB).
const SOCKET_BUFFER: libc::c_int = 4 * 1024 * 1024;
/// How long a stop waits for FUSE-T's own unmount before forcing it.
const UNMOUNT_WAIT: Duration = Duration::from_secs(10);
const FUSE_INIT: u32 = 26;
/// INIT flags (macFUSE's numbering) fuser requests on macOS that this filesystem must not
/// claim: case-insensitive names, volume rename and extended times.
const INIT_FLAGS_REFUSED: u32 = (1 << 29) | (1 << 30) | (1 << 31);

/// The FUSE-T NFS server this process would start: `FUSE_NFSSRV_PATH`, else
/// `/usr/local/bin/go-nfsv4`.
pub fn server_path() -> PathBuf {
    crate::protocol::dependencies::program_path(SERVER_DEFAULT, Some(SERVER_ENV))
}

/// FUSE-T as a runtime dependency: the startup gate refuses a start without it, naming the cask.
pub const DEPENDENCY: crate::protocol::dependencies::ProtocolDependency =
    crate::protocol::dependencies::ProtocolDependency::ProgramAt {
        path: SERVER_DEFAULT,
        env: Some(SERVER_ENV),
    };

/// Whether FUSE-T's server is installed where this process will look for it.
pub fn fuse_t_installed() -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(server_path())
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// What `spawn()` checks before it touches the mount point.
pub(super) fn preflight() -> Result<()> {
    ensure!(
        fuse_t_installed(),
        "FUSE-T is not installed ({} is not an executable file): {INSTALL_HINT}",
        server_path().display()
    );
    Ok(())
}

fn c_chars(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Every mount in the table as (mounted on, mounted from, type), without waiting on any of
/// them: `MNT_NOWAIT` answers from what the kernel has, so a dead NFS mount cannot hang it.
fn mount_table() -> Vec<(String, String, String)> {
    // SAFETY: a null buffer asks only for the count.
    let n = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if n < 0 {
        return Vec::new();
    }
    let cap = n as usize + 16;
    // SAFETY: statfs is plain data, valid when zeroed.
    let mut buf: Vec<libc::statfs> = vec![unsafe { std::mem::zeroed() }; cap];
    let bytes = (cap * std::mem::size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: the buffer holds `cap` entries and `bytes` says so.
    let got = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    if got < 0 {
        return Vec::new();
    }
    buf.truncate(got as usize);
    buf.iter()
        .map(|s| {
            (
                c_chars(&s.f_mntonname),
                c_chars(&s.f_mntfromname),
                c_chars(&s.f_fstypename),
            )
        })
        .collect()
}

/// The path the mount table uses for `p`: its parent resolved (`/tmp` is `/private/tmp`), its
/// own name as given. The mount point itself is never resolved, because resolving it would
/// stat it, and a dead NFS mount does not answer a stat.
fn table_path(p: &Path) -> String {
    let resolved = match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map(|d| d.join(name))
            .unwrap_or_else(|_| p.to_path_buf()),
        _ => p.to_path_buf(),
    };
    resolved.to_string_lossy().into_owned()
}

/// Whether a FUSE-T filesystem is mounted at `p`, from the mount table.
pub fn is_fuse_mounted(p: &Path) -> bool {
    let want = table_path(p);
    mount_table()
        .iter()
        .any(|(on, from, kind)| *on == want && kind == "nfs" && from.starts_with("fuse-t:"))
}

/// Whether anything at all is mounted at `p`.
fn anything_mounted(p: &Path) -> bool {
    let want = table_path(p);
    mount_table().iter().any(|(on, _, _)| *on == want)
}

fn set_buffers(fd: impl AsFd) {
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: a valid descriptor and a c_int option value of the declared size.
        unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                (&SOCKET_BUFFER as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

// ------------------------------------------------------------------ the relay

/// Duplicates of the stream and of both datagram sockets. Shutting a socket down through any of
/// its descriptors wakes a thread blocked reading it through another; a Unix datagram socket
/// whose peer closes does not wake (measured), so every socket is shut down explicitly.
struct Sockets {
    ended: AtomicBool,
    stream: OwnedFd,
    fuser_side: OwnedFd,
    relay_side: OwnedFd,
}

impl Sockets {
    /// End the relay: every blocked read returns, the writer's queue closes, and fuser's
    /// session thread ends at the zero-length read this gives it.
    fn shutdown(&self) {
        self.ended.store(true, Ordering::SeqCst);
        for fd in [&self.stream, &self.fuser_side, &self.relay_side] {
            // SAFETY: shutting down a socket we hold; an error (already shut) is of no interest.
            unsafe {
                libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR);
            }
        }
    }
}

/// The three relay threads; dropping this does not stop them, `shutdown` does, and so does
/// either end closing.
struct Relay {
    sockets: Arc<Sockets>,
}

impl Relay {
    fn start(
        stream: UnixStream,
        relay_side: UnixDatagram,
        fuser_side: &UnixDatagram,
    ) -> Result<Self> {
        let sockets = Arc::new(Sockets {
            ended: AtomicBool::new(false),
            stream: stream.as_fd().try_clone_to_owned()?,
            fuser_side: fuser_side.as_fd().try_clone_to_owned()?,
            relay_side: relay_side.as_fd().try_clone_to_owned()?,
        });
        let init_unique = Arc::new(AtomicU64::new(u64::MAX));
        let (queue_tx, queue_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        // FUSE-T → fuser: one datagram per request.
        let mut reader = stream.try_clone()?;
        let to_fuser = relay_side.try_clone()?;
        let refusals = queue_tx.clone();
        let (s, init) = (sockets.clone(), init_unique.clone());
        std::thread::Builder::new()
            .name("fuse-t-requests".into())
            .spawn(move || {
                relay_requests(&mut reader, &to_fuser, &refusals, &init, &s.ended);
                s.shutdown();
            })?;

        // fuser → queue: drained as fast as fuser writes, so its sends never find the buffer
        // full.
        let s = sockets.clone();
        std::thread::Builder::new()
            .name("fuse-t-replies".into())
            .spawn(move || {
                // One byte more than any reply may be, so a datagram cut short by the buffer
                // is seen rather than relayed truncated.
                let mut buf = vec![0u8; MAX_MESSAGE + 1];
                loop {
                    let n = match relay_side.recv(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) if n > MAX_MESSAGE => {
                            tracing::error!(
                                "fuser wrote a reply larger than {MAX_MESSAGE} bytes; ending \
                                 the FUSE-T session"
                            );
                            break;
                        }
                        Ok(n) => n,
                    };
                    let mut reply = buf[..n].to_vec();
                    let init = init_unique.load(Ordering::SeqCst);
                    patch_init_reply(&mut reply, init);
                    trim_init_reply(&mut reply, init);
                    if queue_tx.send(reply).is_err() {
                        break;
                    }
                }
                s.shutdown();
            })?;

        // queue → FUSE-T.
        let mut writer = stream;
        let s = sockets.clone();
        std::thread::Builder::new()
            .name("fuse-t-writer".into())
            .spawn(move || {
                while let Ok(reply) = queue_rx.recv() {
                    if writer.write_all(&reply).is_err() {
                        break;
                    }
                }
                s.shutdown();
            })?;
        Ok(Relay { sockets })
    }

    fn shutdown(&self) {
        self.sockets.shutdown();
    }
}

/// Read requests off FUSE-T's stream until it ends; each goes to fuser as one datagram. A
/// request too large to relay is answered E2BIG here.
fn relay_requests(
    stream: &mut UnixStream,
    to_fuser: &UnixDatagram,
    replies: &std::sync::mpsc::Sender<Vec<u8>>,
    init_unique: &AtomicU64,
    ended: &AtomicBool,
) {
    let mut header = [0u8; IN_HEADER];
    loop {
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let len = u32::from_ne_bytes(header[0..4].try_into().unwrap_or_default()) as usize;
        let opcode = u32::from_ne_bytes(header[4..8].try_into().unwrap_or_default());
        let unique = u64::from_ne_bytes(header[8..16].try_into().unwrap_or_default());
        if len < IN_HEADER {
            tracing::error!("FUSE-T sent a request of {len} bytes, shorter than its header");
            return;
        }
        if len > MAX_MESSAGE {
            // Skip the body and refuse the request; the stream stays in step.
            let rest = (len - IN_HEADER) as u64;
            if std::io::copy(&mut Read::take(&mut *stream, rest), &mut std::io::sink()).ok()
                != Some(rest)
            {
                return;
            }
            let mut reply = Vec::with_capacity(OUT_HEADER);
            reply.extend_from_slice(&(OUT_HEADER as u32).to_ne_bytes());
            reply.extend_from_slice(&(-libc::E2BIG).to_ne_bytes());
            reply.extend_from_slice(&unique.to_ne_bytes());
            tracing::warn!(
                "FUSE-T request (opcode {opcode}) of {len} bytes is too large; answered E2BIG"
            );
            if replies.send(reply).is_err() {
                return;
            }
            continue;
        }
        let mut message = vec![0u8; len];
        message[..IN_HEADER].copy_from_slice(&header);
        if stream.read_exact(&mut message[IN_HEADER..]).is_err() {
            return;
        }
        if opcode == FUSE_INIT {
            init_unique.store(unique, Ordering::SeqCst);
        }
        loop {
            match to_fuser.send(&message) {
                Ok(_) => break,
                // fuser's buffer is full: it is busy, not gone. Try again shortly.
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    if ended.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return,
            }
        }
    }
}

/// Clear the INIT flags this filesystem must not claim from fuser's INIT reply.
fn patch_init_reply(reply: &mut [u8], init_unique: u64) {
    // fuse_out_header (len, error, unique), then fuse_init_out (major, minor, max_readahead,
    // flags, ...).
    const FLAGS: usize = OUT_HEADER + 12;
    if reply.len() < FLAGS + 4 {
        return;
    }
    let error = i32::from_ne_bytes(reply[4..8].try_into().unwrap_or_default());
    let unique = u64::from_ne_bytes(reply[8..16].try_into().unwrap_or_default());
    if unique != init_unique || error != 0 {
        return;
    }
    let flags = u32::from_ne_bytes(reply[FLAGS..FLAGS + 4].try_into().unwrap_or_default());
    reply[FLAGS..FLAGS + 4].copy_from_slice(&(flags & !INIT_FLAGS_REFUSED).to_ne_bytes());
}

/// The INIT reply cut to the 24-byte `fuse_init_out` of ABI 7.19, the version fuser declares on
/// macOS. fuser sizes the reply by the version FUSE-T *offers* (7.23, so all 64 bytes), and
/// FUSE-T picks its wire profile from that size: 64 bytes reads as libfuse3, whose structures
/// are Linux's, while fuser lays out macFUSE's (`crtime` and `flags` in every attribute). At 24
/// bytes FUSE-T uses its libfuse2 profile, which is that layout (measured: its log says
/// `profile=v2 client=libfuse2-compatible proto=7.19`).
fn trim_init_reply(reply: &mut Vec<u8>, init_unique: u64) {
    const INIT_OUT_7_19: usize = 24;
    if reply.len() <= OUT_HEADER + INIT_OUT_7_19 {
        return;
    }
    let error = i32::from_ne_bytes(reply[4..8].try_into().unwrap_or_default());
    let unique = u64::from_ne_bytes(reply[8..16].try_into().unwrap_or_default());
    if unique != init_unique || error != 0 {
        return;
    }
    reply.truncate(OUT_HEADER + INIT_OUT_7_19);
    reply[0..4].copy_from_slice(&((OUT_HEADER + INIT_OUT_7_19) as u32).to_ne_bytes());
}

// ------------------------------------------------------------------ mounting

/// Owns the mount: dropping it unmounts, stops the watchdog, the relay and FUSE-T's server.
/// `MountGuard` holds it, so `stop_server` aborting the worker task unmounts.
pub(super) struct Mount {
    mount_point: PathBuf,
    monitor: Option<UnixStream>,
    server: Option<Child>,
    watchdog: Option<Child>,
    relay: Option<Relay>,
    session: Option<fuser::BackgroundSession>,
}

impl Mount {
    /// Ask FUSE-T to unmount, wait for the mount table to agree, and force it if it does not.
    fn unmount(&mut self) {
        if !is_fuse_mounted(&self.mount_point) {
            return;
        }
        if let Some(monitor) = self.monitor.as_mut() {
            let _ = monitor.write_all(b"unmount");
        }
        if wait_unmounted(&self.mount_point, UNMOUNT_WAIT) {
            return;
        }
        tracing::warn!(
            "FUSE-T did not unmount {} within {} s; forcing it",
            self.mount_point.display(),
            UNMOUNT_WAIT.as_secs()
        );
        force_unmount(&self.mount_point);
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        self.unmount();
        // Stopped on purpose: the watchdog's job is done, and killing it before its pipe closes
        // keeps it from unmounting whatever is at this path later.
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.kill();
            let _ = watchdog.wait();
        }
        if let Some(relay) = self.relay.take() {
            relay.shutdown();
        }
        drop(self.monitor.take());
        if let Some(server) = self.server.take() {
            reap(server);
        }
        // fuser's session thread ended with the relay.
        drop(self.session.take());
    }
}

/// Wait for FUSE-T's server to exit (it does once its stream closes), killing it if it has not
/// within a few seconds; on a thread, so a stop never waits for it.
fn reap(mut server: Child) {
    let _ = std::thread::Builder::new()
        .name("fuse-t-reap".into())
        .spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = server.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = server.kill();
            let _ = server.wait();
        });
}

fn wait_unmounted(p: &Path, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if !anything_mounted(p) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `umount -f`, then Disk Arbitration's forced unmount, each with a deadline.
fn force_unmount(p: &Path) {
    let run = |program: &str, args: &[&str]| {
        let child = Command::new(program)
            .args(args)
            .arg(p)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    };
    run("/sbin/umount", &["-f"]);
    if anything_mounted(p) {
        run("/usr/sbin/diskutil", &["unmount", "force"]);
    }
}

/// The watchdog: `sh` in a session of its own, blocked reading a pipe whose only writer is this
/// process. The read returns at end of file when this process is gone (SIGKILL included, since
/// the kernel closes the descriptor), and it unmounts the mount point forcibly, retrying for up
/// to 30 s, until the mount table no longer lists it. A normal stop unmounts first and then
/// kills the watchdog before closing the pipe.
fn spawn_watchdog(mount_point: &Path) -> std::io::Result<Child> {
    const SCRIPT: &str = r#"read -r _ || true
listed() { /sbin/mount | /usr/bin/grep -qF " on $1 ("; }
i=0
while [ $i -lt 30 ] && listed "$1"; do
  /sbin/umount -f "$1" >/dev/null 2>&1
  listed "$1" || exit 0
  /usr/sbin/diskutil unmount force "$1" >/dev/null 2>&1
  listed "$1" || exit 0
  sleep 1
  i=$((i+1))
done"#;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(SCRIPT)
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

/// FUSE-T's log, for an error message: where it is and its last lines about this mount.
pub fn log_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join("Library/Logs/fuse-t/fuse-t.log")
}

fn log_tail(server_pid: Option<u32>) -> String {
    let text = std::fs::read_to_string(log_path()).unwrap_or_default();
    let tag = server_pid.map(|p| format!("pid={p}"));
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| tag.as_ref().is_none_or(|t| l.contains(t.as_str())))
        .collect();
    let tail = lines[lines.len().saturating_sub(5)..].join(" | ");
    crate::utils::sanitize::strip_controls(&tail)
}

/// Mount `fs` at `mount_point` through FUSE-T and run fuser's session on it: returns once FUSE-T
/// has completed the INIT handshake and reported the NFS mount made.
pub(super) async fn start(
    mount_point: &Path,
    read_only: bool,
    allow_other: bool,
    fs: FuseFs,
    label: &str,
    status_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<Mount> {
    let mp = mount_point.to_path_buf();
    let mut m = tokio::task::spawn_blocking(move || mount(&mp, read_only, allow_other, fs))
        .await
        .context("the mount task failed")??;
    match spawn_watchdog(mount_point) {
        Ok(w) => m.watchdog = Some(w),
        Err(e) => Log::new(Some(status_tx)).warn(format!(
            "FUSE {label}: no unmount watchdog ({e}); if this process is killed, only FUSE-T's \
             own unmount removes the mount"
        )),
    }
    Ok(m)
}

/// Start FUSE-T's server on the mount point and fuser on the requests it relays. Blocking, and
/// bounded: every step that waits has `MOUNT_TIMEOUT`, and a failure leaves nothing running.
fn mount(mount_point: &Path, read_only: bool, allow_other: bool, fs: FuseFs) -> Result<Mount> {
    let server_path = server_path();
    let (stream, theirs) = UnixStream::pair()?;
    let (monitor, theirs_monitor) = UnixStream::pair()?;
    set_buffers(&stream);
    set_buffers(&theirs);
    let (fuser_side, relay_side) = UnixDatagram::pair()?;
    set_buffers(&fuser_side);
    set_buffers(&relay_side);

    let (comm_fd, monitor_fd) = (theirs.as_raw_fd(), theirs_monitor.as_raw_fd());
    let mut cmd = Command::new(&server_path);
    // Never --namedattr. It routes every extended-attribute call (and macOS stamps quarantine
    // and provenance attributes on files by itself) through short-lived hidden attribute vnodes
    // in Apple's NFS client, which is what makes its `nfs_vinvalbuf2: ubc_msync failed!, error
    // 22` panic likely (FUSE-T issue #109, Apple FB23527406). It panicked the development Mac
    // within seconds. Without it the NFS client has no xattrs to offer and falls back to
    // AppleDouble `._name` files, which --noappledouble refuses (and `FuseFs` refuses any that
    // get through), so extended attributes are simply unsupported on macOS.
    // --dontbrowse: not a Finder volume, so Finder and Spotlight do not walk it. --rwsize: one
    // NFS read or write is at most one FUSE request of `max_write`.
    cmd.arg("--volname")
        .arg(VOLUME_NAME)
        .arg("--noappledouble")
        .arg("--dontbrowse")
        .arg(format!("--rwsize={MAX_WRITE_BYTES}"));
    if read_only {
        cmd.arg("-r");
    }
    cmd.arg(mount_point)
        .env("_FUSE_COMMFD", comm_fd.to_string())
        .env("_FUSE_MONFD", monitor_fd.to_string())
        .env("_FUSE_COMMVERS", "2")
        .env("_FUSE_CALL_BY_LIB", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Ok(exe) = std::env::current_exe() {
        cmd.env("_FUSE_DAEMON_PATH", exe);
    }
    // SAFETY: only fcntl and setsid, which are async-signal-safe, run between fork and exec.
    // Its own session keeps a Ctrl+C meant for this process from killing the NFS server under
    // a live mount; the stream closing is what tells it this process is gone.
    unsafe {
        cmd.pre_exec(move || {
            for fd in [comm_fd, monitor_fd] {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let server = cmd.spawn().with_context(|| {
        format!(
            "starting FUSE-T's NFS server {}: {INSTALL_HINT}",
            server_path.display()
        )
    })?;
    drop(theirs);
    drop(theirs_monitor);
    let server_pid = server.id();
    let relay = Relay::start(stream, relay_side, &fuser_side)?;
    let mut m = Mount {
        mount_point: mount_point.to_path_buf(),
        monitor: Some(monitor),
        server: Some(server),
        watchdog: None,
        relay: Some(relay),
        session: None,
    };
    let fail = |what: String| -> anyhow::Error {
        anyhow::anyhow!(
            "{what}. FUSE-T's log ({}) says: {}",
            log_path().display(),
            log_tail(Some(server_pid))
        )
    };

    let deadline = Instant::now() + MOUNT_TIMEOUT;
    if let Some(monitor) = m.monitor.as_mut() {
        monitor
            .write_all(b"mount")
            .context("asking FUSE-T to mount")?;
    }

    // The INIT handshake, on a thread of its own so that a FUSE-T that never sends INIT is
    // answered by shutting the relay down (which ends the handshake's read), not by a thread
    // left blocked forever.
    let (acl, config) = session_config(allow_other);
    let fuser_fd: OwnedFd = fuser_side.into();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handshake = std::thread::Builder::new()
        .name("fuse-t-init".into())
        .spawn(move || {
            let r = fuser::Session::from_fd(fs, fuser_fd, acl, config).and_then(|s| s.spawn());
            let _ = done_tx.send(());
            r
        })?;
    let in_time = done_rx.recv_timeout(MOUNT_TIMEOUT).is_ok();
    if !in_time {
        if let Some(relay) = m.relay.as_ref() {
            relay.shutdown();
        }
    }
    let session = handshake
        .join()
        .map_err(|_| anyhow::anyhow!("the FUSE session thread panicked"))?;
    if !in_time {
        bail!(fail(format!(
            "FUSE-T did not start the FUSE session within {} s",
            MOUNT_TIMEOUT.as_secs()
        )));
    }
    m.session = Some(session.map_err(|e| fail(format!("the FUSE session handshake failed: {e}")))?);

    // FUSE-T answers `mount` once the NFS mount is made (or has failed): a 32-bit status.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let mut status = [0u8; 4];
    let answered = match m.monitor.as_mut() {
        Some(monitor) => monitor
            .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
            .and_then(|_| monitor.read_exact(&mut status)),
        None => Err(std::io::ErrorKind::NotConnected.into()),
    };
    if let Err(e) = answered {
        bail!(fail(format!("FUSE-T did not report the mount made ({e})")));
    }
    if let Some(monitor) = m.monitor.as_mut() {
        let _ = monitor.set_read_timeout(None);
    }
    let status = i32::from_ne_bytes(status);
    if status != 0 {
        bail!(fail(format!("FUSE-T could not mount (status {status})")));
    }
    if !is_fuse_mounted(mount_point) {
        bail!(fail(
            "FUSE-T reported the mount made, but the mount table does not list it".into()
        ));
    }
    Ok(m)
}
