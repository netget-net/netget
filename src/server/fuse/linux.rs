//! The Linux backend: `/dev/fuse` mounted by the setuid `fusermount3` helper, as libfuse does
//! it, with fuser speaking the kernel protocol on the descriptor it hands back.
use super::{session_config, FuseFs, MOUNT_TIMEOUT};
use crate::logging::emit::Log;
use crate::utils::sanitize;
use anyhow::{bail, ensure, Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const FUSERMOUNT: &str = "fusermount3";

/// What `spawn()` checks before it touches the mount point.
pub(super) fn preflight() -> Result<()> {
    ensure!(
        Path::new("/dev/fuse").exists(),
        "/dev/fuse does not exist: load the module (modprobe fuse) and install fuse3 \
         (apt-get install fuse3)"
    );
    Ok(())
}

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

/// Owns the mount: dropping it unmounts, stops the watchdog and closes the auto_unmount socket.
/// `MountGuard` holds it, so `stop_server` aborting the worker task unmounts.
pub(super) struct Mount {
    mount_point: PathBuf,
    watch: Option<UnixStream>,
    helper: Option<Child>,
    watchdog: Option<Child>,
    session: Option<fuser::BackgroundSession>,
}

impl Drop for Mount {
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

/// Mount `fs` at `mount_point` and run fuser's session on it: returns once the kernel's INIT
/// handshake has completed.
pub(super) async fn start(
    mount_point: &Path,
    read_only: bool,
    allow_other: bool,
    fs: FuseFs,
    label: &str,
    status_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<Mount> {
    let mut options = String::from("fsname=netget,subtype=netget,default_permissions,auto_unmount");
    if read_only {
        options.push_str(",ro");
    }
    if allow_other {
        options.push_str(",allow_other");
    }
    let mp = mount_point.to_path_buf();
    let mounted = tokio::task::spawn_blocking(move || mount(&mp, &options))
        .await
        .context("the mount task failed")??;
    let mut m = Mount {
        mount_point: mount_point.to_path_buf(),
        watch: Some(mounted.watch),
        helper: Some(mounted.helper),
        watchdog: None,
        session: None,
    };

    match spawn_watchdog(mount_point) {
        Ok(w) => m.watchdog = Some(w),
        Err(e) => Log::new(Some(status_tx)).warn(format!(
            "FUSE {label}: no unmount watchdog ({e}); if this process is killed, only \
             fusermount3's auto_unmount (fuse3 3.17 or later) removes the mount"
        )),
    }

    let (acl, config) = session_config(allow_other);
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
    m.session = Some(session);
    Ok(m)
}
