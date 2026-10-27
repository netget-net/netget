//! The association under M3UA: an SCTP one-to-one socket (RFC 4666 section 1.4.1), or the
//! labelled lab TCP transport. Shared by the SGP (`mod.rs`) and the ASP client
//! (`src/client/m3ua`).
//!
//! Once the socket exists it is driven through a `tokio::net::TcpStream` on its descriptor, as
//! the `ngap` transport does. Reading is the M3UA length-delimited stream either way. Writing
//! over SCTP goes through `sendmsg` so each message carries what RFC 4666 section 1.4.7 asks of
//! it, which a plain `write` cannot express:
//!
//! - **PPID 3** (M3UA) on every DATA chunk, in an `SCTP_SNDRCV` control message. Wireshark keys
//!   its M3UA dissector on it; with PPID 0 a capture shows bare SCTP.
//! - **Stream 0 for management** (MGMT, ASPSM, ASPTM, RKM) and **stream 1 for Transfer** (DATA)
//!   where the association negotiated more than one outbound stream; a single-stream association
//!   carries everything on 0.
//! - One `write` is one M3UA message, which is the contract every caller here keeps (and which
//!   the dashboard's peer command task keeps too: one `write_all` per message).
//!
//! The lab transport writes the same octets to a TCP stream. M3UA needs no extra framing on a
//! byte stream because its common header carries the message length.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// IANA protocol number for SCTP; named here because `libc` lacks it where the stack is absent.
pub const IPPROTO_SCTP: i32 = 132;
/// The SCTP payload protocol identifier IANA assigns M3UA (RFC 4666 section 1.4.7).
pub const M3UA_PPID: u32 = 3;
/// The stream Transfer messages use where the association has more than one.
pub const DATA_STREAM: u16 = 1;

/// Open the one-to-one SCTP socket for `addr`, or explain why this host cannot.
pub fn sctp_socket(addr: &SocketAddr, role: &str) -> Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP))).map_err(|e| {
        anyhow!(
            "M3UA {role} cannot open an SCTP socket on this host: {e}. M3UA's transport is SCTP \
             (RFC 4666 section 1.4.1, IANA port 2905) and this operating system has no SCTP \
             stack available to this process — macOS ships neither kernel support nor headers \
             for SCTP, and a Linux kernel without the sctp module fails the same way \
             (`modprobe sctp`). NetGet refuses rather than pretend it is speaking SIGTRAN. \
             Either run on a host with SCTP, or, for local protocol work only, pass the startup \
             parameter transport=\"tcp\" — a NON-STANDARD framing that exercises the M3UA layer \
             and that no real SIGTRAN peer speaks."
        )
    })
}

/// Open an association to an SGP (the ASP side). `sctp` false is the lab TCP transport.
/// `local_port` binds the near end first: SIGTRAN peers are commonly configured with the exact
/// remote port they will accept an association from.
pub async fn connect(
    addr: SocketAddr,
    sctp: bool,
    local_port: Option<u16>,
    deadline: Duration,
) -> Result<TcpStream> {
    let socket = if sctp {
        sctp_socket(&addr, "ASP")?
    } else {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?
    };
    if let Some(port) = local_port {
        let local: SocketAddr = if addr.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, port).into()
        };
        socket.set_reuse_address(true)?;
        socket
            .bind(&local.into())
            .map_err(|e| anyhow!("binding the association's local port {port}: {e}"))?;
    }
    let std_stream = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
        socket
            .connect_timeout(&addr.into(), deadline)
            .map_err(|e| anyhow!("association to {addr} failed: {e}"))?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    })
    .await
    .map_err(|e| anyhow!("SCTP connect task failed: {e}"))??;
    Ok(TcpStream::from_std(std_stream)?)
}

/// Split an association into its reader and its message writer.
pub fn split(stream: TcpStream, sctp: bool) -> (Reader, Writer) {
    // Each message at once: without these the kernel holds a message written straight after
    // another until the peer acknowledges the first (SCTP), or until the first is acknowledged
    // or a segment fills (Nagle, on the lab TCP transport).
    if sctp {
        crate::utils::sctp::set_nodelay(&stream, "M3UA");
    } else {
        let _ = stream.set_nodelay(true);
    }
    let stream = Arc::new(stream);
    (
        Reader {
            stream: stream.clone(),
        },
        Writer { stream, sctp },
    )
}

/// The read side: the association's byte stream.
pub struct Reader {
    stream: Arc<TcpStream>,
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            std::task::ready!(self.stream.poll_read_ready(cx))?;
            match self.stream.try_read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

/// The write side. Each `write` call is one whole M3UA message.
pub struct Writer {
    stream: Arc<TcpStream>,
    sctp: bool,
}

impl Writer {
    /// Half-close: an SCTP SHUTDOWN, or a TCP FIN.
    pub fn close(&self) {
        let _ = socket2::SockRef::from(&*self.stream).shutdown(std::net::Shutdown::Write);
    }
}

/// The stream RFC 4666 section 1.4.7 puts a message on: Transfer off stream 0, the rest on it.
pub fn stream_for(message: &[u8]) -> u16 {
    match super::codec::peek_class_type(message) {
        Some((super::codec::CLASS_TRANSFER, _)) => DATA_STREAM,
        _ => 0,
    }
}

#[cfg(unix)]
fn sctp_send(stream: &TcpStream, message: &[u8], sid: u16) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    // struct sctp_sndrcvinfo (linux/sctp.h): stream, ssn, flags, (pad), ppid, context,
    // timetolive, tsn, cumtsn, assoc_id — 32 octets.
    #[repr(C)]
    struct SndRcvInfo {
        stream: u16,
        ssn: u16,
        flags: u16,
        _pad: u16,
        ppid: u32,
        context: u32,
        timetolive: u32,
        tsn: u32,
        cumtsn: u32,
        assoc_id: i32,
    }
    const SCTP_SNDRCV: i32 = 1;
    let info = SndRcvInfo {
        stream: sid,
        ssn: 0,
        flags: 0,
        _pad: 0,
        // Network byte order (RFC 6458 section 5.3.2).
        ppid: M3UA_PPID.to_be(),
        context: 0,
        timetolive: 0,
        tsn: 0,
        cumtsn: 0,
        assoc_id: 0,
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<SndRcvInfo>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: message.as_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    };
    // SAFETY: msghdr is plain data; its pointers refer to `iov` and `control`, which outlive the
    // sendmsg call, and CMSG_FIRSTHDR/CMSG_DATA stay within `control` because it is CMSG_SPACE
    // bytes long.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = IPPROTO_SCTP;
        (*cmsg).cmsg_type = SCTP_SNDRCV;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<SndRcvInfo>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &info as *const SndRcvInfo as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<SndRcvInfo>(),
        );
        let n = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

#[cfg(not(unix))]
fn sctp_send(_stream: &TcpStream, _message: &[u8], _sid: u16) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "SCTP is not available on this platform",
    ))
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            std::task::ready!(self.stream.poll_write_ready(cx))?;
            let result = if self.sctp {
                let preferred = stream_for(buf);
                let stream = self.stream.clone();
                let mut r = stream.try_io(tokio::io::Interest::WRITABLE, || {
                    sctp_send(&stream, buf, preferred)
                });
                if preferred != 0 && matches!(&r, Err(e) if e.raw_os_error() == Some(libc::EINVAL))
                {
                    // The association negotiated a single outbound stream.
                    r = stream.try_io(tokio::io::Interest::WRITABLE, || sctp_send(&stream, buf, 0));
                }
                r
            } else {
                self.stream.try_write(buf)
            };
            match result {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}
