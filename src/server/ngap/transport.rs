//! N2 transport: an SCTP association (TS 38.412 section 7), or a non-standard TCP framing for lab
//! use on hosts without SCTP. Shared by the AMF (server) and the gNB (client).
//!
//! # SCTP, the real one
//!
//! The socket is a one-to-one style SCTP socket (`SOCK_STREAM`, `IPPROTO_SCTP`) requested from
//! the kernel through `socket2`. It is a **probe, not a `cfg`**: on macOS, or a Linux kernel
//! without the `sctp` module, `socket(2)` fails and the caller gets an error naming SCTP, TS
//! 38.412 and the lab escape hatch — the `m3ua` precedent. The code below compiles on every unix
//! and type-checks on the machine that cannot run it.
//!
//! An SCTP one-to-one socket presents the TCP socket API, so once it exists it is driven through a
//! `tokio::net::TcpStream` registered on its descriptor. What TCP's API cannot express is done
//! with `sendmsg`/`recvmsg` directly:
//!
//! - **Every message carries PPID 60** (TS 38.412 section 7), in an `SCTP_SNDRCV` control
//!   message. Wireshark keys its NGAP dissector on it, and some stacks check it.
//! - **Non-UE-associated signalling goes on stream 0, UE-associated on stream 1** (TS 38.412
//!   section 7). The writer decides by decoding the PDU it is asked to send; if the association
//!   negotiated a single outbound stream, `sendmsg` refuses stream 1 and the message goes on 0.
//! - **Message boundaries come from `MSG_EOR`**: NGAP has no length field, so a message is exactly
//!   one SCTP user message. A message longer than [`super::codec::MAX_PDU_LEN`] is drained to its
//!   end and reported as [`ReadOutcome::TooLarge`]; the association survives because the next
//!   boundary is still known.
//! - **`SCTP_NODELAY`** on every association. Without it the kernel holds a message back while
//!   an earlier one is unacknowledged, and the peer's delayed SACK makes that 200 ms: measured
//!   against Open5GS, a 5GSM Modification Complete written right after the Modify Response left
//!   208 ms later, and a UL NAS Transport after an Initial Context Setup Response the same. NGAP
//!   signalling is request/response with no batching to win.
//!
//! # `tcp`, the lab one
//!
//! **No real gNB or AMF speaks NGAP over TCP.** NGAP has no framing of its own, so the lab
//! transport prefixes every PDU with a 4-octet big-endian length — a NetGet invention that exists
//! so the layers above the socket can be exercised on macOS. [`Transport::label`] says so
//! wherever the transport is named. A declared length over the bound cannot be skipped safely on
//! a byte stream, so it ends the connection.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};

use super::codec;

/// IANA protocol number for SCTP; named here because `libc` lacks it where the stack is absent.
pub const IPPROTO_SCTP: i32 = 132;
/// Octets of the lab transport's length prefix.
pub const LAB_HEADER_LEN: usize = 4;

/// Which transport an N2 association runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TS 38.412 section 7: SCTP, PPID 60.
    Sctp,
    /// **Non-standard**: a 4-octet length prefix over TCP, for hosts with no SCTP stack.
    Tcp,
}

impl Transport {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sctp" => Ok(Self::Sctp),
            "tcp" => Ok(Self::Tcp),
            other => Err(anyhow!(
                "transport must be \"sctp\" (what TS 38.412 defines for N2) or \"tcp\" \
                 (non-standard length-prefixed framing, for local protocol work only), got {other:?}"
            )),
        }
    }

    pub fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        match params
            .map(|p| p.get_optional_string("transport"))
            .transpose()?
            .flatten()
        {
            Some(s) => Self::parse(&s),
            None => Ok(Self::Sctp),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sctp => "sctp",
            Self::Tcp => "tcp",
        }
    }

    /// How the transport is named wherever an operator or the model can see it. The TCP wording
    /// carries its own warning because this string travels into logs, the dashboard and events.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sctp => "sctp (TS 38.412, PPID 60)",
            Self::Tcp => "tcp (NON-STANDARD length-prefixed lab transport, not N2)",
        }
    }
}

fn no_sctp(role: &str, e: std::io::Error) -> anyhow::Error {
    anyhow!(
        "NGAP {role} cannot open an SCTP socket on this host: {e}. NGAP's transport is SCTP \
         (TS 38.412 section 7, port 38412, PPID 60) and this operating system has no SCTP stack \
         available to this process — macOS ships neither kernel support nor headers for SCTP, and \
         a Linux kernel without the sctp module fails the same way (`modprobe sctp`). NetGet \
         refuses rather than pretend it is speaking N2. Either run on a host with SCTP, or, for \
         local protocol work only, pass the startup parameter transport=\"tcp\" — a NON-STANDARD \
         length-prefixed framing that no real gNB or AMF speaks."
    )
}

fn sctp_socket(addr: &SocketAddr, role: &str) -> Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))
        .map_err(|e| no_sctp(role, e))
}

/// `SCTP_NODELAY` (the option number of linux/sctp.h): send each message at once. Other
/// systems' SCTP stacks number the option differently, and none of them is one this code is run
/// on, so they are left at their default; a failure is logged, never fatal.
#[cfg(target_os = "linux")]
fn set_sctp_nodelay(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    const SCTP_NODELAY: libc::c_int = 3;
    let on: libc::c_int = 1;
    // SAFETY: a valid descriptor, a pointer to a live c_int and its size.
    let r = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            IPPROTO_SCTP,
            SCTP_NODELAY,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        tracing::debug!(
            "NGAP could not set SCTP_NODELAY: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_sctp_nodelay(_stream: &TcpStream) {}

/// Bind the AMF's listening socket.
///
/// Public because the SCTP refusal is a feature with its own test: on a host without SCTP this
/// must fail with a message naming SCTP rather than an errno.
pub async fn bind_listener(addr: SocketAddr, transport: Transport) -> Result<TcpListener> {
    match transport {
        Transport::Tcp => crate::server::socket_helpers::create_reusable_tcp_listener(addr).await,
        Transport::Sctp => {
            let socket = sctp_socket(&addr, "AMF")?;
            socket
                .set_reuse_address(true)
                .map_err(|e| anyhow!("NGAP could not set SO_REUSEADDR on the SCTP socket: {e}"))?;
            socket
                .bind(&addr.into())
                .map_err(|e| anyhow!("NGAP could not bind the SCTP socket to {addr}: {e}"))?;
            socket
                .listen(128)
                .map_err(|e| anyhow!("NGAP could not listen on the SCTP socket at {addr}: {e}"))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| anyhow!("NGAP could not make the SCTP socket non-blocking: {e}"))?;
            let std_listener: std::net::TcpListener = socket.into();
            TcpListener::from_std(std_listener)
                .map_err(|e| anyhow!("NGAP could not register the SCTP listener with tokio: {e}"))
        }
    }
}

/// Open an association to an AMF (the gNB side).
pub async fn connect(addr: SocketAddr, transport: Transport, deadline: Duration) -> Result<Conn> {
    let stream = match transport {
        Transport::Tcp => tokio::time::timeout(deadline, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("no answer from {addr} within {}s", deadline.as_secs()))??,
        Transport::Sctp => {
            let socket = sctp_socket(&addr, "gNB")?;
            let std_stream = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
                socket
                    .connect_timeout(&addr.into(), deadline)
                    .map_err(|e| anyhow!("SCTP association to {addr} failed: {e}"))?;
                socket.set_nonblocking(true)?;
                Ok(socket.into())
            })
            .await
            .map_err(|e| anyhow!("SCTP connect task failed: {e}"))??;
            TcpStream::from_std(std_stream)?
        }
    };
    Ok(Conn::new(stream, transport))
}

/// One established association.
pub struct Conn {
    stream: Arc<TcpStream>,
    transport: Transport,
}

impl Conn {
    pub fn new(stream: TcpStream, transport: Transport) -> Self {
        if transport == Transport::Sctp {
            set_sctp_nodelay(&stream);
        }
        Conn {
            stream: Arc::new(stream),
            transport,
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// The underlying socket, for tests that must put octets on it NetGet's writer would refuse.
    #[doc(hidden)]
    pub fn socket(&self) -> socket2::SockRef<'_> {
        socket2::SockRef::from(&*self.stream)
    }

    pub fn reader(&self) -> MessageReader {
        MessageReader {
            stream: self.stream.clone(),
            transport: self.transport,
        }
    }

    pub fn writer(&self) -> MessageWriter {
        MessageWriter {
            stream: self.stream.clone(),
            transport: self.transport,
            pending: None,
        }
    }
}

/// The result of waiting for one message.
#[derive(Debug)]
pub enum ReadOutcome {
    Message(Vec<u8>),
    /// A message over [`codec::MAX_PDU_LEN`], of this many octets (at least). Over SCTP it was
    /// drained and the association can continue; over the lab transport the framing is lost.
    TooLarge(usize),
    Eof,
    TimedOut,
    Error(String),
}

/// Reads whole NGAP messages.
pub struct MessageReader {
    stream: Arc<TcpStream>,
    transport: Transport,
}

impl MessageReader {
    /// Wait up to `deadline` for the next message to *start* arriving; a message that has begun
    /// is then given the same deadline to finish.
    pub async fn next(&mut self, deadline: Duration) -> ReadOutcome {
        match tokio::time::timeout(deadline, self.next_inner(deadline)).await {
            Ok(o) => o,
            Err(_) => ReadOutcome::TimedOut,
        }
    }

    async fn next_inner(&mut self, _deadline: Duration) -> ReadOutcome {
        match self.transport {
            Transport::Tcp => {
                let mut header = [0u8; LAB_HEADER_LEN];
                match read_exact(&self.stream, &mut header).await {
                    Ok(true) => {}
                    Ok(false) => return ReadOutcome::Eof,
                    Err(e) => return ReadOutcome::Error(e.to_string()),
                }
                let len = u32::from_be_bytes(header) as usize;
                if len > codec::MAX_PDU_LEN {
                    return ReadOutcome::TooLarge(len);
                }
                let mut body = vec![0u8; len];
                match read_exact(&self.stream, &mut body).await {
                    Ok(true) => ReadOutcome::Message(body),
                    Ok(false) => ReadOutcome::Eof,
                    Err(e) => ReadOutcome::Error(e.to_string()),
                }
            }
            Transport::Sctp => sctp_recv(&self.stream).await,
        }
    }
}

/// Fill `buf` from the stream. `Ok(false)` on a clean EOF before any octet of it arrived.
async fn read_exact(stream: &TcpStream, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        stream.readable().await?;
        match stream.try_read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ))
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(unix)]
async fn sctp_recv(stream: &TcpStream) -> ReadOutcome {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut message: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; codec::MAX_PDU_LEN + 1];
    let mut oversized = false;
    loop {
        if let Err(e) = stream.readable().await {
            return ReadOutcome::Error(e.to_string());
        }
        let r = stream.try_io(tokio::io::Interest::READABLE, || {
            let mut iov = libc::iovec {
                iov_base: chunk.as_mut_ptr() as *mut libc::c_void,
                iov_len: chunk.len(),
            };
            // SAFETY: msghdr is plain data; every pointer in it refers to `iov`/`chunk`, which
            // outlive the call.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            // SAFETY: fd is the live socket owned by `stream`; msg is initialised above.
            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok((n as usize, msg.msg_flags))
            }
        });
        let (n, flags) = match r {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return ReadOutcome::Error(e.to_string()),
        };
        if n == 0 {
            return ReadOutcome::Eof;
        }
        // MSG_NOTIFICATION (0x8000 on Linux): none are subscribed to, but never mistake one
        // for user data.
        if flags & 0x8000 != 0 {
            continue;
        }
        if !oversized {
            if message.len() + n > codec::MAX_PDU_LEN {
                oversized = true;
            } else {
                message.extend_from_slice(&chunk[..n]);
            }
        }
        let total = message.len() + if oversized { n } else { 0 };
        if flags & libc::MSG_EOR != 0 {
            return if oversized {
                ReadOutcome::TooLarge(total.max(codec::MAX_PDU_LEN + 1))
            } else {
                ReadOutcome::Message(message)
            };
        }
    }
}

#[cfg(not(unix))]
async fn sctp_recv(_stream: &TcpStream) -> ReadOutcome {
    ReadOutcome::Error("SCTP is not available on this platform".into())
}

/// Writes whole NGAP messages: each `write` is one message.
///
/// Implements `AsyncWrite` so the dashboard's generic peer command task can use it, under the
/// contract that one `write_all` call is one PDU (which is how both that task and NetGet's own
/// sessions use it).
pub struct MessageWriter {
    stream: Arc<TcpStream>,
    transport: Transport,
    /// Lab transport: the framed message still being written, and how much of it is out.
    pending: Option<(Vec<u8>, usize)>,
}

impl MessageWriter {
    /// Send one PDU.
    pub async fn send(&mut self, pdu: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.write_all(pdu).await?;
        self.flush().await
    }

    /// Half-close: an SCTP SHUTDOWN, or a TCP FIN.
    pub fn close(&self) {
        let _ = socket2::SockRef::from(&*self.stream).shutdown(std::net::Shutdown::Write);
    }
}

#[cfg(unix)]
fn sctp_send(stream: &TcpStream, pdu: &[u8], sid: u16) -> std::io::Result<usize> {
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
        // The PPID is carried in network byte order (RFC 6458 section 5.3.2).
        ppid: codec::PPID.to_be(),
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
        iov_base: pdu.as_ptr() as *mut libc::c_void,
        iov_len: pdu.len(),
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
fn sctp_send(_stream: &TcpStream, _pdu: &[u8], _sid: u16) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "SCTP is not available on this platform",
    ))
}

impl AsyncWrite for MessageWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.len() > codec::MAX_PDU_LEN {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "NGAP PDU of {} octets exceeds {}",
                    buf.len(),
                    codec::MAX_PDU_LEN
                ),
            )));
        }
        match self.transport {
            Transport::Sctp => {
                // TS 38.412 section 7: UE-associated signalling off stream 0.
                let preferred: u16 = if codec::is_ue_associated(buf) { 1 } else { 0 };
                loop {
                    if let Err(e) = std::task::ready!(self.stream.poll_write_ready(cx)) {
                        return Poll::Ready(Err(e));
                    }
                    let stream = self.stream.clone();
                    let mut result = stream.try_io(tokio::io::Interest::WRITABLE, || {
                        sctp_send(&stream, buf, preferred)
                    });
                    if preferred != 0
                        && matches!(&result, Err(e) if e.raw_os_error() == Some(libc::EINVAL))
                    {
                        // The association negotiated a single outbound stream.
                        result = stream
                            .try_io(tokio::io::Interest::WRITABLE, || sctp_send(&stream, buf, 0));
                    }
                    match result {
                        Ok(_) => return Poll::Ready(Ok(buf.len())),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            }
            Transport::Tcp => {
                if self.pending.is_none() {
                    let mut framed = Vec::with_capacity(LAB_HEADER_LEN + buf.len());
                    framed.extend_from_slice(&(buf.len() as u32).to_be_bytes());
                    framed.extend_from_slice(buf);
                    self.pending = Some((framed, 0));
                }
                loop {
                    let (data, done) = self.pending.as_ref().expect("set above");
                    if *done == data.len() {
                        self.pending = None;
                        return Poll::Ready(Ok(buf.len()));
                    }
                    if let Err(e) = std::task::ready!(self.stream.poll_write_ready(cx)) {
                        self.pending = None;
                        return Poll::Ready(Err(e));
                    }
                    let remaining = data[*done..].to_vec();
                    match self.stream.try_write(&remaining) {
                        Ok(n) => {
                            if let Some((_, d)) = self.pending.as_mut() {
                                *d += n;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            self.pending = None;
                            return Poll::Ready(Err(e));
                        }
                    }
                }
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
