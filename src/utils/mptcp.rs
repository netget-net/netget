//! Multipath TCP (RFC 8684) sockets for the `tcp` server and client (`multipath: true`).
//!
//! MPTCP is not a protocol of its own in NetGet: it is the same byte stream as TCP, carried
//! over one or more subflows, so it is a startup parameter of `tcp`. A peer that does not
//! speak MPTCP gets plain TCP from the same socket (the kernel falls back during the
//! handshake), which is why whether MPTCP was *negotiated* is reported per connection rather
//! than assumed from the parameter.
//!
//! **Linux only.** The socket is opened with `IPPROTO_MPTCP` (262). macOS has MPTCP in the
//! kernel, but only Apple's own services can listen with it, and a client reaches it only
//! through Network.framework (`NWParameters.multipathServiceType`), not BSD sockets; other
//! platforms have none. There `multipath: true` is refused with [`UNSUPPORTED_REASON`] rather
//! than quietly opening a plain TCP socket.
//!
//! When the Linux kernel refuses the socket the start fails with the reason
//! ([`explain_open_error`]): `EPROTONOSUPPORT` is a kernel without MPTCP, `ENOPROTOOPT` is
//! MPTCP switched off (`net.mptcp.enabled=0`, per network namespace). It does not fall back,
//! because the operator asked for MPTCP and plain TCP is what they would have had without
//! asking.
//!
//! This file depends only on `std`, `tokio`, `socket2` and `libc`, so it can be compiled on
//! its own; that is how it was exercised on Linux (see `src/server/tcp/AGENTS.md`).

use std::io;
use std::net::SocketAddr;

/// `IPPROTO_MPTCP` from `<netinet/in.h>` (`linux/in.h`).
pub const IPPROTO_MPTCP: i32 = 262;
/// `TCP_IS_MPTCP` from `linux/tcp.h` (`SOL_TCP` level): 1 when the socket is using MPTCP.
/// Recent kernels only — 6.8 answers `EOPNOTSUPP`/`ENOPROTOOPT`, see [`is_mptcp`].
pub const TCP_IS_MPTCP: i32 = 43;
/// `SOL_MPTCP` from `bits/socket.h`.
pub const SOL_MPTCP: i32 = 284;
/// `MPTCP_INFO` from `linux/mptcp.h` (`SOL_MPTCP` level).
pub const MPTCP_INFO: i32 = 1;

/// Why `multipath: true` cannot be honoured on this platform, or `None` where it can.
#[cfg(target_os = "linux")]
pub const UNSUPPORTED_REASON: Option<&str> = None;
#[cfg(target_os = "macos")]
pub const UNSUPPORTED_REASON: Option<&str> = Some(
    "multipath (MPTCP) is not available to NetGet on macOS: the macOS kernel implements \
     MPTCP, but a third-party process cannot listen with it, and a client can only use it \
     through Network.framework (NWParameters.multipathServiceType), not the BSD sockets \
     NetGet uses. Run NetGet on Linux (5.6+, net.mptcp.enabled=1) for MPTCP, or leave \
     multipath unset for plain TCP.",
);
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub const UNSUPPORTED_REASON: Option<&str> = Some(
    "multipath (MPTCP) is only implemented on Linux (5.6+, net.mptcp.enabled=1); this \
     platform has no MPTCP socket API NetGet can use. Leave multipath unset for plain TCP.",
);

/// The error a refused `IPPROTO_MPTCP` socket is reported with: the OS error plus what it
/// means for MPTCP and how to fix it.
pub fn explain_open_error(e: io::Error) -> io::Error {
    let hint = match e.raw_os_error() {
        #[cfg(target_os = "linux")]
        Some(libc::EPROTONOSUPPORT) => {
            "this kernel has no MPTCP support (it needs Linux 5.6+ built with CONFIG_MPTCP)"
        }
        #[cfg(target_os = "linux")]
        Some(libc::ENOPROTOOPT) => {
            "MPTCP is disabled in this network namespace (net.mptcp.enabled=0); enable it with \
             `sysctl -w net.mptcp.enabled=1`"
        }
        _ => "the kernel refused an IPPROTO_MPTCP socket",
    };
    io::Error::new(
        e.kind(),
        format!("multipath (MPTCP) requested but unavailable: {hint} ({e}). Leave multipath unset for plain TCP."),
    )
}

/// Open a listening MPTCP socket on `addr` (`SO_REUSEADDR`, backlog 128), the MPTCP
/// counterpart of `socket_helpers::create_reusable_tcp_listener`. Call it inside a tokio
/// runtime.
#[cfg(target_os = "linux")]
pub fn listen(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::from(IPPROTO_MPTCP)),
    )
    .map_err(explain_open_error)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}

#[cfg(not(target_os = "linux"))]
pub fn listen(_addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    Err(unsupported())
}

/// Connect to `addr` over an MPTCP socket. The kernel falls back to plain TCP when the server
/// does not answer MPTCP, so check [`is_mptcp`] on the result.
#[cfg(target_os = "linux")]
pub async fn connect(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::from(IPPROTO_MPTCP)),
    )
    .map_err(explain_open_error)?;
    socket.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = socket.into();
    tokio::net::TcpSocket::from_std_stream(std_stream)
        .connect(addr)
        .await
}

#[cfg(not(target_os = "linux"))]
pub async fn connect(_addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    Err(unsupported())
}

/// Whether this connected socket is actually carrying MPTCP (`false` once the kernel fell
/// back to plain TCP, and for any socket that was never MPTCP).
///
/// `TCP_IS_MPTCP` answers directly where the kernel has it. Kernels without it (6.8, for
/// one) answer `EOPNOTSUPP` on an MPTCP socket and `ENOPROTOOPT` on a TCP one; there
/// `MPTCP_INFO` decides — it returns the MPTCP state of a socket using MPTCP and `EOPNOTSUPP`
/// for one that fell back or is plain TCP.
#[cfg(target_os = "linux")]
pub fn is_mptcp<S: std::os::fd::AsRawFd>(socket: &S) -> io::Result<bool> {
    let fd = socket.as_raw_fd();
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a live socket borrowed for the call; `val`/`len` are valid for writes of
    // the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_TCP,
            TCP_IS_MPTCP,
            (&mut val as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == 0 {
        return Ok(val != 0);
    }
    let err = io::Error::last_os_error();
    if !matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOPROTOOPT)
    ) {
        return Err(err);
    }
    let mut info = [0u8; 256];
    let mut len = info.len() as libc::socklen_t;
    // SAFETY: as above; `info` is writable for `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_MPTCP,
            MPTCP_INFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EOPNOTSUPP) | Some(libc::ENOPROTOOPT) => Ok(false),
        _ => Err(err),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_mptcp<S>(_socket: &S) -> io::Result<bool> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        UNSUPPORTED_REASON.unwrap_or("multipath (MPTCP) is not supported on this platform"),
    )
}
