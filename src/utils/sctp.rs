//! Socket options shared by the protocols that run over SCTP (`ngap`, `m3ua`).

use tokio::net::TcpStream;

/// `SCTP_NODELAY` (the option number of linux/sctp.h): send each message at once.
///
/// Without it the kernel holds a message written straight after another until the peer
/// acknowledges the first, and a peer that delays its acknowledgements (Open5GS does, by about
/// 200 ms) holds back every second message by that much. Other systems' SCTP stacks number the
/// option differently, and none of them is one this code is run on, so they are left at their
/// default; a failure is logged, never fatal.
#[cfg(target_os = "linux")]
pub fn set_nodelay(stream: &TcpStream, protocol: &str) {
    use std::os::fd::AsRawFd;
    const IPPROTO_SCTP: libc::c_int = 132;
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
            "{protocol} could not set SCTP_NODELAY: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_nodelay(_stream: &TcpStream, _protocol: &str) {}
