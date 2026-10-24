//! Waiting until bytes a test wrote have actually arrived, rather than sleeping and hoping.
//!
//! For tests whose premise is "these bytes had arrived when the server looked" — batching
//! tests above all, where what was written during a held model call must be waiting when the
//! call returns, and where two writes must reach the server as two reads. A completed write
//! promises neither: macOS hands loopback traffic to an input thread, and under load bytes
//! written a moment ago can still be on their way, or still unread, when the server looks. A
//! fixed sleep only makes the premise likely; these make it true before the test goes on.

use std::time::Duration;

/// How long either wait gives the other side before failing the test.
const ARRIVAL_DEADLINE: Duration = Duration::from_secs(30);

/// Wait until the peer has acknowledged every byte written on `stream`.
///
/// TCP acknowledges bytes once they are in the receiving socket's buffer, so after this the
/// server can read them without waiting for anything.
///
/// Where the platform cannot say (neither Linux nor macOS), this returns at once.
pub async fn wait_until_acknowledged(stream: &tokio::net::TcpStream) {
    let deadline = tokio::time::Instant::now() + ARRIVAL_DEADLINE;
    loop {
        match unacknowledged_bytes(stream) {
            None | Some(0) => return,
            Some(n) => assert!(
                tokio::time::Instant::now() < deadline,
                "{n} written bytes were never acknowledged by the peer"
            ),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Bytes written on `stream` that the peer has not acknowledged yet, where the OS will say.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub fn unacknowledged_bytes(stream: &tokio::net::TcpStream) -> Option<usize> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut n: libc::c_int = 0;
    // Linux: TIOCOUTQ (SIOCOUTQ) on a TCP socket is everything not yet acknowledged, sent or not.
    #[cfg(target_os = "linux")]
    // SAFETY: `fd` is a live socket owned by `stream`; `n` is a valid `c_int` to write into.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) };
    // macOS: SO_NWRITE is the send buffer's byte count, and TCP keeps data there until it is
    // acknowledged.
    #[cfg(target_vendor = "apple")]
    let rc = {
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: as above; `len` holds the size of `n`.
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                (&mut n as *mut libc::c_int).cast(),
                &mut len,
            )
        }
    };
    (rc == 0).then_some(n.max(0) as usize)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn unacknowledged_bytes(_stream: &tokio::net::TcpStream) -> Option<usize> {
    None
}

/// Wait until server `id` has counted exactly `bytes` received across its connections.
///
/// For a server that counts a read once it has taken it in — queued it behind the answer in
/// flight, or started answering it — this means the server has read those bytes. A test that
/// writes once, waits for this, then writes again knows the two writes were two reads, and
/// that the first is where the server's dispatcher will find it.
pub async fn wait_until_server_received(
    state: &netget::state::app_state::AppState,
    id: netget::state::ServerId,
    bytes: u64,
) {
    let deadline = tokio::time::Instant::now() + ARRIVAL_DEADLINE;
    loop {
        let received: u64 = state
            .get_server(id)
            .await
            .map(|s| s.connections.values().map(|c| c.bytes_received).sum())
            .unwrap_or_default();
        assert!(
            received <= bytes,
            "server #{} counted {received} bytes received, more than the {bytes} written",
            id.as_u32()
        );
        if received == bytes {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server #{} counted {received} of the {bytes} bytes written",
            id.as_u32()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
