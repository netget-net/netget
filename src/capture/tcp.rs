//! Capturing a TCP connection: a stream wrapper that records what it reads and writes.
//!
//! ```ignore
//! let stream = crate::capture::tcp::CapturedStream::server(&app_state, server_id, stream);
//! let (read_half, write_half) = tokio::io::split(stream);   // unchanged from here on
//! ```
//!
//! The wrapper records each read as a segment from the peer and each accepted write as a
//! segment from NetGet, a read of zero bytes as the peer's FIN and a shutdown as NetGet's.
//! Dropping the last handle on the connection closes whatever direction is still open, so
//! a connection the server simply drops still ends in the file.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::pcap::{self, ACK, FIN, PSH, SYN};
use super::{CaptureOwner, CaptureSlot};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ServerId};

/// Fixed initial sequence numbers. Wireshark shows relative numbers anyway; what matters is
/// that each direction advances by exactly the bytes it carried.
const ISN_INITIATOR: u32 = 0x1000_0000;
const ISN_RESPONDER: u32 = 0x5000_0000;

const INITIATOR: usize = 0;
const RESPONDER: usize = 1;

/// One TCP connection's capture state, shared by both halves of the stream.
pub struct TcpFlow {
    slot: Arc<CaptureSlot>,
    /// `[initiator, responder]`: who sent the SYN, and who answered it.
    ends: [SocketAddr; 2],
    /// Which end NetGet is.
    local: usize,
    state: Mutex<FlowState>,
}

#[derive(Default)]
struct FlowState {
    /// The capture file this flow last wrote to; `0` before any.
    generation: u64,
    next_seq: [u32; 2],
    fin: [bool; 2],
}

impl TcpFlow {
    /// A connection NetGet accepted: the peer is the initiator.
    pub fn accepted(slot: Arc<CaptureSlot>, local: SocketAddr, peer: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            slot,
            ends: [peer, local],
            local: RESPONDER,
            state: Mutex::new(FlowState::default()),
        })
    }

    /// A connection NetGet opened: NetGet is the initiator.
    pub fn connected(slot: Arc<CaptureSlot>, local: SocketAddr, peer: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            slot,
            ends: [local, peer],
            local: INITIATOR,
            state: Mutex::new(FlowState::default()),
        })
    }

    /// Bytes the peer sent.
    pub fn inbound(&self, data: &[u8]) {
        self.data(1 - self.local, data);
    }

    /// Bytes NetGet sent.
    pub fn outbound(&self, data: &[u8]) {
        self.data(self.local, data);
    }

    /// The peer closed its direction (a read returned zero bytes).
    pub fn inbound_closed(&self) {
        self.fin(1 - self.local);
    }

    /// NetGet closed its direction.
    pub fn outbound_closed(&self) {
        self.fin(self.local);
    }

    fn data(&self, from: usize, data: &[u8]) {
        if data.is_empty() || !self.slot.is_active() {
            return;
        }
        let Some(writer) = self.slot.current() else {
            return;
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.open_if_needed(&mut st, &writer);
        let to = 1 - from;
        for chunk in data.chunks(pcap::MAX_SEGMENT_PAYLOAD) {
            let pkt = pcap::tcp_packet(
                self.ends[from],
                self.ends[to],
                st.next_seq[from],
                st.next_seq[to],
                PSH | ACK,
                chunk,
                self.slot.next_ip_id(),
            );
            st.next_seq[from] = st.next_seq[from].wrapping_add(chunk.len() as u32);
            writer.submit(pkt);
        }
    }

    fn fin(&self, from: usize) {
        if !self.slot.is_active() {
            return;
        }
        let Some(writer) = self.slot.current() else {
            return;
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.generation == writer.generation && st.fin[from] {
            return;
        }
        self.open_if_needed(&mut st, &writer);
        self.emit_fin(&mut st, &writer, from);
    }

    fn emit_fin(&self, st: &mut FlowState, writer: &super::writer::CaptureWriter, from: usize) {
        let to = 1 - from;
        writer.submit(pcap::tcp_packet(
            self.ends[from],
            self.ends[to],
            st.next_seq[from],
            st.next_seq[to],
            FIN | ACK,
            &[],
            self.slot.next_ip_id(),
        ));
        st.next_seq[from] = st.next_seq[from].wrapping_add(1);
        st.fin[from] = true;
    }

    /// The first packet this flow puts in a file opens the connection there: SYN, SYN-ACK,
    /// ACK. A capture started while the connection was already open opens it at that point.
    fn open_if_needed(&self, st: &mut FlowState, writer: &super::writer::CaptureWriter) {
        if st.generation == writer.generation {
            return;
        }
        st.generation = writer.generation;
        st.fin = [false, false];
        let (i, r) = (self.ends[INITIATOR], self.ends[RESPONDER]);
        writer.submit(pcap::tcp_packet(
            i,
            r,
            ISN_INITIATOR,
            0,
            SYN,
            &[],
            self.slot.next_ip_id(),
        ));
        writer.submit(pcap::tcp_packet(
            r,
            i,
            ISN_RESPONDER,
            ISN_INITIATOR.wrapping_add(1),
            SYN | ACK,
            &[],
            self.slot.next_ip_id(),
        ));
        writer.submit(pcap::tcp_packet(
            i,
            r,
            ISN_INITIATOR.wrapping_add(1),
            ISN_RESPONDER.wrapping_add(1),
            ACK,
            &[],
            self.slot.next_ip_id(),
        ));
        st.next_seq = [ISN_INITIATOR.wrapping_add(1), ISN_RESPONDER.wrapping_add(1)];
    }
}

impl Drop for TcpFlow {
    /// The connection is gone: close in the file whatever direction is still open, NetGet's
    /// first, so a server that drops a connection without a shutdown still ends its stream.
    fn drop(&mut self) {
        let Some(writer) = self.slot.current() else {
            return;
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.generation != writer.generation {
            // Nothing of this connection is in the current file.
            return;
        }
        for from in [self.local, 1 - self.local] {
            if !st.fin[from] {
                self.emit_fin(&mut st, &writer, from);
            }
        }
    }
}

/// A stream that records what passes through it into its instance's capture.
///
/// Holds no buffer and changes no byte: reads and writes go straight to `inner`, and only
/// what `inner` reported as read or accepted is recorded.
pub struct CapturedStream<S> {
    inner: S,
    flow: Arc<TcpFlow>,
}

impl<S> CapturedStream<S> {
    pub fn new(inner: S, flow: Arc<TcpFlow>) -> Self {
        Self { inner, flow }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn flow(&self) -> &Arc<TcpFlow> {
        &self.flow
    }
}

impl CapturedStream<tokio::net::TcpStream> {
    /// Wrap a stream `server_id` accepted. Addresses come from the socket itself; one it
    /// cannot report falls back to the unspecified address, which only affects the headers.
    pub fn server(state: &AppState, server_id: ServerId, stream: tokio::net::TcpStream) -> Self {
        let slot = state.capture.slot(CaptureOwner::Server(server_id));
        let (local, peer) = addrs(&stream);
        Self::new(stream, TcpFlow::accepted(slot, local, peer))
    }

    /// Wrap a stream that belongs to no instance, for code paths that may run without one:
    /// it records nothing, and keeps the type the same as on the captured path.
    pub fn uncaptured(stream: tokio::net::TcpStream) -> Self {
        let (local, peer) = addrs(&stream);
        Self::new(
            stream,
            TcpFlow::accepted(Arc::new(CaptureSlot::default()), local, peer),
        )
    }

    /// Wrap a stream `client_id` connected.
    pub fn client(state: &AppState, client_id: ClientId, stream: tokio::net::TcpStream) -> Self {
        let slot = state.capture.slot(CaptureOwner::Client(client_id));
        let (local, peer) = addrs(&stream);
        Self::new(stream, TcpFlow::connected(slot, local, peer))
    }
}

fn addrs(stream: &tokio::net::TcpStream) -> (SocketAddr, SocketAddr) {
    let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
    (
        stream.local_addr().unwrap_or(unspecified),
        stream.peer_addr().unwrap_or(unspecified),
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let had_room = buf.remaining() > 0;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let got = &buf.filled()[before..];
            if !got.is_empty() {
                this.flow.inbound(got);
            } else if had_room {
                this.flow.inbound_closed();
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            this.flow.outbound(&buf[..*n]);
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &result {
            // Only the first `n` bytes across the slices were accepted.
            let mut left = *n;
            let mut accepted = Vec::with_capacity(left);
            for b in bufs {
                if left == 0 {
                    break;
                }
                let take = left.min(b.len());
                accepted.extend_from_slice(&b[..take]);
                left -= take;
            }
            this.flow.outbound(&accepted);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = &result {
            this.flow.outbound_closed();
        }
        result
    }
}
