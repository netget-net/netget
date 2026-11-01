//! Capturing a UDP socket: one packet in the file per datagram received or sent.
//!
//! ```ignore
//! let tap = crate::capture::udp::UdpTap::server(&app_state, server_id, local_addr);
//! let (n, peer) = socket.recv_from(&mut buf).await?;
//! tap.inbound(peer, &buf[..n]);
//! socket.send_to(&reply, peer).await?;
//! tap.outbound(peer, &reply);
//! ```
//!
//! Record a send only once `send_to` has succeeded, so the file holds what left the socket.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{pcap, CaptureOwner, CaptureSlot};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ServerId};

/// A UDP socket's hook into its instance's capture. Cheap to clone into tasks.
#[derive(Clone)]
pub struct UdpTap {
    slot: Arc<CaptureSlot>,
    local: SocketAddr,
}

impl UdpTap {
    pub fn new(slot: Arc<CaptureSlot>, local: SocketAddr) -> Self {
        Self { slot, local }
    }

    /// The tap for a server's socket bound at `local`.
    pub fn server(state: &AppState, server_id: ServerId, local: SocketAddr) -> Self {
        Self::new(state.capture.slot(CaptureOwner::Server(server_id)), local)
    }

    /// The tap for a client's socket bound at `local`.
    pub fn client(state: &AppState, client_id: ClientId, local: SocketAddr) -> Self {
        Self::new(state.capture.slot(CaptureOwner::Client(client_id)), local)
    }

    /// A datagram `peer` sent to this socket.
    pub fn inbound(&self, peer: SocketAddr, data: &[u8]) {
        self.record(peer, self.local, data);
    }

    /// A datagram this socket sent to `peer`.
    pub fn outbound(&self, peer: SocketAddr, data: &[u8]) {
        self.record(self.local, peer, data);
    }

    fn record(&self, src: SocketAddr, dst: SocketAddr, data: &[u8]) {
        if !self.slot.is_active() {
            return;
        }
        if let Some(writer) = self.slot.current() {
            writer.submit(pcap::udp_packet(src, dst, data, self.slot.next_ip_id()));
        }
    }
}
