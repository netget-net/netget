//! A raw IPv4 socket for IP protocol 47, shared by the GRE server and client.
//!
//! On receive the kernel hands a raw IPv4 socket the whole packet, IP header included, and
//! (because the socket is bound) only packets addressed to the bound address. On send the
//! kernel writes the IP header itself (`IP_HDRINCL` is off), with the bound address as its
//! source, so what goes in is the GRE header and its payload.
//!
//! Linux delivers a copy of every protocol-47 packet for the bound address to every raw socket
//! *and* to its own GRE module, so a kernel `gre`/`gretap` link on the same address would see
//! the same packets. macOS (XNU has no GRE in the kernel) hands them to raw sockets alone.
//!
//! Needs root, or `CAP_NET_RAW` on Linux.
use anyhow::{ensure, Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::unix::AsyncFd;

/// The largest IPv4 packet: what one receive can hold.
pub const MAX_IP_PACKET: usize = 65_535;

pub struct RawGre {
    fd: AsyncFd<Socket>,
    local: Ipv4Addr,
}

/// One received packet: who sent it, and where its GRE bytes are in the buffer.
pub struct Received {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// The GRE packet (the IP payload): `buf[start..end]`.
    pub start: usize,
    pub end: usize,
}

impl RawGre {
    /// A raw protocol-47 socket bound to `local`, which must be an address of this host (or
    /// `0.0.0.0` for every address).
    pub fn bind(local: Ipv4Addr) -> Result<Self> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(i32::from(crate::utils::gre::IP_PROTOCOL))),
        )
        .context(
            "cannot open a raw IP protocol-47 socket: GRE needs root, or CAP_NET_RAW on Linux",
        )?;
        socket
            .set_nonblocking(true)
            .context("cannot make the raw GRE socket non-blocking")?;
        socket
            .bind(&SockAddr::from(SocketAddrV4::new(local, 0)))
            .with_context(|| format!("cannot bind the raw GRE socket to {local}"))?;
        Ok(Self {
            fd: AsyncFd::new(socket).context("cannot register the raw GRE socket")?,
            local,
        })
    }

    pub fn local(&self) -> Ipv4Addr {
        self.local
    }

    /// The local address as a socket address with port 0, which is what the registry records
    /// for a protocol with no ports.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(SocketAddrV4::new(self.local, 0))
    }

    /// The next protocol-47 packet. `buf` should hold [`MAX_IP_PACKET`] bytes. A packet whose
    /// IP header does not make sense is skipped, not returned.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        loop {
            let mut guard = self.fd.readable().await?;
            let n = match guard.try_io(|inner| {
                // SAFETY: `recv` only writes initialised bytes into the buffer, and `u8` and
                // `MaybeUninit<u8>` have the same layout.
                let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
                inner.get_ref().recv(uninit)
            }) {
                Ok(r) => r?,
                Err(_would_block) => continue,
            };
            match parse_ip_header(&buf[..n]) {
                Ok(r) => return Ok(r),
                Err(e) => tracing::debug!("GRE raw socket skipped a packet: {e:#}"),
            }
        }
    }

    /// Hand one GRE packet to the kernel for `to`, without waiting. `WouldBlock` when the send
    /// buffer is full; wait with [`RawGre::writable`].
    pub fn try_send_to(&self, packet: &[u8], to: Ipv4Addr) -> io::Result<usize> {
        self.fd
            .get_ref()
            .send_to(packet, &SockAddr::from(SocketAddrV4::new(to, 0)))
    }

    pub async fn writable(&self) -> io::Result<()> {
        let mut guard = self.fd.writable().await?;
        guard.clear_ready();
        Ok(())
    }

    /// Send, waiting for room in the send buffer.
    pub async fn send_to(&self, packet: &[u8], to: Ipv4Addr) -> io::Result<usize> {
        loop {
            match self.try_send_to(packet, to) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.writable().await?,
                other => return other,
            }
        }
    }
}

/// The outer IPv4 header of a received packet. The payload is taken to run to the end of what
/// was received rather than to the header's total length, which macOS reports in host order
/// and without the header.
fn parse_ip_header(b: &[u8]) -> Result<Received> {
    ensure!(
        b.len() >= 20,
        "a {}-byte packet has no IPv4 header",
        b.len()
    );
    ensure!(b[0] >> 4 == 4, "IP version {}", b[0] >> 4);
    let ihl = usize::from(b[0] & 0x0f) * 4;
    ensure!(ihl >= 20 && b.len() >= ihl, "IPv4 header length {ihl}");
    ensure!(
        b[9] == crate::utils::gre::IP_PROTOCOL,
        "IP protocol {}",
        b[9]
    );
    Ok(Received {
        src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
        dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        start: ihl,
        end: b.len(),
    })
}
