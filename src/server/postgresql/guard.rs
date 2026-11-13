//! The frontend-message size bound, enforced on the bytes before pgwire sees them.
//!
//! pgwire's framer bounds a Query, Parse or Bind at its `LARGE_PACKET_SIZE_LIMIT`, 0x3ffffffe
//! bytes — PostgreSQL's own 1 GB `MaxAllocSize` — and buffers a message whole before decoding it.
//! Real PostgreSQL can afford that because a peer must authenticate before it may send a Query;
//! this server authenticates nobody, so any stranger could make it hold a gigabyte per
//! connection, 256 connections at a time. And everything a message carries is handed to the
//! model, so nothing near that size is ever useful: [`MAX_FRONTEND_MESSAGE_BYTES`] is the bound.
//!
//! There is no seam inside pgwire for it. `process_socket` takes a concrete `TcpStream` and owns
//! every read, and its codec is a concrete type `process_message` is written against. So NetGet
//! keeps the peer's socket and hands pgwire one end of a loopback TCP pair instead
//! ([`Backend::pair`]); [`relay`] copies bytes between the two, reading the frontend framing as it
//! goes — a type byte and a 4-byte length per message after startup, a length and a code before
//! it — and refuses a message by its *declared* length, before a byte of its body is forwarded.
//! The relay holds one read buffer per direction, so its own memory per connection is constant.
//!
//! A refused message is answered as PostgreSQL answers a frame it will not read: `FATAL 08P01`.
//! The relay stops forwarding the peer's bytes at the refused header and half-closes pgwire's
//! side, so pgwire finishes answering everything it already has, writes it, and ends; only then
//! is the ErrorResponse written, so it never lands in the middle of one of pgwire's messages.
//!
//! The loopback listener is reachable by other local processes. [`Backend::pair`] accepts only
//! the connection it opened itself (matched by its source address) and drops anything else, so
//! nothing reaches pgwire that did not come through the relay.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// The largest frontend message this server reads, type byte and length field included.
///
/// Everything a Query, Parse or Bind carries is put in front of the model, and no model takes a
/// megabyte of SQL usefully; a megabyte is also far past any statement a real application sends
/// to a mock. 256 connections at this bound is 256 MiB, where pgwire's own bound is 256 GiB.
pub const MAX_FRONTEND_MESSAGE_BYTES: usize = 1024 * 1024;

/// The largest startup-phase packet (SSLRequest, GSSENCRequest, CancelRequest, StartupMessage):
/// pgwire's own `MAXIMUM_STARTUP_MESSAGE_LEN`, and PostgreSQL's `MAX_STARTUP_PACKET_LENGTH`.
pub const MAX_STARTUP_PACKET_BYTES: usize = 10_000;

/// Protocol version 3.0, the StartupMessage's code. After it every message is typed.
const PROTOCOL_V3: u32 = 196_608;

/// Why the relay stopped forwarding the peer's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A message declared a length past the bound (`declared` counts the type byte too).
    TooLong { declared: usize, limit: usize },
    /// A length field that cannot be a message (shorter than itself).
    Malformed(&'static str),
}

impl Refusal {
    /// The ErrorResponse text the peer reads.
    pub fn message(&self) -> String {
        match self {
            Refusal::TooLong { declared, limit } => {
                format!("message of {declared} bytes exceeds this server's limit of {limit} bytes")
            }
            Refusal::Malformed(why) => format!("invalid message: {why}"),
        }
    }

    /// `FATAL 08P01` (protocol_violation), framed: `'E'`, the length, then the severity, the
    /// non-localised severity, the code and the message as NUL-terminated fields, and a final NUL.
    pub fn error_response(&self) -> Vec<u8> {
        let mut fields = Vec::new();
        for (tag, value) in [
            (b'S', "FATAL".to_string()),
            (b'V', "FATAL".to_string()),
            (b'C', "08P01".to_string()),
            (b'M', self.message()),
        ] {
            fields.push(tag);
            fields.extend_from_slice(value.as_bytes());
            fields.push(0);
        }
        fields.push(0);
        let mut out = vec![b'E'];
        out.extend_from_slice(&((fields.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(&fields);
        out
    }
}

/// The frontend framing, read incrementally from the bytes the peer sends.
///
/// Before the StartupMessage every packet is a 4-byte length and a 4-byte code (SSLRequest and
/// GSSENCRequest are answered and followed by another such packet); from the StartupMessage on,
/// every message is a type byte and a 4-byte length. Only headers are kept: the body of an
/// admitted message is counted, not buffered.
#[derive(Debug)]
pub struct FrontendScreen {
    typed: bool,
    header: Vec<u8>,
    body_left: usize,
    /// The packet whose body is being skipped is the StartupMessage, after which the framing is
    /// typed.
    startup_pending: bool,
    limit: usize,
}

impl FrontendScreen {
    pub fn new(limit: usize) -> Self {
        Self {
            typed: false,
            header: Vec::with_capacity(8),
            body_left: 0,
            startup_pending: false,
            limit,
        }
    }

    /// Account for `data`, returning the bytes that may be forwarded to pgwire and, when a header
    /// in `data` is refused, the refusal.
    ///
    /// A header is held back until it is whole and checked, so a refused message reaches pgwire
    /// not even in part: what is forwarded is always whole messages plus, at most, the body of
    /// the one admitted last.
    pub fn admit(&mut self, data: &[u8]) -> (Vec<u8>, Option<Refusal>) {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if self.body_left > 0 {
                let take = self.body_left.min(data.len() - i);
                out.extend_from_slice(&data[i..i + take]);
                self.body_left -= take;
                i += take;
                if self.body_left == 0 {
                    self.finish_message();
                }
                continue;
            }
            let header_len = if self.typed { 5 } else { 8 };
            let take = (header_len - self.header.len()).min(data.len() - i);
            self.header.extend_from_slice(&data[i..i + take]);
            i += take;
            if self.header.len() < header_len {
                break;
            }
            let header = std::mem::take(&mut self.header);
            match self.check_header(&header) {
                Ok(body) => {
                    out.extend_from_slice(&header);
                    self.body_left = body;
                    if body == 0 {
                        self.finish_message();
                    }
                }
                Err(refusal) => return (out, Some(refusal)),
            }
        }
        (out, None)
    }

    /// The message whose body just ended was the StartupMessage: typed framing from here on.
    fn finish_message(&mut self) {
        if self.startup_pending {
            self.typed = true;
            self.startup_pending = false;
        }
    }

    /// The body length a complete header announces, or why it is refused.
    fn check_header(&mut self, h: &[u8]) -> Result<usize, Refusal> {
        if self.typed {
            let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
            if len < 4 {
                return Err(Refusal::Malformed(
                    "declared message length is shorter than the length field",
                ));
            }
            if len + 1 > self.limit {
                return Err(Refusal::TooLong {
                    declared: len + 1,
                    limit: self.limit,
                });
            }
            Ok(len - 4)
        } else {
            let len = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
            let code = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            if len < 8 {
                return Err(Refusal::Malformed("invalid length of startup packet"));
            }
            if len > MAX_STARTUP_PACKET_BYTES {
                return Err(Refusal::TooLong {
                    declared: len,
                    limit: MAX_STARTUP_PACKET_BYTES,
                });
            }
            if code >> 16 == PROTOCOL_V3 >> 16 {
                self.startup_pending = true;
            }
            Ok(len - 8)
        }
    }
}

/// The loopback listener pgwire is served from, one per server.
pub struct Backend {
    listener: TcpListener,
    addr: SocketAddr,
    pairing: Mutex<()>,
}

impl Backend {
    pub async fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            listener,
            addr,
            pairing: Mutex::new(()),
        })
    }

    /// A connected loopback pair: (the relay's end, pgwire's end).
    ///
    /// Serialised, so the connection accepted is the one just opened; anything else that reached
    /// the listener (another local process) is dropped unread.
    pub async fn pair(&self) -> std::io::Result<(TcpStream, TcpStream)> {
        let _serial = self.pairing.lock().await;
        let ours = TcpStream::connect(self.addr).await?;
        let want = ours.local_addr()?;
        loop {
            let (theirs, peer) =
                tokio::time::timeout(Duration::from_secs(10), self.listener.accept())
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "the loopback backend did not accept",
                        )
                    })??;
            if peer == want {
                let _ = ours.set_nodelay(true);
                let _ = theirs.set_nodelay(true);
                return Ok((ours, theirs));
            }
        }
    }
}

/// Copy bytes between the peer and pgwire's end of the pair until either side ends, screening
/// what the peer sends with [`FrontendScreen`]. Returns the refusal, if one ended the session.
pub async fn relay(peer: TcpStream, backend: TcpStream, limit: usize) -> Option<Refusal> {
    let (mut peer_rd, mut peer_wr) = peer.into_split();
    let (mut be_rd, mut be_wr) = backend.into_split();

    // pgwire -> peer, unscreened. Ends when pgwire closes its end; held in `AbortOnDrop` so that
    // aborting the connection task (stop_server, the idle watchdog) ends it too.
    let mut downstream = crate::utils::task_guard::AbortOnDrop(tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match be_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if peer_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        peer_wr
    }));

    // peer -> pgwire, screened.
    let mut screen = FrontendScreen::new(limit);
    let mut buf = vec![0u8; 16 * 1024];
    let mut refusal = None;
    let mut downstream_done = None;
    loop {
        tokio::select! {
            read = peer_rd.read(&mut buf) => {
                let n = match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let (forward, refused) = screen.admit(&buf[..n]);
                if !forward.is_empty() && be_wr.write_all(&forward).await.is_err() {
                    break;
                }
                if refused.is_some() {
                    refusal = refused;
                    break;
                }
            }
            done = &mut downstream.0 => {
                downstream_done = Some(done);
                break;
            }
        }
    }

    // Half-close pgwire's side: it answers what it already has, then sees EOF and ends, which
    // ends `downstream` at a message boundary.
    let _ = be_wr.shutdown().await;
    let peer_wr = match downstream_done {
        Some(done) => done.ok(),
        None => (&mut downstream.0).await.ok(),
    };
    if let (Some(refusal), Some(mut peer_wr)) = (refusal.as_ref(), peer_wr) {
        let _ = peer_wr.write_all(&refusal.error_response()).await;
        let _ = peer_wr.shutdown().await;
    }
    refusal
}
