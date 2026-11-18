//! The frontend screen: the message size bound and the message format check, enforced on the
//! bytes before pgwire sees them.
//!
//! **Size.** pgwire's framer bounds a Query, Parse or Bind at its `LARGE_PACKET_SIZE_LIMIT`,
//! 0x3ffffffe bytes — PostgreSQL's own 1 GB `MaxAllocSize` — and buffers a message whole before
//! decoding it. The limit is a per-message-type constant (`Message::max_message_length`), not a
//! setting. Real PostgreSQL can afford it because a peer must authenticate before it may send a
//! Query; this server authenticates nobody, so any stranger could make it hold a gigabyte per
//! connection, 256 connections at a time. And everything a message carries is handed to the
//! model, so nothing near that size is ever useful: [`MAX_FRONTEND_MESSAGE_BYTES`] is the bound.
//!
//! **Format.** pgwire 0.42.3 isolates each message's body and refuses a short one rather than
//! panicking, but a message its decoder refuses ends the session with nothing written to the
//! peer, and a decoder that stops short of the body's end is not noticed: a Query of `x` with no
//! NUL is served as an empty query. PostgreSQL answers both `FATAL 08P01`. [`check_typed`] and
//! [`check_startup`] make that answer here.
//!
//! There is no seam inside pgwire for either. `process_socket` takes a concrete `TcpStream` and
//! owns every read, and its codec is a concrete type `process_message` is written against. So
//! NetGet keeps the peer's socket and hands pgwire one end of a loopback TCP pair instead
//! ([`Backend::pair`]); [`relay`] copies bytes between the two, reading the frontend framing as it
//! goes — a type byte and a 4-byte length per message after startup, a length and a code before
//! it. A message is refused by its *declared* length before its body is read, and otherwise held
//! until it is whole and checked, then forwarded. The relay's memory per connection is one
//! message, at most the bound.
//!
//! A refused message is answered as PostgreSQL answers a frame it will not read: `FATAL 08P01`.
//! The relay stops forwarding the peer's bytes at the refused message and half-closes pgwire's
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

/// The SSLRequest and GSSENCRequest codes; each packet is exactly 8 bytes.
const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;

/// Why the relay stopped forwarding the peer's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A message declared a length past the bound (`declared` counts the type byte too).
    TooLong { declared: usize, limit: usize },
    /// A message that is not what its type says: a length field shorter than itself, or a
    /// message pgwire's decoder refuses or does not read to its end. The text is PostgreSQL's.
    Malformed(&'static str),
}

impl Refusal {
    /// The `decision=` tag the connection's close is logged with.
    pub fn decision(&self) -> &'static str {
        match self {
            Refusal::TooLong { .. } => "refused_oversize_message",
            Refusal::Malformed(_) => "refused_malformed_message",
        }
    }
}

impl Refusal {
    /// The ErrorResponse text the peer reads.
    pub fn message(&self) -> String {
        match self {
            Refusal::TooLong { declared, limit } => {
                format!("message of {declared} bytes exceeds this server's limit of {limit} bytes")
            }
            Refusal::Malformed(why) => why.to_string(),
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
/// GSSENCRequest, exactly 8 bytes each, are answered and followed by another such packet); from
/// the StartupMessage on, every message is a type byte and a 4-byte length.
///
/// A message is held until it is whole — never more than the bound its header was admitted
/// under — and the StartupMessage and every typed message are checked ([`check_typed`],
/// [`check_startup`]) before any of their bytes are forwarded.
#[derive(Debug)]
pub struct FrontendScreen {
    typed: bool,
    /// The message being read: its header, then its body as it arrives.
    message: Vec<u8>,
    body_left: usize,
    /// The message being read is the StartupMessage, after which the framing is typed.
    startup_pending: bool,
    limit: usize,
}

impl FrontendScreen {
    pub fn new(limit: usize) -> Self {
        Self {
            typed: false,
            message: Vec::with_capacity(8),
            body_left: 0,
            startup_pending: false,
            limit,
        }
    }

    /// Account for `data`, returning the bytes that may be forwarded to pgwire and, when a
    /// message in `data` is refused, the refusal.
    ///
    /// Only whole, checked messages are forwarded, so a refused message reaches pgwire not even
    /// in part. A header is refused by its declared length alone, before its body is read.
    pub fn admit(&mut self, data: &[u8]) -> (Vec<u8>, Option<Refusal>) {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if self.body_left > 0 {
                let take = self.body_left.min(data.len() - i);
                self.message.extend_from_slice(&data[i..i + take]);
                self.body_left -= take;
                i += take;
                if self.body_left == 0 {
                    if let Err(refusal) = self.finish_message(&mut out) {
                        return (out, Some(refusal));
                    }
                }
                continue;
            }
            let header_len = if self.typed { 5 } else { 8 };
            let take = (header_len - self.message.len()).min(data.len() - i);
            self.message.extend_from_slice(&data[i..i + take]);
            i += take;
            if self.message.len() < header_len {
                break;
            }
            let mut header = [0u8; 8];
            header[..header_len].copy_from_slice(&self.message[..header_len]);
            match self.check_header(&header[..header_len]) {
                Ok(body) => {
                    self.body_left = body;
                    if body == 0 {
                        if let Err(refusal) = self.finish_message(&mut out) {
                            return (out, Some(refusal));
                        }
                    }
                }
                Err(refusal) => return (out, Some(refusal)),
            }
        }
        (out, None)
    }

    /// The message just completed: check it, forward it, and after the StartupMessage switch to
    /// typed framing.
    fn finish_message(&mut self, out: &mut Vec<u8>) -> Result<(), Refusal> {
        let message = std::mem::take(&mut self.message);
        if self.typed {
            check_typed(&message)?;
        } else if self.startup_pending {
            check_startup(&message)?;
            self.typed = true;
            self.startup_pending = false;
        }
        out.extend_from_slice(&message);
        Ok(())
    }

    /// The body length a complete header announces, or why it is refused.
    fn check_header(&mut self, h: &[u8]) -> Result<usize, Refusal> {
        if self.typed {
            let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
            if len < 4 {
                return Err(Refusal::Malformed(
                    "invalid message length: shorter than the length field",
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
            // pgwire reads an SSLRequest or GSSENCRequest as 8 bytes whatever length it declares,
            // so a longer one would have the screen and pgwire disagree on where the next packet
            // starts: what the screen holds as the rest of this packet, pgwire would read as a
            // StartupMessage and typed messages that were never checked.
            if (code == SSL_REQUEST_CODE || code == GSSENC_REQUEST_CODE) && len != 8 {
                return Err(Refusal::Malformed("invalid length of startup packet"));
            }
            if code >> 16 == PROTOCOL_V3 >> 16 {
                self.startup_pending = true;
            }
            Ok(len - 8)
        }
    }
}

/// What PostgreSQL says of a message that is not what its type says it is.
const INVALID_FORMAT: Refusal = Refusal::Malformed("invalid message format");

/// A whole typed message (type byte, length, body) is one pgwire can serve: pgwire's own decoder
/// reads it, and reads all of it.
///
/// pgwire 0.42 isolates each message's body and refuses a short one, but when its decoder fails,
/// `process_socket` ends the session without a word to the peer; and it does not check that a
/// decoder consumed the whole body, so an unterminated string is read as an empty one (a Query
/// of `x` with no NUL is served as an empty query) and trailing bytes are dropped. PostgreSQL
/// answers all of these `FATAL 08P01`. So the message is decoded here first, with the decoder
/// pgwire will run, and re-encoded: a message that does not decode, or whose re-encoding is not
/// the bytes that arrived, is refused before pgwire sees it.
///
/// The one difference a re-encoding may show is UTF-8: pgwire reads a string lossily, so invalid
/// UTF-8 re-encodes as U+FFFD. When that is the only difference
/// ([`differs_only_by_lossy_utf8`]), the message is passed on as it arrived, and pgwire serves it
/// with U+FFFD in place of those bytes.
pub fn check_typed(message: &[u8]) -> Result<(), Refusal> {
    use pgwire::messages::{DecodeContext, PgWireFrontendMessage};

    let mut ctx = DecodeContext::default();
    ctx.awaiting_frontend_ssl = false;
    ctx.awaiting_frontend_startup = false;
    let mut buf = bytes::BytesMut::from(message);
    // pgwire's decoders are meant not to panic on any input (the `pgwire_frontend` fuzz target
    // holds them to it); if one does, the peer is refused rather than the relay task lost.
    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PgWireFrontendMessage::decode(&mut buf, &ctx)
    }));
    let decoded = match decoded {
        Ok(Ok(Some(decoded))) if buf.is_empty() => decoded,
        _ => return Err(INVALID_FORMAT),
    };
    let mut again = bytes::BytesMut::with_capacity(message.len());
    if decoded.encode(&mut again).is_err() {
        return Err(INVALID_FORMAT);
    }
    if again[..] == message[..] {
        return Ok(());
    }
    if message.first() == again.first()
        && differs_only_by_lossy_utf8(&message[5..], again.get(5..).unwrap_or_default())
    {
        return Ok(());
    }
    Err(INVALID_FORMAT)
}

/// `again` is `original` with some of its invalid UTF-8 replaced by U+FFFD, as pgwire's lossy
/// string read does, and differs from it in nothing else.
///
/// Walked chunk by chunk, so the replacement is only accepted where the original had invalid
/// UTF-8: valid text must re-appear exactly, and each invalid run either verbatim (a binary field,
/// which pgwire copies) or as one U+FFFD (a string). A comparison of the two bodies read lossily
/// as wholes is not enough — a Bind parameter length of `ff ff ff fe`, which pgwire reads as NULL
/// and re-encodes `ff ff ff ff`, reads the same lossily.
fn differs_only_by_lossy_utf8(original: &[u8], again: &[u8]) -> bool {
    const REPLACEMENT: &[u8] = "\u{FFFD}".as_bytes();
    let mut rest = again;
    for chunk in original.utf8_chunks() {
        let Some(after) = rest.strip_prefix(chunk.valid().as_bytes()) else {
            return false;
        };
        rest = after;
        let invalid = chunk.invalid();
        if invalid.is_empty() {
            continue;
        }
        if let Some(after) = rest.strip_prefix(invalid) {
            rest = after;
        } else if let Some(after) = rest.strip_prefix(REPLACEMENT) {
            rest = after;
        } else {
            return false;
        }
    }
    rest.is_empty()
}

/// A whole StartupMessage has PostgreSQL's layout: the length, the protocol version, then
/// `name NUL value NUL` pairs ended by one more NUL, and nothing after it.
///
/// pgwire reads the parameters until a name fails to read, so a name or value with no NUL ends
/// the list and the rest of the packet is dropped. PostgreSQL refuses such a packet `FATAL
/// 08P01`, "invalid startup packet layout: expected terminator as last byte".
pub fn check_startup(message: &[u8]) -> Result<(), Refusal> {
    const LAYOUT: Refusal =
        Refusal::Malformed("invalid startup packet layout: expected terminator as last byte");
    let mut params = message.get(8..).unwrap_or_default();
    loop {
        match params.iter().position(|b| *b == 0) {
            // The terminator, and nothing after it.
            Some(0) if params.len() == 1 => return Ok(()),
            // A name, then its value.
            Some(name_end) if name_end > 0 => {
                let rest = &params[name_end + 1..];
                let value_end = rest.iter().position(|b| *b == 0).ok_or(LAYOUT)?;
                params = &rest[value_end + 1..];
            }
            _ => return Err(LAYOUT),
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
