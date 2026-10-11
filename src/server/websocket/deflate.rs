//! RFC 7692 permessage-deflate, as a byte stream beneath tungstenite.
//!
//! tungstenite 0.21 — every published version, in fact — has no extension hook and refuses
//! any frame with RSV1 set, so the extension lives one layer down: [`DeflateStream`] wraps
//! the socket, reads and writes WebSocket frames itself, and shows tungstenite only
//! uncompressed ones.
//!
//! - **Inbound**, a message whose first frame has RSV1 set is collected across its
//!   continuation frames, inflated as one (§7.2.2: append `00 00 ff ff`, then inflate) and
//!   handed up as a single unfragmented frame with RSV1 clear, keeping the peer's masking key
//!   so a server-role tungstenite still sees a masked client frame. Uncompressed messages and
//!   every control frame pass through untouched.
//! - **Outbound**, every data message tungstenite writes is deflated (§7.2.1: compress, sync
//!   flush, drop the trailing `00 00 ff ff`) and sent as one frame with RSV1 set, re-masked
//!   with tungstenite's own key on the client side.
//!
//! Context takeover is kept unless the negotiation said otherwise, and a negotiated
//! `*_max_window_bits` is honoured in both directions (flate2's zlib backend). Inflation is
//! bounded by the connection's maximum message size, checked while inflating, so a small
//! compressed frame cannot expand past it (a decompression bomb is an error, not an
//! allocation).

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The extension token (§7).
pub const EXTENSION: &str = "permessage-deflate";

/// What the offer the client sends looks like: no constraints of its own, and it accepts any
/// window the server picks for client-to-server messages.
pub const CLIENT_OFFER: &str = "permessage-deflate; client_max_window_bits";

/// The tail a sync flush ends with, which §7.2.1 removes and §7.2.2 puts back.
const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// One side's negotiated parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateParams {
    /// The server resets its compression context after every message.
    pub server_no_context_takeover: bool,
    /// The client resets its compression context after every message.
    pub client_no_context_takeover: bool,
    /// LZ77 window the server compresses with (9..=15).
    pub server_max_window_bits: u8,
    /// LZ77 window the client compresses with (9..=15).
    pub client_max_window_bits: u8,
}

impl Default for DeflateParams {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
        }
    }
}

impl DeflateParams {
    /// The `Sec-WebSocket-Extensions` value that states these parameters.
    pub fn header_value(&self) -> String {
        let mut out = EXTENSION.to_string();
        if self.server_no_context_takeover {
            out.push_str("; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            out.push_str("; client_no_context_takeover");
        }
        if self.server_max_window_bits < 15 {
            out.push_str(&format!(
                "; server_max_window_bits={}",
                self.server_max_window_bits
            ));
        }
        if self.client_max_window_bits < 15 {
            out.push_str(&format!(
                "; client_max_window_bits={}",
                self.client_max_window_bits
            ));
        }
        out
    }

    /// As the event payloads report it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "extension": EXTENSION,
            "server_no_context_takeover": self.server_no_context_takeover,
            "client_no_context_takeover": self.client_no_context_takeover,
            "server_max_window_bits": self.server_max_window_bits,
            "client_max_window_bits": self.client_max_window_bits,
        })
    }
}

/// `name; p1; p2=v` as (name, [(param, value)]). Quoted values are unquoted (§9.1 allows them).
fn parse_element(element: &str) -> Option<(String, Vec<(String, Option<String>)>)> {
    let mut parts = element.split(';').map(str::trim);
    let name = parts.next()?.to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let mut params = Vec::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let (k, v) = match p.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"').to_string())),
            None => (p, None),
        };
        params.push((k.to_ascii_lowercase(), v));
    }
    Some((name, params))
}

/// Every element of every `Sec-WebSocket-Extensions` value, in order.
fn elements<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|v| v.split(','))
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect()
}

/// A window size parameter: 9..=15. zlib cannot make a raw-deflate stream with an 8-bit window
/// (it silently uses 9), so an offer demanding 8 is one this side cannot honour.
fn window_bits(value: &Option<String>) -> Result<Option<u8>, ()> {
    match value {
        None => Ok(None),
        Some(v) => match v.parse::<u8>() {
            Ok(n) if (9..=15).contains(&n) => Ok(Some(n)),
            _ => Err(()),
        },
    }
}

/// Server side (§5, §7.1): accept the first `permessage-deflate` offer this server can honour,
/// and say what was accepted. `None` when there is no such offer — the connection then runs
/// uncompressed, which is always allowed.
pub fn negotiate<'a>(offers: impl IntoIterator<Item = &'a str>) -> Option<(DeflateParams, String)> {
    'offer: for element in elements(offers) {
        let Some((name, params)) = parse_element(&element) else {
            continue;
        };
        if name != EXTENSION {
            continue;
        }
        let mut accepted = DeflateParams::default();
        let mut seen: Vec<&str> = Vec::new();
        for (k, v) in &params {
            // §7.1: a parameter twice, or one with a bad value, invalidates the offer.
            if seen.contains(&k.as_str()) {
                continue 'offer;
            }
            seen.push(k.as_str());
            match k.as_str() {
                "server_no_context_takeover" if v.is_none() => {
                    accepted.server_no_context_takeover = true
                }
                "client_no_context_takeover" if v.is_none() => {
                    accepted.client_no_context_takeover = true
                }
                "server_max_window_bits" => match window_bits(v) {
                    Ok(Some(n)) => accepted.server_max_window_bits = n,
                    _ => continue 'offer,
                },
                // A hint that the client can take a smaller window; this server keeps 15 for
                // the client's direction unless the client names a value it wants.
                "client_max_window_bits" => match window_bits(v) {
                    Ok(Some(n)) => accepted.client_max_window_bits = n,
                    Ok(None) => {}
                    Err(()) => continue 'offer,
                },
                _ => continue 'offer,
            }
        }
        let value = accepted.header_value();
        return Some((accepted, value));
    }
    None
}

/// Client side (§7.1): what the server's response says, checked against what was offered.
/// `Ok(None)` is a server that declined, `Err` one that answered with something not offered.
pub fn accept_response<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Option<DeflateParams>, String> {
    let all = elements(values);
    let mut result = None;
    for element in all {
        let Some((name, params)) = parse_element(&element) else {
            return Err(format!("malformed extension {element:?}"));
        };
        if name != EXTENSION {
            return Err(format!(
                "the server accepted an extension that was not offered: {name}"
            ));
        }
        if result.is_some() {
            return Err("the server accepted permessage-deflate twice".into());
        }
        let mut p = DeflateParams::default();
        for (k, v) in &params {
            match k.as_str() {
                "server_no_context_takeover" if v.is_none() => p.server_no_context_takeover = true,
                "client_no_context_takeover" if v.is_none() => p.client_no_context_takeover = true,
                "server_max_window_bits" => {
                    p.server_max_window_bits = window_bits(v)
                        .ok()
                        .flatten()
                        .ok_or_else(|| format!("bad server_max_window_bits {v:?}"))?
                }
                "client_max_window_bits" => {
                    p.client_max_window_bits = window_bits(v)
                        .ok()
                        .flatten()
                        .ok_or_else(|| format!("bad client_max_window_bits {v:?}"))?
                }
                other => return Err(format!("unknown permessage-deflate parameter {other:?}")),
            }
        }
        result = Some(p);
    }
    Ok(result)
}

/// Which end of the connection this stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Server,
    Client,
}

/// The compression state of one negotiated connection.
pub struct Codec {
    side: Side,
    params: DeflateParams,
    inflate: Decompress,
    deflate: Compress,
    max_message: usize,
}

impl Codec {
    pub fn new(side: Side, params: DeflateParams, max_message: usize) -> Self {
        let (ours, theirs) = match side {
            Side::Server => (params.server_max_window_bits, params.client_max_window_bits),
            Side::Client => (params.client_max_window_bits, params.server_max_window_bits),
        };
        Self {
            side,
            params,
            // Inflating with a window at least as large as the sender's is always correct.
            inflate: Decompress::new_with_window_bits(false, theirs.max(9)),
            deflate: Compress::new_with_window_bits(Compression::default(), false, ours.max(9)),
            max_message,
        }
    }

    fn peer_resets(&self) -> bool {
        match self.side {
            Side::Server => self.params.client_no_context_takeover,
            Side::Client => self.params.server_no_context_takeover,
        }
    }

    fn we_reset(&self) -> bool {
        match self.side {
            Side::Server => self.params.server_no_context_takeover,
            Side::Client => self.params.client_no_context_takeover,
        }
    }

    /// Inflate one message's payload, refusing to produce more than `max_message` bytes. The
    /// output buffer never grows past `max_message + 1`, so the check happens while inflating.
    pub fn inflate(&mut self, compressed: &[u8]) -> io::Result<Vec<u8>> {
        let mut input = Vec::with_capacity(compressed.len() + TAIL.len());
        input.extend_from_slice(compressed);
        input.extend_from_slice(&TAIL);
        let limit = self.max_message.saturating_add(1);
        let start = self.inflate.total_in();
        let mut out: Vec<u8> = Vec::new();
        loop {
            let room = (out.len() + 32 * 1024).min(limit) - out.len();
            out.reserve_exact(room);
            let (in_before, out_before) = (self.inflate.total_in(), out.len());
            let consumed = (in_before - start) as usize;
            self.inflate
                .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
                .map_err(|e| protocol(&format!("inflate: {e}")))?;
            if out.len() > self.max_message {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "permessage-deflate: message inflates past {} bytes",
                        self.max_message
                    ),
                ));
            }
            let consumed = (self.inflate.total_in() - start) as usize;
            if consumed >= input.len() && out.len() < out.capacity() {
                break;
            }
            if self.inflate.total_in() == in_before && out.len() == out_before {
                return Err(protocol("inflate made no progress"));
            }
        }
        if self.peer_resets() {
            self.inflate.reset(false);
        }
        Ok(out)
    }

    /// Deflate one message's payload with a sync flush and the tail removed.
    pub fn deflate(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let start = self.deflate.total_in();
        let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 64);
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(out.capacity().max(256));
            }
            let consumed = (self.deflate.total_in() - start) as usize;
            self.deflate
                .compress_vec(&payload[consumed..], &mut out, FlushCompress::Sync)
                .map_err(|e| io::Error::other(format!("deflate: {e}")))?;
            let consumed = (self.deflate.total_in() - start) as usize;
            // Done once the input is consumed and the flush fitted with room to spare.
            if consumed >= payload.len() && out.capacity() - out.len() >= 64 {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - TAIL.len());
        }
        if self.we_reset() {
            self.deflate.reset();
        }
        Ok(out)
    }
}

/// One WebSocket frame as it crossed the wire, payload unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    /// RSV2 and RSV3, carried through untouched so tungstenite still refuses them.
    pub rsv23: u8,
    pub opcode: u8,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl Frame {
    fn is_control_frame(&self) -> bool {
        self.opcode >= 0x8
    }

    /// Parse one frame from the front of `buf`; `Ok(None)` when more bytes are needed. A
    /// declared length past `max` is refused before anything is buffered for it.
    pub fn parse(buf: &[u8], max: usize) -> io::Result<Option<(Frame, usize)>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let b0 = buf[0];
        let b1 = buf[1];
        let masked = b1 & 0x80 != 0;
        let (len, mut at) = match b1 & 0x7f {
            126 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4usize)
            }
            127 => {
                if buf.len() < 10 {
                    return Ok(None);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[2..10]);
                (u64::from_be_bytes(b), 10usize)
            }
            n => (u64::from(n), 2usize),
        };
        if len > max as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of {len} bytes exceeds the {max}-byte limit"),
            ));
        }
        let len = len as usize;
        let mask = if masked {
            if buf.len() < at + 4 {
                return Ok(None);
            }
            let m = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
            at += 4;
            Some(m)
        } else {
            None
        };
        if buf.len() < at + len {
            return Ok(None);
        }
        let mut payload = buf[at..at + len].to_vec();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        Ok(Some((
            Frame {
                fin: b0 & 0x80 != 0,
                rsv1: b0 & 0x40 != 0,
                rsv23: b0 & 0x30,
                opcode: b0 & 0x0f,
                mask,
                payload,
            },
            at + len,
        )))
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(
            (if self.fin { 0x80 } else { 0 })
                | (if self.rsv1 { 0x40 } else { 0 })
                | self.rsv23
                | self.opcode,
        );
        let mask_bit = if self.mask.is_some() { 0x80 } else { 0 };
        let len = self.payload.len();
        if len < 126 {
            out.push(mask_bit | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match self.mask {
            Some(m) => {
                out.extend_from_slice(&m);
                out.extend(self.payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
            }
            None => out.extend_from_slice(&self.payload),
        }
    }
}

/// A data message being reassembled.
struct Partial {
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload: Vec<u8>,
}

/// The frame transform for one direction.
#[derive(Default)]
struct Direction {
    raw: Vec<u8>,
    /// A compressed (inbound) or to-be-compressed (outbound) message in progress.
    partial: Option<Partial>,
    /// An uncompressed inbound message is being passed through frame by frame.
    passing: bool,
}

enum Mode {
    /// No extension: bytes pass straight through.
    Plain,
    /// Client side before the 101: pass bytes through until the response head is complete,
    /// then read `Sec-WebSocket-Extensions` from it.
    AwaitResponse {
        max_message: usize,
    },
    Active(Box<Codec>),
}

/// The socket beneath tungstenite. See the module docs.
pub struct DeflateStream<S> {
    inner: S,
    mode: Mode,
    max_message: usize,
    /// Largest frame handed up to tungstenite; an inflated message is re-fragmented to fit.
    max_frame: usize,
    read: Direction,
    write: Direction,
    /// Bytes ready for tungstenite to read.
    ready: Vec<u8>,
    /// Bytes ready for the socket.
    pending: Vec<u8>,
    /// What the 101 response negotiated (client side), once read.
    negotiated: Option<Result<Option<DeflateParams>, String>>,
}

impl<S> DeflateStream<S> {
    /// A server connection whose handshake already happened: `leftover` is whatever the
    /// handshake read beyond the request head, which belongs to the frame stream.
    pub fn server(
        inner: S,
        params: Option<DeflateParams>,
        max_message: usize,
        max_frame: usize,
        leftover: Vec<u8>,
    ) -> Self {
        let mut s = Self::new(inner, max_message, max_frame);
        if let Some(p) = params {
            s.mode = Mode::Active(Box::new(Codec::new(Side::Server, p, max_message)));
        }
        s.read.raw = leftover;
        s
    }

    /// A client connection about to send its handshake. The response decides the mode.
    pub fn client(inner: S, max_message: usize, max_frame: usize) -> Self {
        let mut s = Self::new(inner, max_message, max_frame);
        s.mode = Mode::AwaitResponse { max_message };
        s
    }

    fn new(inner: S, max_message: usize, max_frame: usize) -> Self {
        Self {
            inner,
            mode: Mode::Plain,
            max_message,
            max_frame: max_frame.max(1),
            read: Direction::default(),
            write: Direction::default(),
            ready: Vec::new(),
            pending: Vec::new(),
            negotiated: None,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Client side: what the server accepted, once its response has been read.
    pub fn negotiated(&self) -> Option<&Result<Option<DeflateParams>, String>> {
        self.negotiated.as_ref()
    }

    /// The parameters in force, if the extension is active.
    pub fn active(&self) -> Option<DeflateParams> {
        match &self.mode {
            Mode::Active(c) => Some(c.params),
            _ => None,
        }
    }

    /// Turn raw inbound bytes into what tungstenite should read.
    fn process_read(&mut self) -> io::Result<()> {
        if let Mode::AwaitResponse { max_message } = self.mode {
            let Some(end) = self.read.raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.read.raw.len() > 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake response head exceeds 64 KiB",
                    ));
                }
                return Ok(());
            };
            let head: Vec<u8> = self.read.raw.drain(..end + 4).collect();
            let text = String::from_utf8_lossy(&head).to_string();
            let values: Vec<&str> = text
                .split("\r\n")
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-extensions"))
                .map(|(_, v)| v.trim())
                .collect();
            let switching = text.starts_with("HTTP/1.1 101");
            let result = if switching {
                accept_response(values)
            } else {
                Ok(None)
            };
            self.mode = match &result {
                Ok(Some(p)) => Mode::Active(Box::new(Codec::new(Side::Client, *p, max_message))),
                _ => Mode::Plain,
            };
            self.negotiated = Some(result.clone());
            self.ready.extend_from_slice(&head);
            if let Err(e) = result {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        let Mode::Active(codec) = &mut self.mode else {
            self.ready.append(&mut self.read.raw);
            return Ok(());
        };
        let max = self.max_message;
        loop {
            let Some((frame, used)) = Frame::parse(&self.read.raw, max)? else {
                return Ok(());
            };
            self.read.raw.drain(..used);
            if frame.is_control_frame() {
                frame.encode(&mut self.ready);
                continue;
            }
            let starts = frame.opcode != 0;
            if starts && frame.rsv1 {
                if self.read.partial.is_some() || self.read.passing {
                    return Err(protocol("a new message began inside another"));
                }
                if frame.fin {
                    let payload = codec.inflate(&frame.payload)?;
                    emit_message(
                        &mut self.ready,
                        frame.opcode,
                        frame.rsv23,
                        frame.mask,
                        payload,
                        self.max_frame,
                    );
                } else {
                    self.read.partial = Some(Partial {
                        opcode: frame.opcode,
                        mask: frame.mask,
                        payload: frame.payload,
                    });
                }
                continue;
            }
            if frame.opcode == 0 {
                if let Some(partial) = self.read.partial.as_mut() {
                    if frame.rsv1 {
                        return Err(protocol("RSV1 on a continuation frame"));
                    }
                    if partial.payload.len() + frame.payload.len() > max {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("compressed message exceeds {max} bytes"),
                        ));
                    }
                    partial.payload.extend_from_slice(&frame.payload);
                    if frame.fin {
                        let partial = self.read.partial.take().expect("checked above");
                        let payload = codec.inflate(&partial.payload)?;
                        emit_message(
                            &mut self.ready,
                            partial.opcode,
                            frame.rsv23,
                            partial.mask,
                            payload,
                            self.max_frame,
                        );
                    }
                    continue;
                }
            }
            // An uncompressed message, or a stray continuation tungstenite will judge.
            if starts {
                self.read.passing = !frame.fin;
            } else if frame.fin {
                self.read.passing = false;
            }
            frame.encode(&mut self.ready);
        }
    }

    /// Turn what tungstenite wrote into what goes on the wire.
    fn process_write(&mut self) -> io::Result<()> {
        let Mode::Active(codec) = &mut self.mode else {
            self.pending.append(&mut self.write.raw);
            return Ok(());
        };
        loop {
            // Our own writer's frames: bounded by what tungstenite was configured to send, so
            // the limit here only guards against a frame we could not represent.
            let Some((frame, used)) = Frame::parse(&self.write.raw, usize::MAX / 2)? else {
                return Ok(());
            };
            self.write.raw.drain(..used);
            if frame.is_control_frame() {
                frame.encode(&mut self.pending);
                continue;
            }
            let partial = match (frame.opcode, self.write.partial.take()) {
                (0, Some(mut p)) => {
                    p.payload.extend_from_slice(&frame.payload);
                    p
                }
                (0, None) => {
                    frame.encode(&mut self.pending);
                    continue;
                }
                (op, _) => Partial {
                    opcode: op,
                    mask: frame.mask,
                    payload: frame.payload,
                },
            };
            if !frame.fin {
                self.write.partial = Some(partial);
                continue;
            }
            let payload = codec.deflate(&partial.payload)?;
            Frame {
                fin: true,
                rsv1: true,
                rsv23: 0,
                opcode: partial.opcode,
                mask: partial.mask,
                payload,
            }
            .encode(&mut self.pending);
        }
    }
}

/// An inflated message as frames of at most `max_frame` bytes each, so tungstenite's own frame
/// limit judges the frames the peer sent rather than the size the message inflated to.
fn emit_message(
    out: &mut Vec<u8>,
    opcode: u8,
    rsv23: u8,
    mask: Option<[u8; 4]>,
    payload: Vec<u8>,
    max_frame: usize,
) {
    if payload.len() <= max_frame {
        Frame {
            fin: true,
            rsv1: false,
            rsv23,
            opcode,
            mask,
            payload,
        }
        .encode(out);
        return;
    }
    let chunks: Vec<&[u8]> = payload.chunks(max_frame).collect();
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.into_iter().enumerate() {
        Frame {
            fin: i == last,
            rsv1: false,
            rsv23,
            opcode: if i == 0 { opcode } else { 0 },
            mask,
            payload: chunk.to_vec(),
        }
        .encode(out);
    }
}

fn protocol(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("permessage-deflate: {msg}"),
    )
}

impl<S: AsyncRead + AsyncWrite + Unpin> DeflateStream<S> {
    /// Write `pending` to the socket; `Ready(Ok)` once it is empty.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.pending.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for DeflateStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.ready.is_empty() {
                let n = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready[..n]);
                this.ready.drain(..n);
                return Poll::Ready(Ok(()));
            }
            // Anything already buffered (the server's handshake leftover) first.
            if !this.read.raw.is_empty() {
                let before = this.read.raw.len();
                this.process_read()?;
                if !this.ready.is_empty() {
                    continue;
                }
                if this.read.raw.len() != before {
                    continue;
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let got = rb.filled();
                    if got.is_empty() {
                        // EOF: a frame cut off mid-way is simply not delivered; tungstenite
                        // sees the stream end.
                        return Poll::Ready(Ok(()));
                    }
                    this.read.raw.extend_from_slice(got);
                    this.process_read()?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for DeflateStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Keep at most one message's worth queued for the socket: past that, wait for it.
        if this.pending.len() > this.max_message {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.write.raw.extend_from_slice(buf);
        this.process_write()?;
        // Push what is ready without waiting; flush finishes the job.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
