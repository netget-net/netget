//! The SPICE wire format, shared by NetGet's server and client.
//!
//! Everything here is little-endian and packed, as `spice/protocol.h` and `spice.proto`
//! (spice-protocol / spice-common) define it:
//!
//! - **Link stage**, once per channel connection: `SpiceLinkHeader` (`REDQ`, 2.2, size), the
//!   client's `SpiceLinkMess` (connection id, channel type and id, capabilities), the server's
//!   `SpiceLinkReply` (error, a 1024-bit RSA public key as an X.509 SubjectPublicKeyInfo,
//!   capabilities), the client's `SpiceLinkAuthMechanism` when both sides offer
//!   `AUTH_SELECTION`, the 128-byte RSA-OAEP ticket, and the server's 4-byte link result.
//! - **Data stage**: every message is a header and a body. With `MINI_HEADER` negotiated by
//!   both sides the header is `type: u16, size: u32`; without it, it is
//!   `serial: u64, type: u16, size: u32, sub_list: u32`.
//!
//! The ticket is the password, NUL-terminated, encrypted with RSA PKCS#1 OAEP (SHA-1 and
//! MGF1-SHA-1, OpenSSL's `RSA_PKCS1_OAEP_PADDING`) under the server's key. That is all SPICE's
//! own authentication is: it hides the password from a passive observer of the link, and it
//! authenticates nothing about the server.
use anyhow::{anyhow, bail, ensure, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

/// `SPICE_MAGIC`: the four bytes `REDQ`.
pub const MAGIC: [u8; 4] = *b"REDQ";
pub const VERSION_MAJOR: u32 = 2;
pub const VERSION_MINOR: u32 = 2;
/// `SpiceLinkHeader`: magic, major, minor, size.
pub const LINK_HEADER_BYTES: usize = 16;
/// The fixed part of `SpiceLinkMess`, before its capability words.
pub const LINK_MESS_BYTES: usize = 18;
/// The fixed part of `SpiceLinkReply`, before its capability words.
pub const LINK_REPLY_BYTES: usize = 4 + TICKET_PUBKEY_BYTES + 12;
/// `SPICE_TICKET_PUBKEY_BYTES`: a 1024-bit RSA key as DER SubjectPublicKeyInfo.
pub const TICKET_PUBKEY_BYTES: usize = 162;
/// An RSA-1024 ciphertext.
pub const TICKET_BYTES: usize = 128;
/// `SPICE_MAX_PASSWORD_LENGTH`.
pub const MAX_PASSWORD_LENGTH: usize = 60;
/// The largest link message (header `size`) either side reads. A real one is 26 to ~200
/// bytes; the size is a peer-chosen `u32`, refused against this before anything is allocated.
pub const MAX_LINK_BYTES: u32 = 4096;
/// The most capability words either side accepts in one list. Every capability defined today
/// fits in one word; the count is a peer-chosen `u32`.
pub const MAX_CAP_WORDS: u32 = 64;
pub const MINI_HEADER_BYTES: usize = 6;
pub const FULL_HEADER_BYTES: usize = 18;

/// Common capabilities (`SPICE_COMMON_CAP_*`), as bit numbers.
pub mod common_cap {
    pub const AUTH_SELECTION: u32 = 0;
    pub const AUTH_SPICE: u32 = 1;
    pub const AUTH_SASL: u32 = 2;
    pub const MINI_HEADER: u32 = 3;
}

/// `SpiceLinkAuthMechanism` values.
pub const AUTH_MECHANISM_SPICE: u32 = 1;

/// Main channel capabilities (`SPICE_MAIN_CAP_*`).
pub mod main_cap {
    pub const NAME_AND_UUID: u32 = 1;
}

/// Display channel capabilities (`SPICE_DISPLAY_CAP_*`).
pub mod display_cap {
    pub const PREF_COMPRESSION: u32 = 6;
}

/// Channel types (`SPICE_CHANNEL_*`).
pub mod channel {
    pub const MAIN: u8 = 1;
    pub const DISPLAY: u8 = 2;
    pub const INPUTS: u8 = 3;
    pub const CURSOR: u8 = 4;
    pub const PLAYBACK: u8 = 5;
    pub const RECORD: u8 = 6;

    pub fn name(t: u8) -> &'static str {
        match t {
            MAIN => "main",
            DISPLAY => "display",
            INPUTS => "inputs",
            CURSOR => "cursor",
            PLAYBACK => "playback",
            RECORD => "record",
            8 => "smartcard",
            9 => "usbredir",
            10 => "port",
            11 => "webdav",
            _ => "unknown",
        }
    }
}

/// Link errors (`SPICE_LINK_ERR_*`), carried in `SpiceLinkReply.error` and the link result.
pub mod link_err {
    pub const OK: u32 = 0;
    pub const ERROR: u32 = 1;
    pub const INVALID_MAGIC: u32 = 2;
    pub const INVALID_DATA: u32 = 3;
    pub const VERSION_MISMATCH: u32 = 4;
    pub const NEED_SECURED: u32 = 5;
    pub const NEED_UNSECURED: u32 = 6;
    pub const PERMISSION_DENIED: u32 = 7;
    pub const BAD_CONNECTION_ID: u32 = 8;
    pub const CHANNEL_NOT_AVAILABLE: u32 = 9;

    pub fn name(code: u32) -> &'static str {
        match code {
            OK => "ok",
            ERROR => "error",
            INVALID_MAGIC => "invalid magic",
            INVALID_DATA => "invalid data",
            VERSION_MISMATCH => "version mismatch",
            NEED_SECURED => "the server requires TLS",
            NEED_UNSECURED => "the server requires a plain connection",
            PERMISSION_DENIED => "permission denied",
            BAD_CONNECTION_ID => "bad connection id",
            CHANNEL_NOT_AVAILABLE => "channel not available",
            _ => "unknown link error",
        }
    }
}

/// Server-to-client message types (`SPICE_MSG_*`).
pub mod msg {
    pub const SET_ACK: u16 = 3;
    pub const PING: u16 = 4;
    pub const WAIT_FOR_CHANNELS: u16 = 5;
    pub const DISCONNECTING: u16 = 6;
    pub const NOTIFY: u16 = 7;

    pub const MAIN_INIT: u16 = 103;
    pub const MAIN_CHANNELS_LIST: u16 = 104;
    pub const MAIN_MOUSE_MODE: u16 = 105;
    pub const MAIN_MULTI_MEDIA_TIME: u16 = 106;
    pub const MAIN_AGENT_CONNECTED: u16 = 107;
    pub const MAIN_AGENT_DISCONNECTED: u16 = 108;
    pub const MAIN_NAME: u16 = 113;
    pub const MAIN_UUID: u16 = 114;

    pub const DISPLAY_MODE: u16 = 101;
    pub const DISPLAY_MARK: u16 = 102;
    pub const DISPLAY_RESET: u16 = 103;
    pub const DISPLAY_COPY_BITS: u16 = 104;
    pub const DISPLAY_INVAL_LIST: u16 = 105;
    pub const DISPLAY_INVAL_ALL_PIXMAPS: u16 = 106;
    pub const DISPLAY_INVAL_PALETTE: u16 = 107;
    pub const DISPLAY_INVAL_ALL_PALETTES: u16 = 108;
    pub const DISPLAY_STREAM_CREATE: u16 = 122;
    pub const DISPLAY_STREAM_DATA: u16 = 123;
    pub const DISPLAY_STREAM_CLIP: u16 = 124;
    pub const DISPLAY_STREAM_DESTROY: u16 = 125;
    pub const DISPLAY_STREAM_DESTROY_ALL: u16 = 126;
    pub const DISPLAY_DRAW_FILL: u16 = 302;
    pub const DISPLAY_DRAW_OPAQUE: u16 = 303;
    pub const DISPLAY_DRAW_COPY: u16 = 304;
    pub const DISPLAY_DRAW_BLEND: u16 = 305;
    pub const DISPLAY_DRAW_BLACKNESS: u16 = 306;
    pub const DISPLAY_DRAW_WHITENESS: u16 = 307;
    pub const DISPLAY_DRAW_INVERS: u16 = 308;
    pub const DISPLAY_DRAW_ROP3: u16 = 309;
    pub const DISPLAY_DRAW_STROKE: u16 = 310;
    pub const DISPLAY_DRAW_TEXT: u16 = 311;
    pub const DISPLAY_DRAW_TRANSPARENT: u16 = 312;
    pub const DISPLAY_DRAW_ALPHA_BLEND: u16 = 313;
    pub const DISPLAY_SURFACE_CREATE: u16 = 314;
    pub const DISPLAY_SURFACE_DESTROY: u16 = 315;
    pub const DISPLAY_STREAM_DATA_SIZED: u16 = 316;
    pub const DISPLAY_MONITORS_CONFIG: u16 = 317;
    pub const DISPLAY_DRAW_COMPOSITE: u16 = 318;

    pub const INPUTS_INIT: u16 = 101;
    pub const INPUTS_KEY_MODIFIERS: u16 = 102;
    pub const INPUTS_MOUSE_MOTION_ACK: u16 = 111;
}

/// Client-to-server message types (`SPICE_MSGC_*`).
pub mod msgc {
    pub const ACK_SYNC: u16 = 1;
    pub const ACK: u16 = 2;
    pub const PONG: u16 = 3;
    pub const DISCONNECTING: u16 = 6;

    pub const MAIN_CLIENT_INFO: u16 = 101;
    pub const MAIN_ATTACH_CHANNELS: u16 = 104;
    pub const MAIN_MOUSE_MODE_REQUEST: u16 = 105;
    pub const MAIN_AGENT_START: u16 = 106;
    pub const MAIN_AGENT_DATA: u16 = 107;
    pub const MAIN_AGENT_TOKEN: u16 = 108;

    pub const DISPLAY_INIT: u16 = 101;
    pub const DISPLAY_STREAM_REPORT: u16 = 102;
    pub const DISPLAY_PREFERRED_COMPRESSION: u16 = 103;

    pub const INPUTS_KEY_DOWN: u16 = 101;
    pub const INPUTS_KEY_UP: u16 = 102;
    pub const INPUTS_KEY_MODIFIERS: u16 = 103;
    pub const INPUTS_KEY_SCANCODE: u16 = 104;
    pub const INPUTS_MOUSE_MOTION: u16 = 111;
    pub const INPUTS_MOUSE_POSITION: u16 = 112;
    pub const INPUTS_MOUSE_PRESS: u16 = 113;
    pub const INPUTS_MOUSE_RELEASE: u16 = 114;
}

/// Mouse modes (`SPICE_MOUSE_MODE_*`): bits in `supported_mouse_modes`.
pub const MOUSE_MODE_SERVER: u32 = 1;
pub const MOUSE_MODE_CLIENT: u32 = 2;

/// Mouse buttons (`SPICE_MOUSE_BUTTON_*`) and the matching `buttons_state` bits.
pub mod button {
    pub const LEFT: u8 = 1;
    pub const MIDDLE: u8 = 2;
    pub const RIGHT: u8 = 3;
    pub const UP: u8 = 4;
    pub const DOWN: u8 = 5;

    pub fn name(b: u8) -> &'static str {
        match b {
            LEFT => "left",
            MIDDLE => "middle",
            RIGHT => "right",
            UP => "scroll_up",
            DOWN => "scroll_down",
            _ => "other",
        }
    }

    /// The `buttons_state` bit for a button, 0 for the wheel and unknown buttons.
    pub fn mask(b: u8) -> u16 {
        match b {
            LEFT => 1,
            MIDDLE => 2,
            RIGHT => 4,
            _ => 0,
        }
    }

    pub fn names_in(state: u16) -> Vec<&'static str> {
        [(1u16, "left"), (2, "middle"), (4, "right")]
            .iter()
            .filter(|(bit, _)| state & bit != 0)
            .map(|(_, n)| *n)
            .collect()
    }
}

/// Surface formats (`SPICE_SURFACE_FMT_*`).
pub const SURFACE_FMT_32_XRGB: u32 = 32;
pub const SURFACE_FLAGS_PRIMARY: u32 = 1;

/// Image types (`SPICE_IMAGE_TYPE_*`).
pub mod image_type {
    pub const BITMAP: u8 = 0;
    pub const QUIC: u8 = 1;
    pub const LZ_PLT: u8 = 100;
    pub const LZ_RGB: u8 = 101;
    pub const GLZ_RGB: u8 = 102;
    pub const FROM_CACHE: u8 = 103;
    pub const SURFACE: u8 = 104;
    pub const JPEG: u8 = 105;
    pub const FROM_CACHE_LOSSLESS: u8 = 106;
    pub const ZLIB_GLZ_RGB: u8 = 107;
    pub const JPEG_ALPHA: u8 = 108;
    pub const LZ4: u8 = 109;

    pub fn name(t: u8) -> &'static str {
        match t {
            BITMAP => "bitmap",
            QUIC => "quic",
            LZ_PLT => "lz_plt",
            LZ_RGB => "lz_rgb",
            GLZ_RGB => "glz_rgb",
            FROM_CACHE => "from_cache",
            SURFACE => "surface",
            JPEG => "jpeg",
            FROM_CACHE_LOSSLESS => "from_cache_lossless",
            ZLIB_GLZ_RGB => "zlib_glz_rgb",
            JPEG_ALPHA => "jpeg_alpha",
            LZ4 => "lz4",
            _ => "unknown",
        }
    }
}

/// `SPICE_IMAGE_FLAGS_CACHE_ME`.
pub const IMAGE_FLAGS_CACHE_ME: u8 = 1;
/// Bitmap formats (`SPICE_BITMAP_FMT_*`) this code reads or writes.
pub const BITMAP_FMT_24BIT: u8 = 7;
pub const BITMAP_FMT_32BIT: u8 = 8;
pub const BITMAP_FMT_RGBA: u8 = 9;
/// `SPICE_BITMAP_FLAGS_PAL_FROM_CACHE`, `SPICE_BITMAP_FLAGS_TOP_DOWN`.
pub const BITMAP_FLAGS_PAL_FROM_CACHE: u8 = 2;
pub const BITMAP_FLAGS_TOP_DOWN: u8 = 4;
/// `SPICE_ROPD_OP_PUT`.
pub const ROPD_OP_PUT: u16 = 1 << 3;
/// `SPICE_IMAGE_SCALE_MODE_NEAREST`.
pub const SCALE_MODE_NEAREST: u8 = 1;
/// `SPICE_IMAGE_COMPRESSION_OFF`, for `SPICE_MSGC_DISPLAY_PREFERRED_COMPRESSION`.
pub const IMAGE_COMPRESSION_OFF: u8 = 1;

/// Notify severities (`SPICE_NOTIFY_SEVERITY_*`) and visibility.
pub const NOTIFY_SEVERITY_INFO: u32 = 0;
pub const NOTIFY_SEVERITY_WARN: u32 = 1;
pub const NOTIFY_SEVERITY_ERROR: u32 = 2;
pub const NOTIFY_VISIBILITY_HIGH: u32 = 2;

pub fn severity_name(s: u32) -> &'static str {
    match s {
        NOTIFY_SEVERITY_INFO => "info",
        NOTIFY_SEVERITY_WARN => "warn",
        NOTIFY_SEVERITY_ERROR => "error",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------------------------
// Little-endian cursor
// ---------------------------------------------------------------------------------------------

/// A bounds-checked little-endian reader over a message body. Every read either returns the
/// value or an error naming the field: nothing here indexes past the end.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn bytes(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| anyhow!("{what}: {n} bytes needed, {} left", self.remaining()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    pub fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.bytes(1, what)?[0])
    }
    pub fn u16(&mut self, what: &str) -> Result<u16> {
        let b = self.bytes(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self, what: &str) -> Result<u32> {
        let b = self.bytes(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn i32(&mut self, what: &str) -> Result<i32> {
        Ok(self.u32(what)? as i32)
    }
    pub fn u64(&mut self, what: &str) -> Result<u64> {
        let b = self.bytes(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}

/// Whether capability `bit` is set in a list of capability words.
pub fn has_cap(caps: &[u32], bit: u32) -> bool {
    caps.get((bit / 32) as usize)
        .is_some_and(|w| w & (1 << (bit % 32)) != 0)
}

/// One capability word with the given bits set.
pub fn caps_word(bits: &[u32]) -> u32 {
    bits.iter()
        .filter(|b| **b < 32)
        .fold(0, |w, b| w | (1 << b))
}

// ---------------------------------------------------------------------------------------------
// Link stage
// ---------------------------------------------------------------------------------------------

/// A `SpiceLinkHeader` around a link body.
pub fn link_header(size: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(LINK_HEADER_BYTES);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&VERSION_MAJOR.to_le_bytes());
    v.extend_from_slice(&VERSION_MINOR.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v
}

/// Why a link header was refused, as the `SPICE_LINK_ERR_*` to answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHeaderError(pub u32);

/// Check a link header and return the size of the body that follows. The size is refused
/// against [`MAX_LINK_BYTES`] here, before anything is read or allocated for it.
pub fn parse_link_header(h: &[u8; LINK_HEADER_BYTES], min: usize) -> Result<u32, LinkHeaderError> {
    if h[0..4] != MAGIC {
        return Err(LinkHeaderError(link_err::INVALID_MAGIC));
    }
    let major = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    if major != VERSION_MAJOR {
        return Err(LinkHeaderError(link_err::VERSION_MISMATCH));
    }
    let size = u32::from_le_bytes([h[12], h[13], h[14], h[15]]);
    if (size as usize) < min || size > MAX_LINK_BYTES {
        return Err(LinkHeaderError(link_err::INVALID_DATA));
    }
    Ok(size)
}

/// Read a capability list of `common` then `channel` words at `offset` within a link body.
fn read_caps(body: &[u8], common: u32, channel: u32, offset: u32) -> Result<(Vec<u32>, Vec<u32>)> {
    ensure!(
        common <= MAX_CAP_WORDS && channel <= MAX_CAP_WORDS,
        "{common} common and {channel} channel capability words; at most {MAX_CAP_WORDS} each"
    );
    let mut c = Cursor::at(body, offset as usize);
    let mut read = |n: u32| -> Result<Vec<u32>> { (0..n).map(|_| c.u32("capability")).collect() };
    let common = read(common)?;
    let channel = read(channel)?;
    Ok((common, channel))
}

/// The client's `SpiceLinkMess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMess {
    pub connection_id: u32,
    pub channel_type: u8,
    pub channel_id: u8,
    pub common_caps: Vec<u32>,
    pub channel_caps: Vec<u32>,
}

impl LinkMess {
    /// Header and body, ready to write.
    pub fn encode(&self) -> Vec<u8> {
        let caps = (self.common_caps.len() + self.channel_caps.len()) * 4;
        let mut v = link_header((LINK_MESS_BYTES + caps) as u32);
        v.extend_from_slice(&self.connection_id.to_le_bytes());
        v.push(self.channel_type);
        v.push(self.channel_id);
        v.extend_from_slice(&(self.common_caps.len() as u32).to_le_bytes());
        v.extend_from_slice(&(self.channel_caps.len() as u32).to_le_bytes());
        v.extend_from_slice(&(LINK_MESS_BYTES as u32).to_le_bytes());
        for w in self.common_caps.iter().chain(&self.channel_caps) {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let connection_id = c.u32("connection id")?;
        let channel_type = c.u8("channel type")?;
        let channel_id = c.u8("channel id")?;
        let common = c.u32("common caps count")?;
        let channel = c.u32("channel caps count")?;
        let offset = c.u32("caps offset")?;
        ensure!(
            offset as usize >= LINK_MESS_BYTES,
            "capabilities at offset {offset} overlap the link message"
        );
        let (common_caps, channel_caps) = read_caps(body, common, channel, offset)?;
        Ok(Self {
            connection_id,
            channel_type,
            channel_id,
            common_caps,
            channel_caps,
        })
    }
}

/// The server's `SpiceLinkReply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkReply {
    pub error: u32,
    pub pubkey: Vec<u8>,
    pub common_caps: Vec<u32>,
    pub channel_caps: Vec<u32>,
}

impl LinkReply {
    pub fn encode(&self) -> Vec<u8> {
        let caps = (self.common_caps.len() + self.channel_caps.len()) * 4;
        let mut v = link_header((LINK_REPLY_BYTES + caps) as u32);
        v.extend_from_slice(&self.error.to_le_bytes());
        let mut key = [0u8; TICKET_PUBKEY_BYTES];
        let n = self.pubkey.len().min(TICKET_PUBKEY_BYTES);
        key[..n].copy_from_slice(&self.pubkey[..n]);
        v.extend_from_slice(&key);
        v.extend_from_slice(&(self.common_caps.len() as u32).to_le_bytes());
        v.extend_from_slice(&(self.channel_caps.len() as u32).to_le_bytes());
        v.extend_from_slice(&(LINK_REPLY_BYTES as u32).to_le_bytes());
        for w in self.common_caps.iter().chain(&self.channel_caps) {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    /// An error-only reply, as spice-server sends one: no key, no capabilities.
    pub fn error(code: u32) -> Vec<u8> {
        Self {
            error: code,
            pubkey: Vec::new(),
            common_caps: Vec::new(),
            channel_caps: Vec::new(),
        }
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let error = c.u32("link error")?;
        if error != link_err::OK {
            return Ok(Self {
                error,
                pubkey: Vec::new(),
                common_caps: Vec::new(),
                channel_caps: Vec::new(),
            });
        }
        let pubkey = c.bytes(TICKET_PUBKEY_BYTES, "public key")?.to_vec();
        let common = c.u32("common caps count")?;
        let channel = c.u32("channel caps count")?;
        let offset = c.u32("caps offset")?;
        ensure!(
            offset as usize >= LINK_REPLY_BYTES,
            "capabilities at offset {offset} overlap the link reply"
        );
        let (common_caps, channel_caps) = read_caps(body, common, channel, offset)?;
        Ok(Self {
            error,
            pubkey,
            common_caps,
            channel_caps,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The ticket
// ---------------------------------------------------------------------------------------------

/// A fresh RSA-1024 key, as spice-server makes one for the link (`SPICE_TICKET_KEY_PAIR_LENGTH`).
pub fn generate_ticket_key() -> Result<rsa::RsaPrivateKey> {
    rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).context("generating the ticket key")
}

/// The public half as the 162-byte X.509 SubjectPublicKeyInfo the link reply carries.
pub fn ticket_public_key(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePublicKey;
    let der = key
        .to_public_key()
        .to_public_key_der()
        .context("encoding the ticket key")?;
    let bytes = der.as_bytes().to_vec();
    ensure!(
        bytes.len() == TICKET_PUBKEY_BYTES,
        "the ticket key encodes to {} bytes, not {TICKET_PUBKEY_BYTES}",
        bytes.len()
    );
    Ok(bytes)
}

/// Encrypt `password` (NUL-terminated, as spice-gtk sends it) under the server's key.
pub fn encrypt_ticket(pubkey_der: &[u8], password: &str) -> Result<Vec<u8>> {
    use rsa::pkcs8::DecodePublicKey;
    ensure!(
        password.len() <= MAX_PASSWORD_LENGTH,
        "a SPICE password is at most {MAX_PASSWORD_LENGTH} bytes"
    );
    let key = rsa::RsaPublicKey::from_public_key_der(pubkey_der)
        .context("the server's ticket key is not an RSA SubjectPublicKeyInfo")?;
    let mut plain = password.as_bytes().to_vec();
    plain.push(0);
    key.encrypt(
        &mut rand::rngs::OsRng,
        rsa::Oaep::new::<sha1::Sha1>(),
        &plain,
    )
    .context("encrypting the ticket")
}

/// Decrypt a ticket and return the password bytes before the first NUL, or `None` when the
/// ciphertext does not decrypt under this key.
pub fn decrypt_ticket(key: &rsa::RsaPrivateKey, ticket: &[u8]) -> Option<Vec<u8>> {
    let plain = key.decrypt(rsa::Oaep::new::<sha1::Sha1>(), ticket).ok()?;
    let end = plain.iter().position(|b| *b == 0).unwrap_or(plain.len());
    Some(plain[..end].to_vec())
}

/// Compare two secrets without stopping at the first difference.
pub fn secrets_equal(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

// ---------------------------------------------------------------------------------------------
// Data stage
// ---------------------------------------------------------------------------------------------

/// A data header: the mini form (`type, size`) or the full one (`serial, type, size, sub_list`).
pub fn data_header(mini: bool, serial: u64, msg_type: u16, size: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(FULL_HEADER_BYTES);
    if !mini {
        v.extend_from_slice(&serial.to_le_bytes());
    }
    v.extend_from_slice(&msg_type.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    if !mini {
        v.extend_from_slice(&0u32.to_le_bytes());
    }
    v
}

/// Why a data message could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The header declared a body larger than the reader accepts; nothing was read for it.
    TooLarge {
        msg_type: u16,
        size: u32,
        max: u32,
    },
    /// The full header carried a sub-message list, which nothing sends any more.
    SubList,
    Io(std::io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::TooLarge {
                msg_type,
                size,
                max,
            } => write!(
                f,
                "message type {msg_type} declares {size} bytes, above the {max} byte limit"
            ),
            ReadError::SubList => write!(f, "a message carried a sub-message list"),
            ReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// Read one data message. The declared size is refused against `max` before the body buffer
/// is allocated.
pub async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    mini: bool,
    max: u32,
) -> std::result::Result<(u16, Vec<u8>), ReadError> {
    let mut h = [0u8; FULL_HEADER_BYTES];
    let n = if mini {
        MINI_HEADER_BYTES
    } else {
        FULL_HEADER_BYTES
    };
    r.read_exact(&mut h[..n]).await?;
    let at = if mini { 0 } else { 8 };
    let msg_type = u16::from_le_bytes([h[at], h[at + 1]]);
    let size = u32::from_le_bytes([h[at + 2], h[at + 3], h[at + 4], h[at + 5]]);
    if !mini && u32::from_le_bytes([h[14], h[15], h[16], h[17]]) != 0 {
        return Err(ReadError::SubList);
    }
    if size > max {
        return Err(ReadError::TooLarge {
            msg_type,
            size,
            max,
        });
    }
    let mut body = vec![0u8; size as usize];
    r.read_exact(&mut body).await?;
    Ok((msg_type, body))
}

// ---------------------------------------------------------------------------------------------
// Message bodies
// ---------------------------------------------------------------------------------------------

/// `SpiceMsgMainInit`.
#[allow(clippy::too_many_arguments)]
pub fn main_init(
    session_id: u32,
    display_channels_hint: u32,
    supported_mouse_modes: u32,
    current_mouse_mode: u32,
    agent_connected: u32,
    agent_tokens: u32,
    multi_media_time: u32,
    ram_hint: u32,
) -> Vec<u8> {
    [
        session_id,
        display_channels_hint,
        supported_mouse_modes,
        current_mouse_mode,
        agent_connected,
        agent_tokens,
        multi_media_time,
        ram_hint,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect()
}

/// `SpiceMsgChannels`: a count, then `(type, id)` pairs.
pub fn channels_list(channels: &[(u8, u8)]) -> Vec<u8> {
    let mut v = (channels.len() as u32).to_le_bytes().to_vec();
    for (t, id) in channels {
        v.push(*t);
        v.push(*id);
    }
    v
}

/// `SpiceMsgMainMouseMode`: supported and current, `u16` each.
pub fn mouse_mode(supported: u16, current: u16) -> Vec<u8> {
    let mut v = supported.to_le_bytes().to_vec();
    v.extend_from_slice(&current.to_le_bytes());
    v
}

/// `SpiceMsgMainName`: the length counts the terminating NUL, which is sent.
pub fn main_name(name: &str) -> Vec<u8> {
    let mut v = ((name.len() + 1) as u32).to_le_bytes().to_vec();
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    v
}

/// `SpiceMsgNotify`. Like spice-server, `message_len` excludes the NUL that follows it.
pub fn notify(time_stamp: u64, severity: u32, what: u32, message: &str) -> Vec<u8> {
    let mut v = time_stamp.to_le_bytes().to_vec();
    v.extend_from_slice(&severity.to_le_bytes());
    v.extend_from_slice(&NOTIFY_VISIBILITY_HIGH.to_le_bytes());
    v.extend_from_slice(&what.to_le_bytes());
    v.extend_from_slice(&(message.len() as u32).to_le_bytes());
    v.extend_from_slice(message.as_bytes());
    v.push(0);
    v
}

/// `SpiceMsgSurfaceCreate`.
pub fn surface_create(
    surface_id: u32,
    width: u32,
    height: u32,
    format: u32,
    flags: u32,
) -> Vec<u8> {
    [surface_id, width, height, format, flags]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

/// A `SpiceRect`, which is `top, left, bottom, right` on the wire.
fn push_rect(v: &mut Vec<u8>, top: i32, left: i32, bottom: i32, right: i32) {
    for x in [top, left, bottom, right] {
        v.extend_from_slice(&x.to_le_bytes());
    }
}

/// The byte offset of the image in a DRAW_COPY whose clip is NONE: DisplayBase (21), the
/// image pointer (4), the source rect (16), rop (2), scale mode (1) and the mask (13).
pub const DRAW_COPY_IMAGE_OFFSET: u32 = 57;

/// `SpiceMsgDisplayDrawCopy` placing an uncompressed 32-bit top-down bitmap of
/// `width` × `height` pixels at (`left`, `top`) on `surface_id`. `bgrx` is `width * 4` bytes
/// a row.
pub fn draw_copy_bitmap(
    surface_id: u32,
    left: u32,
    top: u32,
    width: u32,
    height: u32,
    image_id: u64,
    bgrx: &[u8],
) -> Vec<u8> {
    let stride = width * 4;
    let mut v = Vec::with_capacity(DRAW_COPY_IMAGE_OFFSET as usize + 32 + bgrx.len());
    // DisplayBase: surface, box, clip NONE.
    v.extend_from_slice(&surface_id.to_le_bytes());
    let (t, l) = (top as i32, left as i32);
    push_rect(&mut v, t, l, t + height as i32, l + width as i32);
    v.push(0);
    // Copy: the image, the whole of it as the source, PUT, nearest, no mask.
    v.extend_from_slice(&DRAW_COPY_IMAGE_OFFSET.to_le_bytes());
    push_rect(&mut v, 0, 0, height as i32, width as i32);
    v.extend_from_slice(&ROPD_OP_PUT.to_le_bytes());
    v.push(SCALE_MODE_NEAREST);
    v.push(0); // mask flags
    v.extend_from_slice(&0i32.to_le_bytes()); // mask pos x
    v.extend_from_slice(&0i32.to_le_bytes()); // mask pos y
    v.extend_from_slice(&0u32.to_le_bytes()); // mask bitmap: none
    debug_assert_eq!(v.len(), DRAW_COPY_IMAGE_OFFSET as usize);
    // SpiceImageDescriptor.
    v.extend_from_slice(&image_id.to_le_bytes());
    v.push(image_type::BITMAP);
    v.push(0);
    v.extend_from_slice(&width.to_le_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    // SpiceBitmap: 32-bit, top-down, no palette.
    v.push(BITMAP_FMT_32BIT);
    v.push(BITMAP_FLAGS_TOP_DOWN);
    v.extend_from_slice(&width.to_le_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&stride.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(bgrx);
    v
}

/// A message body whose first field is one `u32`.
pub fn u32_body(x: u32) -> Vec<u8> {
    x.to_le_bytes().to_vec()
}

/// `SpiceMsgcDisplayInit`: pixmap cache id and size (pixels), GLZ dictionary id and window.
pub fn display_init(cache_id: u8, cache_size: i64, glz_id: u8, glz_window: i32) -> Vec<u8> {
    let mut v = vec![cache_id];
    v.extend_from_slice(&cache_size.to_le_bytes());
    v.push(glz_id);
    v.extend_from_slice(&glz_window.to_le_bytes());
    v
}

/// `SpiceMsgPing` answered as `SpiceMsgcPong`: the id and timestamp, without the data.
pub fn pong_for(ping: &[u8]) -> Result<Vec<u8>> {
    if ping.len() < 12 {
        bail!("a PING of {} bytes has no id and timestamp", ping.len());
    }
    Ok(ping[..12].to_vec())
}

/// `SpiceMsgcMouseMotion`.
pub fn mouse_motion(dx: i32, dy: i32, buttons: u16) -> Vec<u8> {
    let mut v = dx.to_le_bytes().to_vec();
    v.extend_from_slice(&dy.to_le_bytes());
    v.extend_from_slice(&buttons.to_le_bytes());
    v
}

/// `SpiceMsgcMousePosition`.
pub fn mouse_position(x: u32, y: u32, buttons: u16, display_id: u8) -> Vec<u8> {
    let mut v = x.to_le_bytes().to_vec();
    v.extend_from_slice(&y.to_le_bytes());
    v.extend_from_slice(&buttons.to_le_bytes());
    v.push(display_id);
    v
}

/// `SpiceMsgcMousePress` / `SpiceMsgcMouseRelease`.
pub fn mouse_button(button: u8, buttons: u16) -> Vec<u8> {
    let mut v = vec![button];
    v.extend_from_slice(&buttons.to_le_bytes());
    v
}
