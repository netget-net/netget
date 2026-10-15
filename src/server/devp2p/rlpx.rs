//! RLPx: the encrypted, authenticated transport every devp2p connection runs on.
//!
//! **Handshake** (EIP-8 form, the only one go-ethereum still accepts). The dialler knows the
//! listener's node id. It sends `auth` = ECIES-to-the-listener of
//! `rlp([sig, initiator-id, initiator-nonce, 4])` plus 100–199 bytes of padding, where `sig` is a
//! recoverable signature by a fresh **ephemeral** key over `static-shared-secret ⊕ nonce`. The
//! listener recovers the dialler's ephemeral public key from that signature and answers `ack` =
//! ECIES-to-the-dialler of `rlp([listener-ephemeral-id, listener-nonce, 4])` plus padding. Each
//! packet is prefixed with its big-endian `u16` length, which is also ECIES's authenticated
//! shared data. Both packets are bounded at [`MAX_HANDSHAKE_BYTES`] before anything is read for
//! them.
//!
//! **Secrets**. With `ecdhe` the x-coordinate of the two ephemeral keys' ECDH:
//! `shared = keccak(ecdhe ‖ keccak(resp-nonce ‖ init-nonce))`, `aes = keccak(ecdhe ‖ shared)`,
//! `mac = keccak(ecdhe ‖ aes)`. The dialler's egress MAC is a running keccak seeded with
//! `(mac ⊕ resp-nonce) ‖ auth-packet`, its ingress MAC with `(mac ⊕ init-nonce) ‖ ack-packet`;
//! the listener's are the same two, swapped.
//!
//! **Frames**. `header (16, AES-256-CTR) ‖ header-mac (16) ‖ frame (padded to 16, same CTR
//! stream) ‖ frame-mac (16)`. The header is a 24-bit frame size and `rlp([0, 0])`. Both MACs are
//! go-ethereum's legacy construction: AES-256-ECB (key `mac`) of the running keccak's digest,
//! XORed with a seed, fed back into the keccak, digest truncated to 16 bytes. Every MAC is
//! checked, in constant time, **before** the bytes it covers are decrypted, and a frame's size
//! is checked against the reader's bound before its body is read.
//!
//! **Compression**. Once both Hellos are exchanged and the peer's base-protocol version is 5 or
//! more, every message payload is a Snappy block. The declared decompressed length is checked
//! against the bound before a byte is decompressed.
use super::crypto::{self, NodeKey, ECIES_OVERHEAD};
use super::rlp::{self, Rlp};
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use anyhow::{ensure, Context, Result};
use rand::Rng;
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest handshake packet accepted (go-ethereum's own bound).
pub const MAX_HANDSHAKE_BYTES: usize = 2048;
/// RLPx frame sizes are 24-bit.
pub const MAX_FRAME_SIZE: usize = 0xff_ffff;
/// The frame header's protocol data: `rlp([0, 0])` (capability id and context id, both unused).
const HEADER_DATA: [u8; 3] = [0xc2, 0x80, 0x80];

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// What the handshake produced.
pub struct Secrets {
    pub aes: [u8; 32],
    pub mac: [u8; 32],
    pub egress_mac: Keccak256,
    pub ingress_mac: Keccak256,
    /// The peer's static public key: the one we dialled, or the one the dialler proved.
    pub remote: PublicKey,
}

/// A decoded `auth` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMsg {
    pub signature: [u8; 65],
    pub initiator_id: [u8; 64],
    pub nonce: [u8; 32],
    pub version: u64,
}

/// A decoded `ack` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckMsg {
    pub ephemeral_id: [u8; 64],
    pub nonce: [u8; 32],
    pub version: u64,
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Decrypt a complete handshake packet (`prefix ‖ ciphertext`) addressed to `key`.
pub fn open_packet(key: &NodeKey, packet: &[u8]) -> Result<Vec<u8>> {
    ensure!(packet.len() > 2, "handshake packet is empty");
    crypto::ecies_decrypt(key.secret(), &packet[2..], &packet[..2])
}

/// Decode an `auth` body. Extra list elements and trailing padding are ignored, as EIP-8
/// requires for forward compatibility.
pub fn parse_auth(plain: &[u8]) -> Result<AuthMsg> {
    let (item, _) = rlp::decode_prefix(plain).context("auth body is not RLP")?;
    let l = item.as_list().context("auth body")?;
    ensure!(l.len() >= 4, "auth body has {} fields, not 4", l.len());
    Ok(AuthMsg {
        signature: l[0].as_fixed().context("auth signature")?,
        initiator_id: l[1].as_fixed().context("auth initiator id")?,
        nonce: l[2].as_fixed().context("auth nonce")?,
        version: l[3].as_u64().context("auth version")?,
    })
}

/// Decode an `ack` body.
pub fn parse_ack(plain: &[u8]) -> Result<AckMsg> {
    let (item, _) = rlp::decode_prefix(plain).context("ack body is not RLP")?;
    let l = item.as_list().context("ack body")?;
    ensure!(l.len() >= 3, "ack body has {} fields, not 3", l.len());
    Ok(AckMsg {
        ephemeral_id: l[0].as_fixed().context("ack ephemeral key")?,
        nonce: l[1].as_fixed().context("ack nonce")?,
        version: l[2].as_u64().context("ack version")?,
    })
}

/// Encrypt a handshake body to `remote`, padded and size-prefixed.
pub fn seal(remote: &PublicKey, body: Rlp) -> Vec<u8> {
    let mut plain = body.encode();
    let pad = rand::thread_rng().gen_range(100..200);
    plain.resize(plain.len() + pad, 0);
    let size = (plain.len() + ECIES_OVERHEAD) as u16;
    let prefix = size.to_be_bytes();
    let mut out = prefix.to_vec();
    out.extend_from_slice(&crypto::ecies_encrypt(remote, &plain, &prefix));
    out
}

/// Read one size-prefixed handshake packet, refusing a size above the bound before reading it.
pub async fn read_packet<S: AsyncRead + Unpin>(io: &mut S) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    io.read_exact(&mut prefix)
        .await
        .context("reading the handshake size")?;
    let size = usize::from(u16::from_be_bytes(prefix));
    ensure!(
        size <= MAX_HANDSHAKE_BYTES,
        "handshake packet of {size} bytes is above the {MAX_HANDSHAKE_BYTES}-byte bound"
    );
    ensure!(
        size > ECIES_OVERHEAD,
        "handshake packet of {size} bytes cannot hold an ECIES message"
    );
    let mut packet = vec![0u8; 2 + size];
    packet[..2].copy_from_slice(&prefix);
    io.read_exact(&mut packet[2..])
        .await
        .context("reading the handshake packet")?;
    Ok(packet)
}

/// Derive the session secrets once both packets and both nonces are known.
#[allow(clippy::too_many_arguments)]
pub fn derive_secrets(
    initiator: bool,
    ephemeral: &NodeKey,
    remote_ephemeral: &PublicKey,
    init_nonce: &[u8; 32],
    resp_nonce: &[u8; 32],
    auth_packet: &[u8],
    ack_packet: &[u8],
    remote: PublicKey,
) -> Secrets {
    let ecdhe = crypto::ecdh_x(ephemeral.secret(), remote_ephemeral);
    let shared = crypto::keccak256(&[&ecdhe, &crypto::keccak256(&[resp_nonce, init_nonce])]);
    let aes = crypto::keccak256(&[&ecdhe, &shared]);
    let mac = crypto::keccak256(&[&ecdhe, &aes]);
    let mut mac1 = Keccak256::new();
    mac1.update(xor32(&mac, resp_nonce));
    mac1.update(auth_packet);
    let mut mac2 = Keccak256::new();
    mac2.update(xor32(&mac, init_nonce));
    mac2.update(ack_packet);
    let (egress_mac, ingress_mac) = if initiator {
        (mac1, mac2)
    } else {
        (mac2, mac1)
    };
    Secrets {
        aes,
        mac,
        egress_mac,
        ingress_mac,
        remote,
    }
}

/// Dial side: send `auth`, read `ack`.
pub async fn initiate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    key: &NodeKey,
    remote: &PublicKey,
) -> Result<Secrets> {
    let ephemeral = NodeKey::random();
    let mut init_nonce = [0u8; 32];
    rand::thread_rng().fill(&mut init_nonce);
    let token = crypto::ecdh_x(key.secret(), remote);
    let signature = crypto::sign_recoverable(&xor32(&token, &init_nonce), ephemeral.secret());
    let auth = seal(
        remote,
        Rlp::List(vec![
            Rlp::bytes(&signature),
            Rlp::bytes(&key.id()),
            Rlp::bytes(&init_nonce),
            Rlp::uint(4),
        ]),
    );
    w.write_all(&auth).await.context("writing auth")?;
    w.flush().await?;
    let ack_packet = read_packet(r).await?;
    let ack = parse_ack(&open_packet(key, &ack_packet).context("decrypting ack")?)?;
    let remote_ephemeral = crypto::public_from_id(&ack.ephemeral_id).context("ack ephemeral")?;
    Ok(derive_secrets(
        true,
        &ephemeral,
        &remote_ephemeral,
        &init_nonce,
        &ack.nonce,
        &auth,
        &ack_packet,
        *remote,
    ))
}

/// The listener's view of a verified `auth`: who dialled, and their ephemeral key.
pub struct AcceptedAuth {
    pub auth: AuthMsg,
    pub initiator: PublicKey,
    pub remote_ephemeral: PublicKey,
}

/// Verify an `auth` body: the initiator id is a point, and the signature recovers to a key.
pub fn accept_auth(key: &NodeKey, auth: AuthMsg) -> Result<AcceptedAuth> {
    let initiator = crypto::public_from_id(&auth.initiator_id).context("auth initiator id")?;
    let token = crypto::ecdh_x(key.secret(), &initiator);
    let remote_ephemeral =
        crypto::recover(&xor32(&token, &auth.nonce), &auth.signature).context("auth signature")?;
    Ok(AcceptedAuth {
        auth,
        initiator,
        remote_ephemeral,
    })
}

/// Listen side: read `auth`, send `ack`.
pub async fn respond<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    key: &NodeKey,
) -> Result<Secrets> {
    let auth_packet = read_packet(r).await?;
    let auth = parse_auth(&open_packet(key, &auth_packet).context("decrypting auth")?)?;
    let accepted = accept_auth(key, auth)?;
    let ephemeral = NodeKey::random();
    let mut resp_nonce = [0u8; 32];
    rand::thread_rng().fill(&mut resp_nonce);
    let ack = seal(
        &accepted.initiator,
        Rlp::List(vec![
            Rlp::bytes(&ephemeral.id()),
            Rlp::bytes(&resp_nonce),
            Rlp::uint(4),
        ]),
    );
    w.write_all(&ack).await.context("writing ack")?;
    w.flush().await?;
    Ok(derive_secrets(
        false,
        &ephemeral,
        &accepted.remote_ephemeral,
        &accepted.auth.nonce,
        &resp_nonce,
        &auth_packet,
        &ack,
        accepted.initiator,
    ))
}

/// One direction's MAC state.
struct MacState {
    cipher: aes::Aes256,
    hash: Keccak256,
}

impl MacState {
    fn new(mac_secret: &[u8; 32], hash: Keccak256) -> Self {
        MacState {
            cipher: aes::Aes256::new(mac_secret.into()),
            hash,
        }
    }

    fn digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }

    fn compute(&mut self, sum1: &[u8; 32], seed: &[u8]) -> [u8; 16] {
        let mut first = [0u8; 16];
        first.copy_from_slice(&sum1[..16]);
        let mut block = aes::Block::from(first);
        self.cipher.encrypt_block(&mut block);
        for (b, s) in block.iter_mut().zip(seed) {
            *b ^= s;
        }
        self.hash.update(block);
        let sum2 = self.digest();
        let mut out = [0u8; 16];
        out.copy_from_slice(&sum2[..16]);
        out
    }

    fn header(&mut self, header_ciphertext: &[u8]) -> [u8; 16] {
        let sum1 = self.digest();
        self.compute(&sum1, header_ciphertext)
    }

    fn frame(&mut self, frame_ciphertext: &[u8]) -> [u8; 16] {
        self.hash.update(frame_ciphertext);
        let seed = self.digest();
        self.compute(&seed, &seed[..16])
    }
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// A size above the reader's bound, refused before the body was read or decompressed.
    TooLarge {
        declared: usize,
        bound: usize,
    },
    /// A MAC mismatch, a bad code, bad Snappy: the peer is not speaking RLPx with us.
    Protocol(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "{e}"),
            FrameError::TooLarge { declared, bound } => {
                write!(f, "{declared} bytes declared, above the {bound}-byte bound")
            }
            FrameError::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// The write half of a session's frame codec.
pub struct FrameWriter {
    enc: Aes256Ctr,
    mac: MacState,
    snappy: bool,
}

/// The read half.
pub struct FrameReader {
    dec: Aes256Ctr,
    mac: MacState,
    snappy: bool,
    /// The largest message accepted, after decompression; frames are bounded by the same
    /// number plus Snappy's worst-case expansion.
    max_message: usize,
}

/// Split the secrets into the two halves of the frame codec.
pub fn codec(secrets: Secrets, max_message: usize) -> (FrameReader, FrameWriter) {
    let iv = [0u8; 16];
    let reader = FrameReader {
        dec: Aes256Ctr::new(&secrets.aes.into(), &iv.into()),
        mac: MacState::new(&secrets.mac, secrets.ingress_mac),
        snappy: false,
        max_message,
    };
    let writer = FrameWriter {
        enc: Aes256Ctr::new(&secrets.aes.into(), &iv.into()),
        mac: MacState::new(&secrets.mac, secrets.egress_mac),
        snappy: false,
    };
    (reader, writer)
}

/// The largest frame a reader with this message bound accepts.
pub fn max_frame_for(max_message: usize) -> usize {
    (snap::raw::max_compress_len(max_message) + 16).min(MAX_FRAME_SIZE)
}

impl FrameWriter {
    pub fn set_snappy(&mut self, on: bool) {
        self.snappy = on;
    }

    /// Encode and encrypt one message.
    pub fn encode(&mut self, code: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let compressed;
        let payload = if self.snappy {
            compressed = snap::raw::Encoder::new()
                .compress_vec(payload)
                .context("snappy compression")?;
            &compressed[..]
        } else {
            payload
        };
        let mut frame = Rlp::uint(code).encode();
        frame.extend_from_slice(payload);
        let fsize = frame.len();
        ensure!(
            fsize <= MAX_FRAME_SIZE,
            "a {fsize}-byte frame does not fit RLPx's 24-bit size"
        );
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&(fsize as u32).to_be_bytes()[1..]);
        header[3..6].copy_from_slice(&HEADER_DATA);
        self.enc.apply_keystream(&mut header);
        let header_mac = self.mac.header(&header);
        frame.resize(fsize.div_ceil(16) * 16, 0);
        self.enc.apply_keystream(&mut frame);
        let frame_mac = self.mac.frame(&frame);
        let mut out = Vec::with_capacity(32 + frame.len() + 16);
        out.extend_from_slice(&header);
        out.extend_from_slice(&header_mac);
        out.extend_from_slice(&frame);
        out.extend_from_slice(&frame_mac);
        Ok(out)
    }
}

impl FrameReader {
    pub fn set_snappy(&mut self, on: bool) {
        self.snappy = on;
    }

    /// Read, verify and decrypt one message: its code and its (decompressed) payload.
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> std::result::Result<(u64, Vec<u8>), FrameError> {
        let mut head = [0u8; 32];
        r.read_exact(&mut head).await?;
        let want = self.mac.header(&head[..16]);
        if !equal(&want, &head[16..]) {
            return Err(FrameError::Protocol("bad frame header MAC".into()));
        }
        self.dec.apply_keystream(&mut head[..16]);
        let fsize =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let bound = max_frame_for(self.max_message);
        if fsize > bound {
            return Err(FrameError::TooLarge {
                declared: fsize,
                bound,
            });
        }
        let padded = fsize.div_ceil(16) * 16;
        let mut frame = vec![0u8; padded + 16];
        r.read_exact(&mut frame).await?;
        let (body, mac) = frame.split_at_mut(padded);
        let want = self.mac.frame(body);
        if !equal(&want, mac) {
            return Err(FrameError::Protocol("bad frame MAC".into()));
        }
        self.dec.apply_keystream(body);
        let body = &body[..fsize];
        let (code, payload) =
            rlp::split_code(body).map_err(|e| FrameError::Protocol(format!("{e:#}")))?;
        if !self.snappy {
            if payload.len() > self.max_message {
                return Err(FrameError::TooLarge {
                    declared: payload.len(),
                    bound: self.max_message,
                });
            }
            return Ok((code, payload.to_vec()));
        }
        let size = snap::raw::decompress_len(payload)
            .map_err(|e| FrameError::Protocol(format!("snappy: {e}")))?;
        if size > self.max_message {
            return Err(FrameError::TooLarge {
                declared: size,
                bound: self.max_message,
            });
        }
        let plain = snap::raw::Decoder::new()
            .decompress_vec(payload)
            .map_err(|e| FrameError::Protocol(format!("snappy: {e}")))?;
        Ok((code, plain))
    }
}
