//! The Stratum V2 secure channel, written from the specification (sv2-spec §4) rather than
//! linked from the Stratum Reference Implementation, so that SRI's binaries are an independent
//! peer: `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`, the authority-signed certificate the
//! responder proves its static key with, and the transport framing that encrypts a frame header
//! and its payload separately.
//!
//! What is borrowed is primitives only: libsecp256k1 (through the `secp256k1` crate) for the
//! ElligatorSwift x-only ECDH and BIP 340 Schnorr signatures, `chacha20poly1305` for the AEAD and
//! `sha2` for SHA-256. The handshake state machine, HMAC, HKDF, the BIP 324 tagged hash over the
//! ECDH point, the certificate layout and the base58check key encoding are this file's own.
use anyhow::{anyhow, bail, ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use secp256k1::{
    ellswift::{ElligatorSwift, ElligatorSwiftParty, ElligatorSwiftSharedSecret},
    schnorr::Signature,
    Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};

/// The Noise protocol name both sides hash into their initial state.
pub const PROTOCOL_NAME: &str = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";
/// An ElligatorSwift-encoded public key.
pub const ELLSWIFT_LEN: usize = 64;
/// A ChaCha20-Poly1305 tag.
pub const MAC_LEN: usize = 16;
/// `SIGNATURE_NOISE_MESSAGE`: version, valid_from, not_valid_after, signature.
pub const SIGNATURE_MESSAGE_LEN: usize = 2 + 4 + 4 + 64;
/// `-> e`: the initiator's ephemeral key in the clear.
pub const INITIATOR_MESSAGE_LEN: usize = ELLSWIFT_LEN;
/// `<- e, ee, s, es`: ephemeral key, encrypted static key, encrypted certificate.
pub const RESPONDER_MESSAGE_LEN: usize =
    ELLSWIFT_LEN + ELLSWIFT_LEN + MAC_LEN + SIGNATURE_MESSAGE_LEN + MAC_LEN;
/// The only certificate format version there is.
pub const CERTIFICATE_VERSION: u16 = 0;
/// Seconds of clock disagreement a certificate's validity window tolerates at either end.
pub const CERTIFICATE_LEEWAY_SECS: u32 = 10;
/// A Noise transport message is at most this long, MAC included.
pub const MAX_CIPHERTEXT_CHUNK: usize = 65535;
/// The plaintext one transport message carries at most.
pub const MAX_PLAINTEXT_CHUNK: usize = MAX_CIPHERTEXT_CHUNK - MAC_LEN;
/// The base58check version prefix of an authority public key (`[1, 0]`, a little-endian U16).
pub const AUTHORITY_KEY_VERSION: u16 = 1;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-SHA256 with a 32-byte key, as the specification spells it out (RFC 2104).
pub fn hmac_sha256(key: &[u8; 32], data: &[&[u8]]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for d in data {
        inner.update(d);
    }
    let inner: [u8; 32] = inner.finalize().into();
    sha256(&[&opad, &inner])
}

/// HKDF with two outputs and an empty info field (RFC 5869), the only form Noise uses.
pub fn hkdf2(chaining_key: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(chaining_key, &[ikm]);
    let out1 = hmac_sha256(&temp, &[&[0x01]]);
    let out2 = hmac_sha256(&temp, &[&out1, &[0x02]]);
    (out1, out2)
}

/// A key and a counter nonce. Without a key it passes data through, as Noise defines.
#[derive(Clone)]
pub struct CipherState {
    key: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {
    pub fn empty() -> Self {
        Self { key: None, n: 0 }
    }

    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: Some(key),
            n: 0,
        }
    }

    /// Messages this state has encrypted or decrypted.
    pub fn nonce_value(&self) -> u64 {
        self.n
    }

    /// 32 zero bits, then the counter as a little-endian 64-bit value (the Noise convention).
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.n.to_le_bytes());
        n
    }

    pub fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = self.key else {
            return Ok(plaintext.to_vec());
        };
        ensure!(self.n != u64::MAX, "Noise nonce exhausted");
        let out = ChaCha20Poly1305::new(&Key::from(key))
            .encrypt(
                &Nonce::from(self.nonce()),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| anyhow!("Noise encryption failed"))?;
        self.n += 1;
        Ok(out)
    }

    /// Decrypt and authenticate; a bad MAC is an error and leaves the nonce where it was.
    pub fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        ensure!(self.n != u64::MAX, "Noise nonce exhausted");
        ensure!(
            ciphertext.len() >= MAC_LEN,
            "Noise message shorter than its MAC"
        );
        let out = ChaCha20Poly1305::new(&Key::from(key))
            .decrypt(
                &Nonce::from(self.nonce()),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| anyhow!("Noise MAC check failed"))?;
        self.n += 1;
        Ok(out)
    }
}

/// The handshake's running state: chaining key, handshake hash and the current cipher.
struct Symmetric {
    ck: [u8; 32],
    h: [u8; 32],
    cipher: CipherState,
}

impl Symmetric {
    fn new() -> Self {
        // The name is longer than a hash, so h = HASH(name); ck = h; then h = HASH(h).
        let h = sha256(&[PROTOCOL_NAME.as_bytes()]);
        Self {
            ck: h,
            h: sha256(&[&h]),
            cipher: CipherState::empty(),
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::with_key(k);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let h = self.h;
        let ct = self.cipher.encrypt(&h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let h = self.h;
        let pt = self.cipher.decrypt(&h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// (initiator → responder, responder → initiator).
    fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::with_key(k1), CipherState::with_key(k2))
    }
}

/// A secp256k1 key and its ElligatorSwift encoding (randomised, so it looks like noise).
pub struct EllKey {
    secret: SecretKey,
    ellswift: [u8; ELLSWIFT_LEN],
}

impl EllKey {
    pub fn generate() -> Self {
        loop {
            if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
                return Self::from_secret(secret);
            }
        }
    }

    pub fn from_secret(secret: SecretKey) -> Self {
        // Encoding needs a context with generator tables, which `ElligatorSwift::new` lacks.
        let ellswift =
            ElligatorSwift::from_seckey(&Secp256k1::new(), secret, Some(rand::random())).to_array();
        Self { secret, ellswift }
    }

    pub fn ellswift(&self) -> [u8; ELLSWIFT_LEN] {
        self.ellswift
    }

    /// The 32-byte x-only (BIP 340) form, which is what a certificate signs.
    pub fn xonly(&self) -> [u8; 32] {
        self.secret
            .x_only_public_key(&Secp256k1::signing_only())
            .0
            .serialize()
    }

    /// `v2_ecdh` (BIP 324): the x coordinate of the shared point from libsecp256k1, hashed here
    /// with the initiator's encoding first whichever side computes it.
    fn ecdh(&self, theirs: &[u8; ELLSWIFT_LEN], initiator: bool) -> [u8; 32] {
        let ours = ElligatorSwift::from_array(self.ellswift);
        let other = ElligatorSwift::from_array(*theirs);
        let (a, b, party) = if initiator {
            (ours, other, ElligatorSwiftParty::A)
        } else {
            (other, ours, ElligatorSwiftParty::B)
        };
        let mut x32 = [0u8; 32];
        ElligatorSwift::shared_secret_with_hasher(a, b, self.secret, party, |x, _, _| {
            x32 = x;
            ElligatorSwiftSharedSecret::from_secret_bytes([0u8; 32])
        });
        let (ell_a, ell_b) = if initiator {
            (self.ellswift, *theirs)
        } else {
            (*theirs, self.ellswift)
        };
        let tag = sha256(&[b"bip324_ellswift_xonly_ecdh"]);
        sha256(&[&tag, &tag, &ell_a, &ell_b, &x32])
    }
}

/// The x-only key an ElligatorSwift encoding decodes to.
pub fn ellswift_xonly(ell: &[u8; ELLSWIFT_LEN]) -> [u8; 32] {
    PublicKey::from_ellswift(ElligatorSwift::from_array(*ell))
        .x_only_public_key()
        .0
        .serialize()
}

/// The pool's certificate authority: signs the static key a responder presents.
pub struct Authority {
    keypair: Keypair,
}

impl Authority {
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        loop {
            if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
                return Self {
                    keypair: Keypair::from_secret_key(&secp, &secret),
                };
            }
        }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let secret = SecretKey::from_slice(bytes).context("not a valid secp256k1 secret key")?;
        Ok(Self {
            keypair: Keypair::from_secret_key(&Secp256k1::new(), &secret),
        })
    }

    pub fn public_xonly(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }

    /// `SIGNATURE_NOISE_MESSAGE` for a static key valid over [valid_from, not_valid_after].
    pub fn certify(
        &self,
        server_xonly: &[u8; 32],
        valid_from: u32,
        not_valid_after: u32,
    ) -> [u8; SIGNATURE_MESSAGE_LEN] {
        let mut out = [0u8; SIGNATURE_MESSAGE_LEN];
        out[0..2].copy_from_slice(&CERTIFICATE_VERSION.to_le_bytes());
        out[2..6].copy_from_slice(&valid_from.to_le_bytes());
        out[6..10].copy_from_slice(&not_valid_after.to_le_bytes());
        let m = certificate_digest(&out[0..10], server_xonly);
        let sig = Secp256k1::signing_only().sign_schnorr_with_aux_rand(
            &Message::from_digest(m),
            &self.keypair,
            &rand::random(),
        );
        out[10..].copy_from_slice(sig.as_ref());
        out
    }
}

/// m = SHA-256(version || valid_from || not_valid_after || server_public_key).
fn certificate_digest(signed_head: &[u8], server_xonly: &[u8; 32]) -> [u8; 32] {
    sha256(&[signed_head, server_xonly])
}

/// What the responder's certificate said, once it verified.
#[derive(Debug, Clone)]
pub struct Certificate {
    pub version: u16,
    pub valid_from: u32,
    pub not_valid_after: u32,
    pub server_xonly: [u8; 32],
}

/// Verify a certificate against the authority key the initiator was configured with.
pub fn verify_certificate(
    message: &[u8; SIGNATURE_MESSAGE_LEN],
    server_xonly: &[u8; 32],
    authority: &[u8; 32],
    now: u32,
) -> Result<Certificate> {
    let version = u16::from_le_bytes([message[0], message[1]]);
    let valid_from = u32::from_le_bytes(message[2..6].try_into().expect("4 bytes"));
    let not_valid_after = u32::from_le_bytes(message[6..10].try_into().expect("4 bytes"));
    ensure!(
        version == CERTIFICATE_VERSION,
        "certificate version {version} is not supported"
    );
    ensure!(
        valid_from.saturating_sub(CERTIFICATE_LEEWAY_SECS) <= now
            && now <= not_valid_after.saturating_add(CERTIFICATE_LEEWAY_SECS),
        "certificate is valid from {valid_from} to {not_valid_after}, and it is {now}"
    );
    let authority = XOnlyPublicKey::from_slice(authority).context("authority key is invalid")?;
    let sig =
        Signature::from_slice(&message[10..]).context("certificate signature is malformed")?;
    let m = certificate_digest(&message[0..10], server_xonly);
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(m), &authority)
        .map_err(|_| anyhow!("certificate is not signed by the configured authority"))?;
    Ok(Certificate {
        version,
        valid_from,
        not_valid_after,
        server_xonly: *server_xonly,
    })
}

/// The two directions of an established session.
pub struct Session {
    pub send: CipherState,
    pub recv: CipherState,
}

/// Responder side: answer `-> e` with `<- e, ee, s, es` and the certificate as its payload.
pub fn respond(
    initiator_message: &[u8; INITIATOR_MESSAGE_LEN],
    static_key: &EllKey,
    authority: &Authority,
    validity_secs: u32,
    now: u32,
) -> Result<([u8; RESPONDER_MESSAGE_LEN], Session)> {
    let mut sym = Symmetric::new();
    let re = *initiator_message;
    sym.mix_hash(&re);
    sym.decrypt_and_hash(&[])?;

    let e = EllKey::generate();
    let mut out = Vec::with_capacity(RESPONDER_MESSAGE_LEN);
    out.extend_from_slice(&e.ellswift());
    sym.mix_hash(&e.ellswift());
    sym.mix_key(&e.ecdh(&re, false));
    out.extend_from_slice(&sym.encrypt_and_hash(&static_key.ellswift())?);
    sym.mix_key(&static_key.ecdh(&re, false));
    let certificate =
        authority.certify(&static_key.xonly(), now, now.saturating_add(validity_secs));
    out.extend_from_slice(&sym.encrypt_and_hash(&certificate)?);
    let (c1, c2) = sym.split();
    let message: [u8; RESPONDER_MESSAGE_LEN] = out
        .try_into()
        .map_err(|_| anyhow!("responder message has the wrong length"))?;
    Ok((message, Session { send: c2, recv: c1 }))
}

/// Initiator side, between its two messages.
pub struct Initiator {
    sym: Symmetric,
    e: EllKey,
}

impl Initiator {
    /// The state and the `-> e` message to send.
    pub fn start() -> Result<(Self, [u8; INITIATOR_MESSAGE_LEN])> {
        let mut sym = Symmetric::new();
        let e = EllKey::generate();
        sym.mix_hash(&e.ellswift());
        sym.encrypt_and_hash(&[])?;
        let msg = e.ellswift();
        Ok((Self { sym, e }, msg))
    }

    /// Process `<- e, ee, s, es`, then check the certificate before trusting anything.
    pub fn finish(
        mut self,
        message: &[u8; RESPONDER_MESSAGE_LEN],
        authority: &[u8; 32],
        now: u32,
    ) -> Result<(Session, Certificate)> {
        let re: [u8; ELLSWIFT_LEN] = message[..ELLSWIFT_LEN].try_into().expect("64 bytes");
        self.sym.mix_hash(&re);
        self.sym.mix_key(&self.e.ecdh(&re, true));
        let rs = self
            .sym
            .decrypt_and_hash(&message[ELLSWIFT_LEN..ELLSWIFT_LEN * 2 + MAC_LEN])
            .context("the responder's static key did not authenticate")?;
        let rs: [u8; ELLSWIFT_LEN] = rs
            .try_into()
            .map_err(|_| anyhow!("static key has the wrong length"))?;
        self.sym.mix_key(&self.e.ecdh(&rs, true));
        let cert = self
            .sym
            .decrypt_and_hash(&message[ELLSWIFT_LEN * 2 + MAC_LEN..])
            .context("the responder's certificate did not authenticate")?;
        let cert: [u8; SIGNATURE_MESSAGE_LEN] = cert
            .try_into()
            .map_err(|_| anyhow!("certificate has the wrong length"))?;
        let certificate = verify_certificate(&cert, &ellswift_xonly(&rs), authority, now)?;
        let (c1, c2) = self.sym.split();
        Ok((Session { send: c1, recv: c2 }, certificate))
    }
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 with a four-byte double-SHA-256 checksum.
pub fn base58check_encode(payload: &[u8]) -> String {
    let check = sha256(&[&sha256(&[payload])]);
    let mut data = payload.to_vec();
    data.extend_from_slice(&check[..4]);
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &data {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| BASE58[*d as usize] as char));
    out
}

pub fn base58check_decode(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len() <= 128, "base58 string is too long");
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes() {
        let Some(value) = BASE58.iter().position(|b| *b == c) else {
            bail!("{:?} is not a base58 character", c as char);
        };
        let mut carry = value as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut data = vec![0u8; zeros];
    data.extend(bytes.iter().rev());
    ensure!(data.len() >= 4, "base58check string is too short");
    let (payload, check) = data.split_at(data.len() - 4);
    ensure!(
        sha256(&[&sha256(&[payload])])[..4] == *check,
        "base58check checksum does not match"
    );
    Ok(payload.to_vec())
}

/// An authority public key as pools publish it: base58check of `[1, 0] || x-only key`.
pub fn encode_authority_key(xonly: &[u8; 32]) -> String {
    let mut payload = AUTHORITY_KEY_VERSION.to_le_bytes().to_vec();
    payload.extend_from_slice(xonly);
    base58check_encode(&payload)
}

pub fn decode_authority_key(text: &str) -> Result<[u8; 32]> {
    let payload = base58check_decode(text.trim())?;
    ensure!(
        payload.len() == 34,
        "an authority public key is 34 bytes once decoded"
    );
    let version = u16::from_le_bytes([payload[0], payload[1]]);
    ensure!(
        version == AUTHORITY_KEY_VERSION,
        "authority key version {version} is not supported"
    );
    let key: [u8; 32] = payload[2..].try_into().expect("32 bytes");
    XOnlyPublicKey::from_slice(&key).context("authority key is not a secp256k1 point")?;
    Ok(key)
}

/// An authority secret key as SRI's configuration writes it: base58check of the 32 bytes.
pub fn decode_secret_key(text: &str) -> Result<Authority> {
    let payload = base58check_decode(text.trim())?;
    ensure!(payload.len() == 32, "a secret key is 32 bytes once decoded");
    Authority::from_secret_bytes(&payload)
}

pub fn encode_secret_key(bytes: &[u8; 32]) -> String {
    base58check_encode(bytes)
}

impl Authority {
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.keypair.secret_bytes()
    }
}
