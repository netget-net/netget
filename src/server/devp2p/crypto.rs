//! The cryptography devp2p is built from: secp256k1 node keys, ECDH, recoverable signatures,
//! keccak-256, and the ECIES variant the RLPx handshake encrypts with.
//!
//! ECIES here is go-ethereum's `crypto/ecies` with `ECIES_AES128_SHA256`, the only parameter set
//! RLPx uses: an ephemeral secp256k1 key `R`, `z` = the x-coordinate of `R·pub`, a 32-byte
//! NIST SP 800-56 concatenation KDF over SHA-256 (counter 1, no shared info), `Ke` = the first
//! 16 bytes, `Km` = SHA-256 of the last 16, AES-128-CTR under `Ke` with a random IV, and an
//! HMAC-SHA256 tag under `Km` over `IV ‖ ciphertext ‖ shared_mac_data`. RLPx passes the
//! message's two-byte size prefix as `shared_mac_data`, so the prefix is authenticated too.
//!
//! The wire form is `0x04 ‖ R (64) ‖ IV (16) ‖ ciphertext ‖ tag (32)`: 113 bytes of overhead.
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{bail, ensure, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::sync::LazyLock;

/// Bytes ECIES adds to a plaintext: the ephemeral key, the IV and the tag.
pub const ECIES_OVERHEAD: usize = 65 + 16 + 32;

static SECP: LazyLock<Secp256k1<secp256k1::All>> = LazyLock::new(Secp256k1::new);

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// keccak-256 (the pre-standard Keccak Ethereum uses, not SHA3-256) of the concatenation.
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A node's identity: its secp256k1 key. The node id is the 64-byte uncompressed public key
/// without the `0x04` prefix.
#[derive(Clone)]
pub struct NodeKey {
    secret: SecretKey,
    public: PublicKey,
}

impl NodeKey {
    pub fn random() -> NodeKey {
        loop {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            if let Ok(k) = NodeKey::from_bytes(&b) {
                return k;
            }
        }
    }

    pub fn from_bytes(b: &[u8]) -> Result<NodeKey> {
        let secret = SecretKey::from_slice(b).context("not a valid secp256k1 secret key")?;
        Ok(NodeKey {
            public: PublicKey::from_secret_key(&SECP, &secret),
            secret,
        })
    }

    /// A key written as 64 hex characters, with or without `0x`.
    pub fn from_hex(s: &str) -> Result<NodeKey> {
        let b =
            hex::decode(s.trim().trim_start_matches("0x")).context("the node key is not hex")?;
        ensure!(b.len() == 32, "the node key is {} bytes, not 32", b.len());
        NodeKey::from_bytes(&b)
    }

    pub fn id(&self) -> [u8; 64] {
        node_id(&self.public)
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// The 64-byte node id of a public key.
pub fn node_id(pk: &PublicKey) -> [u8; 64] {
    let full = pk.serialize_uncompressed();
    let mut id = [0u8; 64];
    id.copy_from_slice(&full[1..]);
    id
}

/// The public key a 64-byte node id names, refused when it is not a point on the curve.
pub fn public_from_id(id: &[u8]) -> Result<PublicKey> {
    ensure!(id.len() == 64, "a node id is 64 bytes, not {}", id.len());
    let mut full = [0u8; 65];
    full[0] = 4;
    full[1..].copy_from_slice(id);
    PublicKey::from_slice(&full).context("the node id is not a secp256k1 public key")
}

/// The x-coordinate of `secret · public`: the raw ECDH shared secret devp2p uses everywhere.
pub fn ecdh_x(secret: &SecretKey, public: &PublicKey) -> [u8; 32] {
    let point = secp256k1::ecdh::shared_secret_point(public, secret);
    let mut x = [0u8; 32];
    x.copy_from_slice(&point[..32]);
    x
}

/// A recoverable signature over a 32-byte digest, as `r ‖ s ‖ v` with `v` 0 or 1.
pub fn sign_recoverable(digest: &[u8; 32], secret: &SecretKey) -> [u8; 65] {
    let sig = SECP.sign_ecdsa_recoverable(&Message::from_digest(*digest), secret);
    let (rec, rs) = sig.serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&rs);
    out[64] = rec.to_i32() as u8;
    out
}

/// The public key that signed `digest`, from an `r ‖ s ‖ v` signature.
pub fn recover(digest: &[u8; 32], sig: &[u8]) -> Result<PublicKey> {
    ensure!(
        sig.len() == 65,
        "a signature is 65 bytes, not {}",
        sig.len()
    );
    let rec = RecoveryId::from_i32(i32::from(sig[64])).context("bad recovery id")?;
    let sig = RecoverableSignature::from_compact(&sig[..64], rec).context("bad signature")?;
    SECP.recover_ecdsa(&Message::from_digest(*digest), &sig)
        .context("the signature recovers no key")
}

/// NIST SP 800-56 concatenation KDF over SHA-256, 32 bytes, no shared info.
fn concat_kdf(z: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(z);
    h.finalize().into()
}

fn ecies_keys(z: &[u8; 32]) -> ([u8; 16], [u8; 32]) {
    let k = concat_kdf(z);
    let mut ke = [0u8; 16];
    ke.copy_from_slice(&k[..16]);
    let km: [u8; 32] = Sha256::digest(&k[16..]).into();
    (ke, km)
}

fn tag(km: &[u8; 32], iv_and_ciphertext: &[u8], shared_mac_data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(km).expect("HMAC takes any key length");
    mac.update(iv_and_ciphertext);
    mac.update(shared_mac_data);
    mac.finalize().into_bytes().into()
}

/// Encrypt `plain` to `remote`.
pub fn ecies_encrypt(remote: &PublicKey, plain: &[u8], shared_mac_data: &[u8]) -> Vec<u8> {
    let ephemeral = NodeKey::random();
    let z = ecdh_x(ephemeral.secret(), remote);
    let (ke, km) = ecies_keys(&z);
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let mut body = Vec::with_capacity(16 + plain.len());
    body.extend_from_slice(&iv);
    body.extend_from_slice(plain);
    Aes128Ctr::new(&ke.into(), &iv.into()).apply_keystream(&mut body[16..]);
    let t = tag(&km, &body, shared_mac_data);
    let mut out = Vec::with_capacity(ECIES_OVERHEAD + plain.len());
    out.extend_from_slice(&ephemeral.public().serialize_uncompressed());
    out.extend_from_slice(&body);
    out.extend_from_slice(&t);
    out
}

/// Decrypt a message sent to `secret`. The tag is checked before anything is decrypted, in
/// constant time.
pub fn ecies_decrypt(secret: &SecretKey, data: &[u8], shared_mac_data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len() > ECIES_OVERHEAD,
        "ECIES message of {} bytes is shorter than its own overhead",
        data.len()
    );
    if data[0] != 4 {
        bail!("ECIES ephemeral key is not an uncompressed point");
    }
    let ephemeral =
        PublicKey::from_slice(&data[..65]).context("ECIES ephemeral key is not on the curve")?;
    let z = ecdh_x(secret, &ephemeral);
    let (ke, km) = ecies_keys(&z);
    let body = &data[65..data.len() - 32];
    let want = tag(&km, body, shared_mac_data);
    let mut diff = 0u8;
    for (a, b) in want.iter().zip(&data[data.len() - 32..]) {
        diff |= a ^ b;
    }
    ensure!(diff == 0, "ECIES tag mismatch");
    let (iv, ciphertext) = body.split_at(16);
    let mut plain = ciphertext.to_vec();
    let iv: [u8; 16] = iv.try_into().expect("16 bytes");
    Aes128Ctr::new(&ke.into(), &iv.into()).apply_keystream(&mut plain);
    Ok(plain)
}
