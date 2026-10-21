//! SUCI concealment (TS 33.501 Annex C): the ECIES Profile A (X25519) and Profile B (secp256r1,
//! compressed points) schemes a UE uses to hide its MSIN, and the home network's deconcealment.
//!
//! Both profiles derive 64 octets with the ANSI X9.63 KDF (SHA-256) from the ECDH shared secret,
//! with the ephemeral public key as SharedInfo: an AES-128 key, a 128-bit initial counter block
//! and a 256-bit HMAC-SHA-256 key. The scheme output is the ephemeral public key, the AES-128-CTR
//! ciphertext of the BCD MSIN, and the first 8 octets of the HMAC over the ciphertext (Annex
//! C.3.2/C.3.3). `tests/server/ngap/security_test.rs` checks every step against the Annex C.4.3
//! and C.4.4 vectors.
//!
//! The home network private key is a startup parameter whose name redacts it; it never reaches an
//! event.

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const PROFILE_A: u8 = 1;
pub const PROFILE_B: u8 = 2;
const MAC_LEN: usize = 8;

/// The ANSI X9.63 KDF with SHA-256 (Annex C.3.4, SEC 1 section 3.6.1).
pub fn x963_kdf(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

struct Keys {
    enc: [u8; 16],
    icb: [u8; 16],
    mac: [u8; 32],
}

fn keys(shared: &[u8], eph_public: &[u8]) -> Keys {
    let k = x963_kdf(shared, eph_public, 64);
    let mut enc = [0u8; 16];
    let mut icb = [0u8; 16];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[0..16]);
    icb.copy_from_slice(&k[16..32]);
    mac.copy_from_slice(&k[32..64]);
    Keys { enc, icb, mac }
}

fn tag(mac_key: &[u8; 32], ciphertext: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("any key length");
    m.update(ciphertext);
    let full = m.finalize().into_bytes();
    let mut t = [0u8; MAC_LEN];
    t.copy_from_slice(&full[..MAC_LEN]);
    t
}

fn ctr(k: &Keys, data: &mut [u8]) {
    let mut c = ctr::Ctr128BE::<aes::Aes128>::new(&k.enc.into(), &k.icb.into());
    c.apply_keystream(data);
}

/// The ECDH shared secret of a profile, from the home network's private key and the UE's
/// ephemeral public key as it crossed the wire.
fn shared_secret(
    profile: u8,
    private_key: &[u8; 32],
    eph_public: &[u8],
) -> Result<Vec<u8>, String> {
    match profile {
        PROFILE_A => {
            let pk: [u8; 32] = eph_public
                .try_into()
                .map_err(|_| "a Profile A ephemeral key is 32 octets".to_string())?;
            let secret = x25519_dalek::StaticSecret::from(*private_key);
            Ok(secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(pk))
                .as_bytes()
                .to_vec())
        }
        PROFILE_B => {
            let sk = p256::SecretKey::from_slice(private_key).map_err(|_| {
                "the Profile B private key is not a valid secp256r1 scalar".to_string()
            })?;
            let pk = p256::PublicKey::from_sec1_bytes(eph_public)
                .map_err(|_| "the Profile B ephemeral key is not a secp256r1 point".to_string())?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        other => Err(format!("protection scheme {other} is not an ECIES profile")),
    }
}

fn eph_len(profile: u8) -> usize {
    if profile == PROFILE_A {
        32
    } else {
        33
    }
}

/// Recover the scheme input (the BCD MSIN) from a Profile A or B scheme output. Refuses an output
/// whose MAC tag does not verify.
pub fn deconceal(
    profile: u8,
    private_key: &[u8; 32],
    scheme_output: &[u8],
) -> Result<Vec<u8>, String> {
    let n = eph_len(profile);
    if scheme_output.len() < n + MAC_LEN + 1 {
        return Err(format!(
            "a profile {profile} scheme output of {} octets is too short",
            scheme_output.len()
        ));
    }
    let eph = &scheme_output[..n];
    let ct = &scheme_output[n..scheme_output.len() - MAC_LEN];
    let received = &scheme_output[scheme_output.len() - MAC_LEN..];
    let shared = shared_secret(profile, private_key, eph)?;
    let k = keys(&shared, eph);
    if !super::security::constant_time_eq(&tag(&k.mac, ct), received) {
        return Err("the SUCI MAC tag does not verify".into());
    }
    let mut plain = ct.to_vec();
    ctr(&k, &mut plain);
    Ok(plain)
}

/// Conceal `plain` for a home network public key with the given ephemeral private key (a UE's
/// side; tests pass a fixed key to reproduce Annex C.4).
pub fn conceal(
    profile: u8,
    home_public: &[u8],
    eph_private: &[u8; 32],
    plain: &[u8],
) -> Result<Vec<u8>, String> {
    let (eph_public, shared) = match profile {
        PROFILE_A => {
            let hp: [u8; 32] = home_public
                .try_into()
                .map_err(|_| "a Profile A home network public key is 32 octets".to_string())?;
            let sk = x25519_dalek::StaticSecret::from(*eph_private);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(hp));
            (pk.as_bytes().to_vec(), shared.as_bytes().to_vec())
        }
        PROFILE_B => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let sk = p256::SecretKey::from_slice(eph_private)
                .map_err(|_| "the ephemeral key is not a valid secp256r1 scalar".to_string())?;
            let hp = p256::PublicKey::from_sec1_bytes(home_public)
                .map_err(|_| "the home network public key is not a secp256r1 point".to_string())?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), hp.as_affine());
            (
                sk.public_key().to_encoded_point(true).as_bytes().to_vec(),
                shared.raw_secret_bytes().to_vec(),
            )
        }
        other => return Err(format!("protection scheme {other} is not an ECIES profile")),
    };
    let k = keys(&shared, &eph_public);
    let mut ct = plain.to_vec();
    ctr(&k, &mut ct);
    let t = tag(&k.mac, &ct);
    let mut out = eph_public;
    out.extend_from_slice(&ct);
    out.extend_from_slice(&t);
    Ok(out)
}
