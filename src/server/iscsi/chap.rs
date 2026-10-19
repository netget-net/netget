//! CHAP for iSCSI (RFC 7143 §12.1.3, RFC 1994): MD5 over the identifier, the secret and the
//! challenge. Checked in Rust against configured secrets; no secret, challenge or response
//! ever reaches the model.
use md5::{Digest, Md5};

/// CHAP_A value for MD5, the only algorithm RFC 7143 requires (and the one every initiator
/// and target in practice offers).
pub const ALGORITHM_MD5: &str = "5";
/// Bytes of challenge we send.
pub const CHALLENGE_LEN: usize = 16;
/// The longest challenge or response we accept from a peer, in bytes (RFC 7143 §12.1.3
/// allows up to 1024 binary bytes).
pub const MAX_BINARY: usize = 1024;

/// The CHAP response: MD5(identifier || secret || challenge).
pub fn response(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update([id]);
    h.update(secret);
    h.update(challenge);
    h.finalize().into()
}

/// A binary value as iSCSI writes it: `0x` and hex.
pub fn encode_binary(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// A binary value in either encoding RFC 7143 §6.1 allows: `0x`/`0X` hex or `0b`/`0B` base64.
pub fn decode_binary(v: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let (prefix, body) = (v.get(..2)?, &v[2..]);
    let out = match prefix {
        "0x" | "0X" => {
            let h = if body.len() % 2 == 1 {
                format!("0{body}")
            } else {
                body.to_string()
            };
            hex::decode(h).ok()?
        }
        "0b" | "0B" => base64::engine::general_purpose::STANDARD
            .decode(body)
            .ok()?,
        _ => return None,
    };
    (!out.is_empty() && out.len() <= MAX_BINARY).then_some(out)
}

/// Compare without stopping at the first difference.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// A fresh identifier and challenge.
pub fn challenge() -> (u8, [u8; CHALLENGE_LEN]) {
    use rand::RngCore;
    let mut c = [0u8; CHALLENGE_LEN];
    rand::thread_rng().fill_bytes(&mut c);
    (rand::random(), c)
}

/// A CHAP name and secret, configured by the operator.
#[derive(Clone)]
pub struct Credential {
    pub name: String,
    pub secret: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .finish()
    }
}
