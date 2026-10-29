//! NVMe/TCP secure channel keys (NVMe TCP Transport 1.1, from TP 8011): the configured PSK's
//! interchange text, the retained PSK, the PSK digest, the TLS PSK and the PSK identity.
//!
//! Both roles use this module: the target (`super`) finds the key a host's identity names, the
//! host (`crate::client::nvme_tcp`) builds the identity it offers. Pure functions on bounded
//! input; nothing here touches a socket or a TLS library.
//!
//! The derivations, as the Linux kernel and current libnvme run them:
//!
//! | Value | Derivation |
//! |---|---|
//! | configured PSK | `NVMeTLSkey-1:<hh>:<base64 of key ‖ CRC-32>:`; `<hh>` 01 (SHA-256) or 02 (SHA-384) names the hash, 00 means the key is used as the retained PSK untransformed |
//! | retained PSK | HKDF-Expand-Label(HKDF-Extract(0, configured), "HostNQN", NQNh, L) |
//! | PSK digest | Base64(HMAC(retained, NQNh ‖ " " ‖ NQNc ‖ " " ‖ "NVMe-over-Fabrics")) |
//! | TLS PSK | HKDF-Expand-Label(HKDF-Extract(0, retained), "nvme-tls-psk", context, L), the context `"<hh> <digest>"` for an identity of version 1 and the identity itself for version 0 |
//! | PSK identity | `NVMe<v>R<hh> <NQNh> <NQNc>`, with ` <digest>` appended for version 1 |
//!
//! HKDF-Expand-Label is TLS 1.3's (RFC 8446 7.1): the info is the output length as two bytes
//! big-endian, then `"tls13 " ‖ label` and the context, each with a one-byte length in front.
//!
//! libnvme 1.8 with OpenSSL 3.0 — what Ubuntu 24.04's `nvme check-tls-key` runs — derives
//! something else. It built the info with four `EVP_PKEY_CTX_add1_hkdf_info` calls, and that
//! OpenSSL replaced the info on each call instead of appending, so its retained PSK is
//! HKDF(configured, info = NQNh) alone. A key that tool inserts cannot be matched by any
//! implementation of the specification, this one included.
use super::auth::Hash;

/// The longest NQN the specification allows (223 bytes) with room to spare; an identity is
/// four fields, so anything longer than this is refused before it is split.
pub const MAX_IDENTITY_LEN: usize = 640;

/// The well-known discovery subsystem NQN, which a host connecting to a discovery controller
/// over TLS names in its identity.
pub use super::nvme::DISCOVERY_NQN;

/// A configured PSK, from its `NVMeTLSkey-1` interchange text. Never printed: `Debug` shows only
/// its length.
#[derive(Clone)]
pub struct ConfiguredKey {
    key: Vec<u8>,
    /// The hash the retained PSK is derived with; `None` for `00`, where the configured key is
    /// itself the retained PSK.
    transform: Option<Hash>,
}

impl std::fmt::Debug for ConfiguredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConfiguredKey({} bytes, redacted)", self.key.len())
    }
}

impl Drop for ConfiguredKey {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

impl ConfiguredKey {
    /// Parse `NVMeTLSkey-1:<hh>:<base64>:`. The key is 32 bytes (SHA-256) or 48 (SHA-384),
    /// followed by its CRC-32 (IEEE, least significant byte first); `<hh>` must agree with the
    /// length unless it is 00.
    pub fn parse(text: &str) -> Result<Self, String> {
        use base64::Engine;
        let rest = text
            .trim()
            .strip_prefix("NVMeTLSkey-1:")
            .ok_or("a TLS key starts NVMeTLSkey-1:")?;
        let (hh, rest) = rest
            .split_once(':')
            .ok_or("a TLS key is NVMeTLSkey-1:<hash>:<base64>:")?;
        let transform = match hh {
            "00" => None,
            "01" => Some(Hash::Sha256),
            "02" => Some(Hash::Sha384),
            _ => return Err("the TLS key's hash field is 00, 01 or 02".into()),
        };
        let b64 = rest.strip_suffix(':').unwrap_or(rest);
        if b64.len() > 128 {
            return Err("the TLS key is too long".into());
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| "the TLS key is not base64".to_string())?;
        if !matches!(raw.len(), 36 | 52) {
            return Err("the TLS key is 32 or 48 bytes with its CRC-32".into());
        }
        let (key, crc) = raw.split_at(raw.len() - 4);
        if crc32fast::hash(key) != u32::from_le_bytes(crc.try_into().expect("4 bytes")) {
            return Err("the TLS key's CRC-32 does not match its key".into());
        }
        if let Some(h) = transform {
            if h.len() != key.len() {
                return Err(format!(
                    "a TLS key with hash {hh} is {} bytes, not {}",
                    h.len(),
                    key.len()
                ));
            }
        }
        Ok(Self {
            key: key.to_vec(),
            transform,
        })
    }

    /// The interchange text of a key (what `nvme gen-tls-key` prints).
    pub fn text(key: &[u8], transform: Option<Hash>) -> String {
        use base64::Engine;
        let mut raw = key.to_vec();
        raw.extend(crc32fast::hash(key).to_le_bytes());
        format!(
            "NVMeTLSkey-1:{:02}:{}:",
            transform.map_or(0, Hash::id),
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    /// The hash of the TLS PSK and of the identity's `<hh>`: the configured hash, or the one
    /// the key's length implies for `00`.
    pub fn hash(&self) -> Hash {
        self.transform.unwrap_or(if self.key.len() == 48 {
            Hash::Sha384
        } else {
            Hash::Sha256
        })
    }

    /// The retained PSK for a host.
    pub fn retained(&self, hostnqn: &str) -> Vec<u8> {
        match self.transform {
            None => self.key.clone(),
            Some(h) => expand_label(h, &self.key, b"HostNQN", hostnqn.as_bytes()),
        }
    }
}

/// HKDF-Extract with a zero salt, then HKDF-Expand-Label to the hash's length.
fn expand_label(hash: Hash, ikm: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let len = hash.len();
    let prk = hash.hmac(&vec![0u8; len], &[ikm]);
    let full_label = [b"tls13 ".as_slice(), label].concat();
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend((len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend(&full_label);
    info.push(context.len() as u8);
    info.extend(context);
    // One HMAC block is the whole output: the length is the hash's own.
    hash.hmac(&prk, &[&info, &[1u8]])
}

/// The PSK digest of a retained PSK for a host and subsystem.
pub fn digest(hash: Hash, retained: &[u8], hostnqn: &str, subnqn: &str) -> String {
    use base64::Engine;
    let mac = hash.hmac(
        retained,
        &[
            hostnqn.as_bytes(),
            b" ",
            subnqn.as_bytes(),
            b" ",
            b"NVMe-over-Fabrics",
        ],
    );
    base64::engine::general_purpose::STANDARD.encode(mac)
}

/// A PSK identity: `NVMe<v>R<hh> <NQNh> <NQNc>[ <digest>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub version: u8,
    pub hash: Hash,
    pub hostnqn: String,
    pub subnqn: String,
    /// The PSK digest, present exactly when `version` is 1.
    pub digest: Option<String>,
}

impl Identity {
    /// Parse an identity. A generated PSK's identity (`G`) belongs to secure channel
    /// concatenation after DH-HMAC-CHAP, which is not implemented, and is refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_IDENTITY_LEN {
            return Err("the PSK identity is too long".into());
        }
        let mut parts = text.split(' ');
        let head = parts.next().unwrap_or_default();
        let b = head.as_bytes();
        if b.len() != 8 || !head.starts_with("NVMe") {
            return Err("a PSK identity starts NVMe<v><R|G><hh>".into());
        }
        let version = match b[4] {
            b'0' => 0,
            b'1' => 1,
            _ => return Err("the PSK identity's version is 0 or 1".into()),
        };
        match b[5] {
            b'R' => {}
            b'G' => {
                return Err(
                    "a generated PSK (secure channel concatenation) is not supported".into(),
                )
            }
            _ => return Err("the PSK identity names a retained (R) PSK".into()),
        }
        let hash = match &head[6..8] {
            "01" => Hash::Sha256,
            "02" => Hash::Sha384,
            _ => return Err("the PSK identity's hash is 01 or 02".into()),
        };
        let hostnqn = parts.next().filter(|s| !s.is_empty());
        let subnqn = parts.next().filter(|s| !s.is_empty());
        let (Some(hostnqn), Some(subnqn)) = (hostnqn, subnqn) else {
            return Err("a PSK identity names a host NQN and a subsystem NQN".into());
        };
        let digest = parts.next().map(str::to_string);
        if parts.next().is_some() {
            return Err("the PSK identity has more fields than it should".into());
        }
        match (version, &digest) {
            (1, None) => return Err("a version 1 PSK identity ends with the PSK digest".into()),
            (0, Some(_)) => return Err("a version 0 PSK identity has no PSK digest".into()),
            _ => {}
        }
        Ok(Self {
            version,
            hash,
            hostnqn: hostnqn.to_string(),
            subnqn: subnqn.to_string(),
            digest,
        })
    }

    pub fn text(&self) -> String {
        let mut s = format!(
            "NVMe{}R{:02} {} {}",
            self.version,
            self.hash.id(),
            self.hostnqn,
            self.subnqn
        );
        if let Some(d) = &self.digest {
            s.push(' ');
            s.push_str(d);
        }
        s
    }
}

/// The identity a host offers for this key, and the TLS PSK that goes with it.
pub fn host_offer(
    key: &ConfiguredKey,
    hostnqn: &str,
    subnqn: &str,
    version: u8,
) -> (Identity, Vec<u8>) {
    let hash = key.hash();
    let retained = key.retained(hostnqn);
    let identity = Identity {
        version,
        hash,
        hostnqn: hostnqn.to_string(),
        subnqn: subnqn.to_string(),
        digest: (version == 1).then(|| digest(hash, &retained, hostnqn, subnqn)),
    };
    let psk = tls_psk(hash, &retained, &identity);
    (identity, psk)
}

/// The TLS PSK for an identity, from the retained PSK of its host.
pub fn tls_psk(hash: Hash, retained: &[u8], identity: &Identity) -> Vec<u8> {
    let context = match &identity.digest {
        Some(d) => format!("{:02} {d}", hash.id()),
        None => identity.text(),
    };
    expand_label(hash, retained, b"nvme-tls-psk", context.as_bytes())
}

/// Why a target refuses an identity.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed(String),
    /// The identity's hash is not the configured key's.
    WrongHash,
    /// The digest is not the one this key gives for that host and subsystem: the host holds a
    /// different key.
    DigestMismatch,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed PSK identity: {e}"),
            Self::WrongHash => f.write_str("the PSK identity's hash is not the configured key's"),
            Self::DigestMismatch => {
                f.write_str("the PSK digest does not match: the host holds a different key")
            }
        }
    }
}

/// The target's half: the TLS PSK for the identity a host sent, or why there is none.
///
/// Any subsystem may be named: which subsystems exist is decided at Connect, and the Connect
/// on this channel must then name the identity's host and subsystem (or, on the discovery NQN,
/// the discovery controller). The returned identity is what that check holds it to.
pub fn target_psk(
    key: &ConfiguredKey,
    identity_text: &str,
) -> Result<(Identity, Vec<u8>), Refusal> {
    let identity = Identity::parse(identity_text).map_err(Refusal::Malformed)?;
    let hash = key.hash();
    if identity.hash != hash {
        return Err(Refusal::WrongHash);
    }
    let retained = key.retained(&identity.hostnqn);
    if let Some(d) = &identity.digest {
        if *d != digest(hash, &retained, &identity.hostnqn, &identity.subnqn) {
            return Err(Refusal::DigestMismatch);
        }
    }
    let psk = tls_psk(hash, &retained, &identity);
    Ok((identity, psk))
}
