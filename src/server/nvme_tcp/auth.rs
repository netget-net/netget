//! DH-HMAC-CHAP in-band authentication (NVMe Base 2.x, "Authentication" and "DH-HMAC-CHAP
//! Protocol"), carried by the Fabrics Authentication Send and Authentication Receive commands:
//! the six messages both roles exchange, the secrets (`DHHC-1:` text), the key transformation,
//! the HMAC responses, and the RFC 7919 Diffie-Hellman groups that augment the challenge.
//!
//! Both roles use this module: the target (`super`) checks a host's response and answers its
//! own, the host (`crate::client::nvme_tcp`) does the reverse. Every decoder works on a bounded
//! buffer and never recurses; the fuzz target runs them.
//!
//! The exchange, as the Linux host and target run it:
//!
//! | Step | Command | Message |
//! |---|---|---|
//! | 1 | Authentication Send | AUTH_Negotiate: the hashes and DH groups the host offers |
//! | 2 | Authentication Receive | DH-HMAC-CHAP_Challenge: hash, group, C1, S1, the controller's public value |
//! | 3 | Authentication Send | DH-HMAC-CHAP_Reply: R1, and C2/S2 when the host wants the controller to prove itself, the host's public value |
//! | 4 | Authentication Receive | DH-HMAC-CHAP_Success1 (with R2 when asked) or AUTH_Failure1 |
//! | 5 | Authentication Send | DH-HMAC-CHAP_Success2 (bidirectional only) or AUTH_Failure2 |
//!
//! R1 = HMAC(Kh, Ca1 ‖ S1 ‖ T_ID ‖ SC_C ‖ "HostHost" ‖ NQNh ‖ 00h ‖ NQNc) and
//! R2 = HMAC(Kc, Ca2 ‖ S2 ‖ T_ID ‖ SC_C ‖ "Controller" ‖ NQNc ‖ 00h ‖ NQNh), where K is the
//! secret transformed with its own NQN, and Ca is C itself under the NULL group or
//! HMAC(H(g^xy mod p), C) under an ffdhe group.
use super::ffdhe;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// SECP of every DH-HMAC-CHAP Authentication Send/Receive.
pub const SECP: u8 = 0xE9;
/// SPSP0 and SPSP1 of a DH-HMAC-CHAP transaction.
pub const SPSP0: u8 = 0x01;
pub const SPSP1: u8 = 0x01;
/// AUTH-TYPE: common messages (negotiate, failures) and DH-HMAC-CHAP messages.
pub const TYPE_COMMON: u8 = 0x00;
pub const TYPE_DHCHAP: u8 = 0x01;
/// The DH-HMAC-CHAP protocol identifier in a negotiate descriptor.
pub const AUTHID_DHCHAP: u8 = 0x01;
/// AUTH_Failure RESCODE: authentication failed.
pub const RESCODE_FAILED: u8 = 0x01;
/// A Connect completion's DW0: authentication required (ATR) and secure channel concatenation
/// required (ASCR).
pub const CONNECT_ATR: u32 = 1 << 17;
pub const CONNECT_ASCR: u32 = 1 << 18;
/// The most bytes one authentication message takes or gives here: ffdhe8192's 1024-byte public
/// value and two SHA-512 values fit with room; the Linux host reads 4096.
pub const MAX_MESSAGE: usize = 4096;
/// Hash and DH group identifiers a negotiate descriptor may list (each list is 30 bytes).
pub const MAX_IDS: usize = 30;
/// The negotiate message with its one protocol descriptor.
pub const NEGOTIATE_LEN: usize = 8 + 64;

/// AUTH-ID values.
pub mod msg {
    pub const NEGOTIATE: u8 = 0x00;
    pub const CHALLENGE: u8 = 0x01;
    pub const REPLY: u8 = 0x02;
    pub const SUCCESS1: u8 = 0x03;
    pub const SUCCESS2: u8 = 0x04;
    pub const FAILURE2: u8 = 0xF0;
    pub const FAILURE1: u8 = 0xF1;
}

/// AUTH_Failure reason code explanations.
pub mod reason {
    pub const FAILED: u8 = 0x01;
    pub const NOT_USABLE: u8 = 0x02;
    pub const CONCAT_MISMATCH: u8 = 0x03;
    pub const HASH_UNUSABLE: u8 = 0x04;
    pub const DHGROUP_UNUSABLE: u8 = 0x05;
    pub const INCORRECT_PAYLOAD: u8 = 0x06;
    pub const INCORRECT_MESSAGE: u8 = 0x07;

    pub fn name(r: u8) -> &'static str {
        match r {
            FAILED => "authentication failed",
            NOT_USABLE => "protocol not usable",
            CONCAT_MISMATCH => "secure channel concatenation mismatch",
            HASH_UNUSABLE => "hash function not usable",
            DHGROUP_UNUSABLE => "DH group not usable",
            INCORRECT_PAYLOAD => "incorrect payload",
            INCORRECT_MESSAGE => "incorrect protocol message",
            _ => "unknown reason",
        }
    }
}

/// The hash functions DH-HMAC-CHAP names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub const ALL: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Sha256),
            2 => Some(Self::Sha384),
            3 => Some(Self::Sha512),
            _ => None,
        }
    }
    pub fn id(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
        }
    }
    /// The digest length, which is also the challenge and response length (HL).
    pub fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
    /// `sha256`, or the kernel's configfs form `hmac(sha256)`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        let s = s
            .strip_prefix("hmac(")
            .and_then(|r| r.strip_suffix(')'))
            .unwrap_or(&s);
        Self::ALL.into_iter().find(|h| h.name() == s)
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
    /// HMAC over the parts, in order.
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut m = <M as hmac::digest::KeyInit>::new_from_slice(key)
                .expect("HMAC takes a key of any length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
        match self {
            Self::Sha256 => run::<Hmac<Sha256>>(key, parts),
            Self::Sha384 => run::<Hmac<Sha384>>(key, parts),
            Self::Sha512 => run::<Hmac<Sha512>>(key, parts),
        }
    }
}

/// The DH groups DH-HMAC-CHAP names: NULL (no exchange) and RFC 7919's ffdhe groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhGroup {
    Null,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
}

impl DhGroup {
    pub const ALL: [DhGroup; 6] = [
        DhGroup::Null,
        DhGroup::Ffdhe2048,
        DhGroup::Ffdhe3072,
        DhGroup::Ffdhe4096,
        DhGroup::Ffdhe6144,
        DhGroup::Ffdhe8192,
    ];

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.id() == id)
    }
    pub fn id(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Ffdhe2048 => 1,
            Self::Ffdhe3072 => 2,
            Self::Ffdhe4096 => 3,
            Self::Ffdhe6144 => 4,
            Self::Ffdhe8192 => 5,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::Ffdhe4096 => "ffdhe4096",
            Self::Ffdhe6144 => "ffdhe6144",
            Self::Ffdhe8192 => "ffdhe8192",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|g| g.name() == s)
    }
    /// The public value's length in bytes (DHVLEN); 0 for NULL.
    pub fn value_len(self) -> usize {
        match self {
            Self::Null => 0,
            Self::Ffdhe2048 => 256,
            Self::Ffdhe3072 => 384,
            Self::Ffdhe4096 => 512,
            Self::Ffdhe6144 => 768,
            Self::Ffdhe8192 => 1024,
        }
    }
    fn prime_hex(self) -> Option<&'static str> {
        match self {
            Self::Null => None,
            Self::Ffdhe2048 => Some(ffdhe::FFDHE2048),
            Self::Ffdhe3072 => Some(ffdhe::FFDHE3072),
            Self::Ffdhe4096 => Some(ffdhe::FFDHE4096),
            Self::Ffdhe6144 => Some(ffdhe::FFDHE6144),
            Self::Ffdhe8192 => Some(ffdhe::FFDHE8192),
        }
    }
    pub fn prime(self) -> Option<BigUint> {
        self.prime_hex()
            .map(|h| BigUint::parse_bytes(h.as_bytes(), 16).expect("an RFC 7919 prime"))
    }
    /// Private exponent bits: twice the group's security strength (NIST SP 800-56A rev. 3,
    /// as the Linux kernel's ffdhe groups use).
    pub fn private_bits(self) -> usize {
        match self {
            Self::Null => 0,
            Self::Ffdhe2048 => 224,
            Self::Ffdhe3072 => 256,
            Self::Ffdhe4096 => 304,
            Self::Ffdhe6144 => 352,
            Self::Ffdhe8192 => 400,
        }
    }
}

/// Parse a comma-separated preference list of hashes or groups.
pub fn parse_list<T>(s: &str, one: impl Fn(&str) -> Option<T>) -> Option<Vec<T>> {
    let items: Option<Vec<T>> = s
        .split(',')
        .filter(|p| !p.trim().is_empty())
        .map(one)
        .collect();
    items.filter(|v| !v.is_empty())
}

/// A DH-HMAC-CHAP secret, from its `DHHC-1:<hh>:<base64 of key ‖ CRC-32>:` text. `<hh>` names
/// the hash the key is transformed with before use (00: none). Never printed: `Debug` shows
/// only its length.
#[derive(Clone)]
pub struct Secret {
    key: Vec<u8>,
    transform: Option<Hash>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes, redacted)", self.key.len())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

impl Secret {
    /// Parse the `DHHC-1` text. The key is 32, 48 or 64 bytes, followed by its CRC-32 (IEEE,
    /// least significant byte first); the hash field is 00 to 03.
    pub fn parse(text: &str) -> Result<Self, String> {
        use base64::Engine;
        let text = text.trim();
        let rest = text
            .strip_prefix("DHHC-1:")
            .ok_or("a DH-HMAC-CHAP secret starts DHHC-1:")?;
        let (hash, rest) = rest
            .split_once(':')
            .ok_or("a DH-HMAC-CHAP secret is DHHC-1:<hash>:<base64>:")?;
        let transform = match hash {
            "00" => None,
            "01" | "02" | "03" => Hash::from_id(hash.as_bytes()[1] - b'0'),
            _ => return Err("the secret's hash field is 00, 01, 02 or 03".into()),
        };
        let b64 = rest.strip_suffix(':').unwrap_or(rest);
        if b64.len() > 256 {
            return Err("the secret's key is too long".into());
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| "the secret's key is not base64".to_string())?;
        if !matches!(raw.len(), 36 | 52 | 68) {
            return Err("the secret's key is 32, 48 or 64 bytes with its CRC-32".into());
        }
        let (key, crc) = raw.split_at(raw.len() - 4);
        if crc32fast::hash(key) != u32::from_le_bytes(crc.try_into().expect("4 bytes")) {
            return Err("the secret's CRC-32 does not match its key".into());
        }
        Ok(Self {
            key: key.to_vec(),
            transform,
        })
    }

    /// The `DHHC-1` text of a key (what `nvme gen-dhchap-key` prints).
    pub fn text(key: &[u8], transform: Option<Hash>) -> String {
        use base64::Engine;
        let mut raw = key.to_vec();
        raw.extend(crc32fast::hash(key).to_le_bytes());
        format!(
            "DHHC-1:{:02}:{}:",
            transform.map_or(0, Hash::id),
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    pub fn len(&self) -> usize {
        self.key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// The key as the HMAC uses it: unchanged for hash 00, else HMAC(key, NQN ‖
    /// "NVMe-over-Fabrics") with the secret's own hash. The NQN is the host's for a host
    /// secret and the subsystem's for a controller secret.
    pub fn transformed(&self, nqn: &str) -> Vec<u8> {
        match self.transform {
            None => self.key.clone(),
            Some(h) => h.hmac(&self.key, &[nqn.as_bytes(), b"NVMe-over-Fabrics"]),
        }
    }
}

/// Whose response: the host's (R1) or the controller's (R2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Host,
    Controller,
}

/// Inputs both sides feed a response.
pub struct ResponseInput<'a> {
    pub hash: Hash,
    /// The transformed secret of the side that answers.
    pub key: &'a [u8],
    /// C1 for the host's response, C2 for the controller's.
    pub challenge: &'a [u8],
    /// H(g^xy mod p) under an ffdhe group, `None` under NULL.
    pub session_key: Option<&'a [u8]>,
    /// S1 for the host's response, S2 for the controller's.
    pub seqnum: u32,
    pub tid: u16,
    pub sc_c: u8,
    pub host_nqn: &'a str,
    pub subsystem_nqn: &'a str,
}

/// R1 or R2.
pub fn response(role: Role, i: &ResponseInput) -> Vec<u8> {
    let augmented;
    let challenge = match i.session_key {
        Some(sk) => {
            augmented = i.hash.hmac(sk, &[i.challenge]);
            augmented.as_slice()
        }
        None => i.challenge,
    };
    let (label, first, second): (&[u8], &str, &str) = match role {
        Role::Host => (b"HostHost", i.host_nqn, i.subsystem_nqn),
        Role::Controller => (b"Controller", i.subsystem_nqn, i.host_nqn),
    };
    i.hash.hmac(
        i.key,
        &[
            challenge,
            &i.seqnum.to_le_bytes(),
            &i.tid.to_le_bytes(),
            &[i.sc_c],
            label,
            first.as_bytes(),
            &[0],
            second.as_bytes(),
        ],
    )
}

/// Byte strings compared in time that does not depend on where they differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Random bytes from the operating system's generator.
pub fn random(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// A sequence number: random and never 0 (0 says "no bidirectional authentication").
pub fn seqnum() -> u32 {
    loop {
        let b = random(4);
        let s = u32::from_le_bytes(b.try_into().expect("4 bytes"));
        if s != 0 {
            return s;
        }
    }
}

/// One side's ephemeral Diffie-Hellman key in an ffdhe group.
pub struct DhKey {
    group: DhGroup,
    prime: BigUint,
    private: BigUint,
    public: Vec<u8>,
}

impl DhKey {
    /// A fresh key, or `None` for the NULL group.
    pub fn generate(group: DhGroup) -> Option<Self> {
        let prime = group.prime()?;
        let private = loop {
            let x = BigUint::from_bytes_be(&random(group.private_bits() / 8));
            if x > BigUint::from(1u8) {
                break x;
            }
        };
        let public = BigUint::from(2u8).modpow(&private, &prime);
        Some(Self {
            group,
            public: padded(&public, group.value_len()),
            prime,
            private,
        })
    }

    pub fn group(&self) -> DhGroup {
        self.group
    }

    /// g^x mod p, big-endian, the group's full length.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// H(peer^x mod p): the session key that augments both challenges. The peer's value must
    /// be the group's length and lie in 2..p-2 (1 and p-1 would make the secret guessable);
    /// otherwise the reason to fail with.
    pub fn session_key(&self, hash: Hash, peer: &[u8]) -> Result<Vec<u8>, u8> {
        if peer.len() != self.group.value_len() {
            return Err(reason::INCORRECT_PAYLOAD);
        }
        let y = BigUint::from_bytes_be(peer);
        let one = BigUint::from(1u8);
        let last = &self.prime - &one;
        if y <= one || y >= last {
            return Err(reason::DHGROUP_UNUSABLE);
        }
        let z = y.modpow(&self.private, &self.prime);
        Ok(hash.digest(&padded(&z, self.group.value_len())))
    }
}

impl Drop for DhKey {
    fn drop(&mut self) {
        self.private = BigUint::from(0u8);
    }
}

fn padded(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(b.len())];
    out.extend_from_slice(&b[b.len().saturating_sub(len)..]);
    out
}

// ------------------------------------------------------------------- messages

/// AUTH_Negotiate with its first protocol descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiate {
    pub tid: u16,
    pub sc_c: u8,
    pub napd: u8,
    pub authid: u8,
    /// Hash identifiers (HALEN of them, at most 30).
    pub hashes: Vec<u8>,
    /// DH group identifiers (DHLEN of them, at most 30).
    pub groups: Vec<u8>,
    /// HALEN and DHLEN as sent, which may exceed the 30 the descriptor holds.
    pub halen: u8,
    pub dhlen: u8,
}

/// DH-HMAC-CHAP_Challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub tid: u16,
    pub hl: u8,
    pub hash_id: u8,
    pub dhgid: u8,
    pub seqnum: u32,
    pub cval: Vec<u8>,
    pub dhv: Vec<u8>,
}

/// DH-HMAC-CHAP_Reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub tid: u16,
    pub hl: u8,
    pub cvalid: bool,
    pub seqnum: u32,
    pub rval: Vec<u8>,
    /// C2: HL bytes, meaningful when `cvalid`.
    pub cval: Vec<u8>,
    pub dhv: Vec<u8>,
}

/// DH-HMAC-CHAP_Success1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Success1 {
    pub tid: u16,
    pub hl: u8,
    pub rvalid: bool,
    pub rval: Vec<u8>,
}

/// AUTH_Failure1 (controller to host) or AUTH_Failure2 (host to controller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub second: bool,
    pub tid: u16,
    pub rescode: u8,
    pub explanation: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Negotiate(Negotiate),
    Challenge(Challenge),
    Reply(Reply),
    Success1(Success1),
    Success2 { tid: u16 },
    Failure(Failure),
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

impl Message {
    pub fn tid(&self) -> u16 {
        match self {
            Self::Negotiate(m) => m.tid,
            Self::Challenge(m) => m.tid,
            Self::Reply(m) => m.tid,
            Self::Success1(m) => m.tid,
            Self::Success2 { tid } => *tid,
            Self::Failure(m) => m.tid,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Negotiate(_) => "AUTH_Negotiate",
            Self::Challenge(_) => "DH-HMAC-CHAP_Challenge",
            Self::Reply(_) => "DH-HMAC-CHAP_Reply",
            Self::Success1(_) => "DH-HMAC-CHAP_Success1",
            Self::Success2 { .. } => "DH-HMAC-CHAP_Success2",
            Self::Failure(f) if f.second => "AUTH_Failure2",
            Self::Failure(_) => "AUTH_Failure1",
        }
    }

    /// Decode one message from the start of `b` (trailing bytes, such as an Authentication
    /// Receive's padding, are ignored). The error is the AUTH_Failure explanation to answer:
    /// INCORRECT_PAYLOAD for a message shorter than it says, INCORRECT_MESSAGE for an unknown
    /// type.
    pub fn decode(b: &[u8]) -> Result<Self, u8> {
        if b.len() < 8 {
            return Err(reason::INCORRECT_PAYLOAD);
        }
        let (auth_type, auth_id, tid) = (b[0], b[1], le16(b, 4));
        let short = reason::INCORRECT_PAYLOAD;
        match (auth_type, auth_id) {
            (TYPE_COMMON, msg::NEGOTIATE) => {
                if b.len() < NEGOTIATE_LEN {
                    return Err(short);
                }
                let (halen, dhlen) = (b[10], b[11]);
                let ids = &b[12..72];
                Ok(Self::Negotiate(Negotiate {
                    tid,
                    sc_c: b[6],
                    napd: b[7],
                    authid: b[8],
                    hashes: ids[..(halen as usize).min(MAX_IDS)].to_vec(),
                    groups: ids[MAX_IDS..MAX_IDS + (dhlen as usize).min(MAX_IDS)].to_vec(),
                    halen,
                    dhlen,
                }))
            }
            (TYPE_COMMON, msg::FAILURE1 | msg::FAILURE2) => Ok(Self::Failure(Failure {
                second: auth_id == msg::FAILURE2,
                tid,
                rescode: b[6],
                explanation: b[7],
            })),
            (TYPE_DHCHAP, msg::CHALLENGE) => {
                if b.len() < 16 {
                    return Err(short);
                }
                let hl = b[6] as usize;
                let dhvlen = le16(b, 10) as usize;
                let end = 16 + hl + dhvlen;
                if b.len() < end {
                    return Err(short);
                }
                Ok(Self::Challenge(Challenge {
                    tid,
                    hl: b[6],
                    hash_id: b[8],
                    dhgid: b[9],
                    seqnum: le32(b, 12),
                    cval: b[16..16 + hl].to_vec(),
                    dhv: b[16 + hl..end].to_vec(),
                }))
            }
            (TYPE_DHCHAP, msg::REPLY) => {
                if b.len() < 16 {
                    return Err(short);
                }
                let hl = b[6] as usize;
                let dhvlen = le16(b, 10) as usize;
                let end = 16 + 2 * hl + dhvlen;
                if b.len() < end {
                    return Err(short);
                }
                Ok(Self::Reply(Reply {
                    tid,
                    hl: b[6],
                    cvalid: b[8] & 1 != 0,
                    seqnum: le32(b, 12),
                    rval: b[16..16 + hl].to_vec(),
                    cval: b[16 + hl..16 + 2 * hl].to_vec(),
                    dhv: b[16 + 2 * hl..end].to_vec(),
                }))
            }
            (TYPE_DHCHAP, msg::SUCCESS1) => {
                if b.len() < 16 {
                    return Err(short);
                }
                let hl = b[6] as usize;
                let rvalid = b[8] & 1 != 0;
                if rvalid && b.len() < 16 + hl {
                    return Err(short);
                }
                Ok(Self::Success1(Success1 {
                    tid,
                    hl: b[6],
                    rvalid,
                    rval: if rvalid {
                        b[16..16 + hl].to_vec()
                    } else {
                        vec![]
                    },
                }))
            }
            (TYPE_DHCHAP, msg::SUCCESS2) => {
                if b.len() < 16 {
                    return Err(short);
                }
                Ok(Self::Success2 { tid })
            }
            _ => Err(reason::INCORRECT_MESSAGE),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let head = |auth_type: u8, auth_id: u8, tid: u16, len: usize| {
            let mut b = vec![0u8; len];
            b[0] = auth_type;
            b[1] = auth_id;
            b[4..6].copy_from_slice(&tid.to_le_bytes());
            b
        };
        match self {
            Self::Negotiate(m) => {
                let mut b = head(TYPE_COMMON, msg::NEGOTIATE, m.tid, NEGOTIATE_LEN);
                b[6] = m.sc_c;
                b[7] = m.napd;
                b[8] = m.authid;
                let (h, g) = (m.hashes.len().min(MAX_IDS), m.groups.len().min(MAX_IDS));
                b[10] = h as u8;
                b[11] = g as u8;
                b[12..12 + h].copy_from_slice(&m.hashes[..h]);
                b[12 + MAX_IDS..12 + MAX_IDS + g].copy_from_slice(&m.groups[..g]);
                b
            }
            Self::Challenge(m) => {
                let mut b = head(
                    TYPE_DHCHAP,
                    msg::CHALLENGE,
                    m.tid,
                    16 + m.cval.len() + m.dhv.len(),
                );
                b[6] = m.hl;
                b[8] = m.hash_id;
                b[9] = m.dhgid;
                b[10..12].copy_from_slice(&(m.dhv.len() as u16).to_le_bytes());
                b[12..16].copy_from_slice(&m.seqnum.to_le_bytes());
                b[16..16 + m.cval.len()].copy_from_slice(&m.cval);
                b[16 + m.cval.len()..].copy_from_slice(&m.dhv);
                b
            }
            Self::Reply(m) => {
                let hl = m.hl as usize;
                let mut b = head(TYPE_DHCHAP, msg::REPLY, m.tid, 16 + 2 * hl + m.dhv.len());
                b[6] = m.hl;
                b[8] = m.cvalid as u8;
                b[10..12].copy_from_slice(&(m.dhv.len() as u16).to_le_bytes());
                b[12..16].copy_from_slice(&m.seqnum.to_le_bytes());
                let r = m.rval.len().min(hl);
                b[16..16 + r].copy_from_slice(&m.rval[..r]);
                let c = m.cval.len().min(hl);
                b[16 + hl..16 + hl + c].copy_from_slice(&m.cval[..c]);
                b[16 + 2 * hl..].copy_from_slice(&m.dhv);
                b
            }
            Self::Success1(m) => {
                let mut b = head(
                    TYPE_DHCHAP,
                    msg::SUCCESS1,
                    m.tid,
                    16 + if m.rvalid { m.rval.len() } else { 0 },
                );
                b[6] = m.hl;
                b[8] = m.rvalid as u8;
                if m.rvalid {
                    b[16..].copy_from_slice(&m.rval);
                }
                b
            }
            Self::Success2 { tid } => head(TYPE_DHCHAP, msg::SUCCESS2, *tid, 16),
            Self::Failure(m) => {
                let id = if m.second {
                    msg::FAILURE2
                } else {
                    msg::FAILURE1
                };
                let mut b = head(TYPE_COMMON, id, m.tid, 8);
                b[6] = m.rescode;
                b[7] = m.explanation;
                b
            }
        }
    }
}

/// An Authentication Send (`send`) or Receive command's SQE fields: SECP, SPSP0, SPSP1 and
/// TL/AL.
pub fn command_fields(sqe: &super::nvme::Sqe) -> (u8, u8, u8, u32) {
    (sqe.0[43], sqe.0[41], sqe.0[42], sqe.u32(44))
}

/// Set an Authentication Send/Receive SQE's SECP, SPSP0/1 and TL/AL.
pub fn set_command_fields(sqe: &mut super::nvme::Sqe, len: u32) {
    sqe.0[41] = SPSP0;
    sqe.0[42] = SPSP1;
    sqe.0[43] = SECP;
    sqe.set_u32(44, len);
}
