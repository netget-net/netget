//! SNMPv3 with the User-based Security Model (RFC 3412 message processing, RFC 3414 USM,
//! RFC 3826 AES, RFC 7860 HMAC-SHA-2), shared by the agent and the manager.
//!
//! What it implements:
//!
//! - **Keys** (RFC 3414 A.2): a password is stretched to a key by hashing a megabyte of it
//!   repeated, then *localized* to one engine as `H(Ku ‖ engineID ‖ Ku)`. The megabyte hash is
//!   done once per user and protocol; localization once per engine.
//! - **Authentication**: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414), HMAC-SHA-224/256/384/512
//!   (RFC 7860, 16/24/32/48-byte MACs), computed over the whole message with the MAC field
//!   zeroed. An incoming MAC is checked over the bytes *as received*, with the field located by
//!   walking the BER — never over a re-encoding, which a sender's non-minimal lengths would make
//!   differ.
//! - **Privacy**: DES-CBC (RFC 3414 §8: key and pre-IV from the localized key, salt = boots ‖
//!   counter) and AES-128-CFB (RFC 3826: IV = boots ‖ time ‖ salt). AES-192/256 exist only as
//!   expired drafts with two incompatible key extensions, and are not offered.
//! - **The agent's side of the procedure** (RFC 3414 §3.2): discovery answered with a
//!   `usmStatsUnknownEngineIDs` report, then unknown users, unsupported levels, wrong digests,
//!   stale times and undecryptable PDUs each answered with their own report, the time report
//!   authenticated so the manager can trust the clock in it.
//! - **The manager's side**: discovery, a clock kept from the agent's reports, and replies
//!   checked for message id, engine, level and MAC before anything in them is believed.
//! - **Engine boots without persistence**: an agent given no `engine_boots` counts them as
//!   seconds of wall-clock time since [`ENGINE_BOOTS_EPOCH_UNIX_SECS`], so every restart reports
//!   a larger value than the run before it and a message captured in one run carries a boots the
//!   next run refuses.
//!
//! What it does not: VACM (every authenticated user sees what the handler answers — the user
//! and level are in the event for the handler to decide on) and SNMPv3 notifications.
//!
//! Every BER decode here runs on bytes screened by [`crate::server::snmp::check_ber_structure`]
//! first: the whole message, the msgSecurityParameters OCTET STRING's contents (which the outer
//! screen treats as one primitive and never descends into), and a decrypted scoped PDU. The
//! screen is applied inside [`decode`] itself, so no caller can reach `rasn` without it.

use anyhow::{bail, ensure, Context, Result};
use des::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rasn::ber;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_snmp::{v2, v3};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// The USM's security-model number (RFC 3411).
pub const USM_SECURITY_MODEL: i64 = 3;
/// `msgFlags` bits.
pub const FLAG_AUTH: u8 = 0x01;
pub const FLAG_PRIV: u8 = 0x02;
pub const FLAG_REPORTABLE: u8 = 0x04;
/// RFC 3414 §2.2.3: a message more than 150 seconds from the authoritative clock is stale.
pub const TIME_WINDOW_SECS: i64 = 150;
/// RFC 3414 §2.2.2: boots at this value means the engine must be reconfigured.
pub const MAX_ENGINE_BOOTS: i64 = 2_147_483_647;
/// RFC 3414 §2.2.1: snmpEngineBoots and snmpEngineTime are both `INTEGER (0..2147483647)`.
/// A received value outside `0..=MAX_ENGINE_TIME` is refused before any arithmetic is done on it.
pub const MAX_ENGINE_TIME: i64 = 2_147_483_647;
/// The size of message NetGet's agent will accept and say it can receive.
pub const MAX_MESSAGE_SIZE: i64 = 65_507;
/// RFC 3414 A.2: the password is repeated to this many bytes before hashing.
const PASSWORD_EXPANSION: usize = 1_048_576;
/// Bounds on what a configuration may hold.
pub const MAX_USERS: usize = 64;
pub const MAX_NAME_BYTES: usize = 32;
pub const MIN_PASSWORD_BYTES: usize = 8;
pub const MAX_PASSWORD_BYTES: usize = 256;
pub const MAX_ENGINE_ID_BYTES: usize = 32;
pub const MIN_ENGINE_ID_BYTES: usize = 5;
/// The instant default engine boots are counted from: 2024-01-01T00:00:00Z. Counting seconds
/// from here stays below [`MAX_ENGINE_BOOTS`] until 2092.
pub const ENGINE_BOOTS_EPOCH_UNIX_SECS: u64 = 1_704_067_200;

/// The largest boots value this process has handed out, so two agents started in the same
/// second of one process still get strictly increasing values.
static LAST_DEFAULT_BOOTS: AtomicI64 = AtomicI64::new(0);

/// snmpEngineBoots for an agent whose operator configured none.
///
/// NetGet persists nothing between runs, so boots cannot be a counter read from disk. It is the
/// number of wall-clock seconds since [`ENGINE_BOOTS_EPOCH_UNIX_SECS`] instead, which grows
/// across restarts as a stored counter would: with a fixed `engine_id` the localized keys are
/// the same in every run, and a captured authenticated message carries the boots of the run it
/// was sent in, which every later run refuses as `usmStatsNotInTimeWindows`. Within one process
/// each call returns more than the last. The guarantee rests on the wall clock: a clock set back
/// across a restart can repeat an earlier run's value, and an operator who cannot trust it sets
/// `engine_boots` explicitly and raises it on every restart.
pub fn default_engine_boots() -> i64 {
    let wall = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let since_epoch = wall.saturating_sub(ENGINE_BOOTS_EPOCH_UNIX_SECS);
    let since_epoch = i64::try_from(since_epoch).unwrap_or(MAX_ENGINE_BOOTS - 1);
    let mut previous = LAST_DEFAULT_BOOTS.load(Ordering::Relaxed);
    loop {
        let next = since_epoch
            .max(previous.saturating_add(1))
            .clamp(1, MAX_ENGINE_BOOTS - 1);
        match LAST_DEFAULT_BOOTS.compare_exchange_weak(
            previous,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(current) => previous = current,
        }
    }
}

/// Whether a received snmpEngineBoots or snmpEngineTime is inside RFC 3414's `0..2147483647`.
pub fn in_engine_range(value: i64) -> bool {
    (0..=MAX_ENGINE_TIME).contains(&value)
}

/// The agent's USM from its startup parameters, or `None` when no v3 user is configured —
/// then a v3 message is dropped and only v1/v2c are served.
pub fn agent_from_params(
    params: Option<&crate::protocol::StartupParams>,
) -> Result<Option<std::sync::Arc<Agent>>> {
    let Some(params) = params else {
        return Ok(None);
    };
    let Some(users) = params.get_optional_array("v3_users")? else {
        return Ok(None);
    };
    let users = users
        .iter()
        .map(User::from_json)
        .collect::<Result<Vec<_>>>()?;
    let engine_id = match params.get_optional_string("engine_id")? {
        Some(hex_id) => hex::decode(hex_id.trim_start_matches("0x"))
            .context("engine_id is hexadecimal, as Net-SNMP writes it (e.g. 80001f8880...)")?,
        None => Agent::random_engine_id(),
    };
    let boots = match params.get_optional_i64("engine_boots")? {
        Some(boots) => boots,
        None => default_engine_boots(),
    };
    Ok(Some(std::sync::Arc::new(Agent::new(
        engine_id, boots, users,
    )?)))
}

/// Whether a datagram is an SNMPv3 message: a SEQUENCE whose first element is INTEGER 3.
pub fn is_v3(data: &[u8]) -> bool {
    let Ok((0x30, start, _)) = tlv(data, 0) else {
        return false;
    };
    matches!(tlv(data, start), Ok((0x02, s, 1)) if data[s] == 3)
}

/// The usmStats counters (RFC 3414 §5), whose varbind is the body of each report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportKind {
    UnsupportedSecLevels,
    NotInTimeWindows,
    UnknownUserNames,
    UnknownEngineIds,
    WrongDigests,
    DecryptionErrors,
}

impl ReportKind {
    const ALL: [ReportKind; 6] = [
        ReportKind::UnsupportedSecLevels,
        ReportKind::NotInTimeWindows,
        ReportKind::UnknownUserNames,
        ReportKind::UnknownEngineIds,
        ReportKind::WrongDigests,
        ReportKind::DecryptionErrors,
    ];

    /// `1.3.6.1.6.3.15.1.1.<n>.0`.
    pub fn oid(self) -> Vec<u32> {
        let n = match self {
            ReportKind::UnsupportedSecLevels => 1,
            ReportKind::NotInTimeWindows => 2,
            ReportKind::UnknownUserNames => 3,
            ReportKind::UnknownEngineIds => 4,
            ReportKind::WrongDigests => 5,
            ReportKind::DecryptionErrors => 6,
        };
        vec![1, 3, 6, 1, 6, 3, 15, 1, 1, n, 0]
    }

    pub fn from_oid(oid: &[u32]) -> Option<ReportKind> {
        ReportKind::ALL.into_iter().find(|k| k.oid() == oid)
    }

    pub fn name(self) -> &'static str {
        match self {
            ReportKind::UnsupportedSecLevels => "usmStatsUnsupportedSecLevels",
            ReportKind::NotInTimeWindows => "usmStatsNotInTimeWindows",
            ReportKind::UnknownUserNames => "usmStatsUnknownUserNames",
            ReportKind::UnknownEngineIds => "usmStatsUnknownEngineIDs",
            ReportKind::WrongDigests => "usmStatsWrongDigests",
            ReportKind::DecryptionErrors => "usmStatsDecryptionErrors",
        }
    }

    fn index(self) -> usize {
        ReportKind::ALL.iter().position(|k| *k == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProtocol {
    None,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthProtocol {
    pub fn parse(s: &str) -> Result<AuthProtocol> {
        Ok(
            match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
                "" | "none" => AuthProtocol::None,
                "md5" => AuthProtocol::Md5,
                "sha" | "sha1" => AuthProtocol::Sha1,
                "sha224" => AuthProtocol::Sha224,
                "sha256" => AuthProtocol::Sha256,
                "sha384" => AuthProtocol::Sha384,
                "sha512" => AuthProtocol::Sha512,
                _ => bail!(
                "auth_protocol {s:?} is not one of none, md5, sha, sha224, sha256, sha384, sha512"
            ),
            },
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            AuthProtocol::None => "none",
            AuthProtocol::Md5 => "md5",
            AuthProtocol::Sha1 => "sha",
            AuthProtocol::Sha224 => "sha224",
            AuthProtocol::Sha256 => "sha256",
            AuthProtocol::Sha384 => "sha384",
            AuthProtocol::Sha512 => "sha512",
        }
    }

    /// The truncated MAC carried in msgAuthenticationParameters.
    pub fn mac_len(self) -> usize {
        match self {
            AuthProtocol::None => 0,
            AuthProtocol::Md5 | AuthProtocol::Sha1 => 12,
            AuthProtocol::Sha224 => 16,
            AuthProtocol::Sha256 => 24,
            AuthProtocol::Sha384 => 32,
            AuthProtocol::Sha512 => 48,
        }
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            AuthProtocol::None => Vec::new(),
            AuthProtocol::Md5 => run::<md5::Md5>(parts),
            AuthProtocol::Sha1 => run::<sha1::Sha1>(parts),
            AuthProtocol::Sha224 => run::<sha2::Sha224>(parts),
            AuthProtocol::Sha256 => run::<sha2::Sha256>(parts),
            AuthProtocol::Sha384 => run::<sha2::Sha384>(parts),
            AuthProtocol::Sha512 => run::<sha2::Sha512>(parts),
        }
    }

    fn mac(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
            let mut m = <M as hmac::digest::KeyInit>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        let full = match self {
            AuthProtocol::None => return Vec::new(),
            AuthProtocol::Md5 => run::<Hmac<md5::Md5>>(key, message),
            AuthProtocol::Sha1 => run::<Hmac<sha1::Sha1>>(key, message),
            AuthProtocol::Sha224 => run::<Hmac<sha2::Sha224>>(key, message),
            AuthProtocol::Sha256 => run::<Hmac<sha2::Sha256>>(key, message),
            AuthProtocol::Sha384 => run::<Hmac<sha2::Sha384>>(key, message),
            AuthProtocol::Sha512 => run::<Hmac<sha2::Sha512>>(key, message),
        };
        full[..self.mac_len()].to_vec()
    }

    /// RFC 3414 A.2.1: hash the password repeated to a megabyte.
    pub fn password_to_key(self, password: &[u8]) -> Vec<u8> {
        if self == AuthProtocol::None || password.is_empty() {
            return Vec::new();
        }
        let mut block = Vec::with_capacity(PASSWORD_EXPANSION);
        while block.len() < PASSWORD_EXPANSION {
            let take = (PASSWORD_EXPANSION - block.len()).min(password.len());
            block.extend_from_slice(&password[..take]);
        }
        self.hash(&[&block])
    }

    /// RFC 3414 A.2.2: localize a key to one engine.
    pub fn localize(self, key: &[u8], engine_id: &[u8]) -> Vec<u8> {
        self.hash(&[key, engine_id, key])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivProtocol {
    None,
    Des,
    Aes128,
}

impl PrivProtocol {
    pub fn parse(s: &str) -> Result<PrivProtocol> {
        Ok(
            match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
                "" | "none" => PrivProtocol::None,
                "des" => PrivProtocol::Des,
                "aes" | "aes128" => PrivProtocol::Aes128,
                _ => bail!("priv_protocol {s:?} is not one of none, des, aes"),
            },
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            PrivProtocol::None => "none",
            PrivProtocol::Des => "des",
            PrivProtocol::Aes128 => "aes",
        }
    }
}

/// msgFlags' security level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SecurityLevel {
    #[serde(rename = "noAuthNoPriv")]
    NoAuthNoPriv,
    #[serde(rename = "authNoPriv")]
    AuthNoPriv,
    #[serde(rename = "authPriv")]
    AuthPriv,
}

impl SecurityLevel {
    pub fn from_flags(flags: u8) -> Result<SecurityLevel> {
        Ok(match (flags & FLAG_AUTH != 0, flags & FLAG_PRIV != 0) {
            (false, false) => SecurityLevel::NoAuthNoPriv,
            (true, false) => SecurityLevel::AuthNoPriv,
            (true, true) => SecurityLevel::AuthPriv,
            (false, true) => bail!("msgFlags asks for privacy without authentication"),
        })
    }

    pub fn flags(self) -> u8 {
        match self {
            SecurityLevel::NoAuthNoPriv => 0,
            SecurityLevel::AuthNoPriv => FLAG_AUTH,
            SecurityLevel::AuthPriv => FLAG_AUTH | FLAG_PRIV,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SecurityLevel::NoAuthNoPriv => "noAuthNoPriv",
            SecurityLevel::AuthNoPriv => "authNoPriv",
            SecurityLevel::AuthPriv => "authPriv",
        }
    }
}

/// A user as configured: a name, and a password per protocol.
#[derive(Clone)]
pub struct User {
    pub name: String,
    pub auth: AuthProtocol,
    pub priv_proto: PrivProtocol,
    /// Ku for authentication and for privacy (both hashed with the auth protocol).
    auth_ku: Vec<u8>,
    priv_ku: Vec<u8>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("auth", &self.auth)
            .field("priv", &self.priv_proto)
            .finish_non_exhaustive()
    }
}

impl User {
    /// `{name, auth_protocol, auth_password, priv_protocol, priv_password}`.
    pub fn from_json(v: &serde_json::Value) -> Result<User> {
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .context("a v3 user needs 'name'")?;
        ensure!(
            !name.is_empty() && name.len() <= MAX_NAME_BYTES,
            "a v3 user name is 1 to {MAX_NAME_BYTES} bytes"
        );
        let text = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let auth = AuthProtocol::parse(text("auth_protocol"))?;
        let priv_proto = PrivProtocol::parse(text("priv_protocol"))?;
        let password = |k: &str, needed: bool| -> Result<Vec<u8>> {
            let p = text(k);
            if !needed {
                ensure!(
                    p.is_empty(),
                    "user {name}: {k} is set for a protocol of none"
                );
                return Ok(Vec::new());
            }
            ensure!(
                (MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&p.len()),
                "user {name}: {k} must be {MIN_PASSWORD_BYTES} to {MAX_PASSWORD_BYTES} bytes \
                 (RFC 3414 §11.2 sets 8 as the minimum)"
            );
            Ok(p.as_bytes().to_vec())
        };
        ensure!(
            priv_proto == PrivProtocol::None || auth != AuthProtocol::None,
            "user {name}: privacy needs an auth_protocol (there is no noAuthPriv)"
        );
        let auth_password = password("auth_password", auth != AuthProtocol::None)?;
        let priv_password = password("priv_password", priv_proto != PrivProtocol::None)?;
        Ok(User {
            name: name.to_string(),
            auth,
            priv_proto,
            auth_ku: auth.password_to_key(&auth_password),
            priv_ku: auth.password_to_key(&priv_password),
        })
    }

    pub fn level(&self) -> SecurityLevel {
        match (self.auth, self.priv_proto) {
            (AuthProtocol::None, _) => SecurityLevel::NoAuthNoPriv,
            (_, PrivProtocol::None) => SecurityLevel::AuthNoPriv,
            _ => SecurityLevel::AuthPriv,
        }
    }

    pub fn localize(&self, engine_id: &[u8]) -> Keys {
        Keys {
            auth: self.auth,
            priv_proto: self.priv_proto,
            auth_key: self.auth.localize(&self.auth_ku, engine_id),
            priv_key: if self.priv_proto == PrivProtocol::None {
                Vec::new()
            } else {
                self.auth.localize(&self.priv_ku, engine_id)
            },
        }
    }
}

/// A user's keys localized to one engine.
#[derive(Clone)]
pub struct Keys {
    pub auth: AuthProtocol,
    pub priv_proto: PrivProtocol,
    pub auth_key: Vec<u8>,
    pub priv_key: Vec<u8>,
}

impl Keys {
    /// Encrypt a scoped PDU. Returns the ciphertext and msgPrivacyParameters.
    pub fn encrypt(
        &self,
        plain: &[u8],
        boots: i64,
        time: i64,
        salt: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.priv_proto {
            PrivProtocol::None => bail!("no privacy protocol"),
            PrivProtocol::Des => {
                ensure!(
                    self.priv_key.len() >= 16,
                    "DES needs a 16-byte localized key"
                );
                let salt = [(boots as u32).to_be_bytes(), (salt as u32).to_be_bytes()].concat();
                let iv: Vec<u8> = self.priv_key[8..16]
                    .iter()
                    .zip(&salt)
                    .map(|(a, b)| a ^ b)
                    .collect();
                let cipher = des::Des::new_from_slice(&self.priv_key[..8]).context("DES key")?;
                let mut data = plain.to_vec();
                data.resize(plain.len().div_ceil(8) * 8, 0);
                let mut prev: [u8; 8] = iv.try_into().expect("8 bytes");
                for block in data.chunks_mut(8) {
                    for (b, p) in block.iter_mut().zip(prev) {
                        *b ^= p;
                    }
                    let mut ga = Block::<des::Des>::default();
                    ga.copy_from_slice(block);
                    cipher.encrypt_block(&mut ga);
                    block.copy_from_slice(&ga);
                    prev.copy_from_slice(block);
                }
                Ok((data, salt))
            }
            PrivProtocol::Aes128 => {
                ensure!(
                    self.priv_key.len() >= 16,
                    "AES-128 needs a 16-byte localized key"
                );
                let salt = salt.to_be_bytes().to_vec();
                let iv = aes_iv(boots, time, &salt);
                let mut data = plain.to_vec();
                aes_cfb(&self.priv_key[..16], iv, &mut data, true)?;
                Ok((data, salt))
            }
        }
    }

    /// Decrypt with the message's boots, time and msgPrivacyParameters.
    pub fn decrypt(
        &self,
        cipher_text: &[u8],
        boots: i64,
        time: i64,
        params: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(params.len() == 8, "msgPrivacyParameters must be 8 bytes");
        match self.priv_proto {
            PrivProtocol::None => bail!("no privacy protocol"),
            PrivProtocol::Des => {
                ensure!(
                    !cipher_text.is_empty() && cipher_text.len() % 8 == 0,
                    "a DES ciphertext is a whole number of 8-byte blocks"
                );
                let iv: Vec<u8> = self.priv_key[8..16]
                    .iter()
                    .zip(params)
                    .map(|(a, b)| a ^ b)
                    .collect();
                let cipher = des::Des::new_from_slice(&self.priv_key[..8]).context("DES key")?;
                let mut prev: [u8; 8] = iv.try_into().expect("8 bytes");
                let mut out = Vec::with_capacity(cipher_text.len());
                for block in cipher_text.chunks(8) {
                    let mut ga = Block::<des::Des>::default();
                    ga.copy_from_slice(block);
                    cipher.decrypt_block(&mut ga);
                    out.extend(ga.iter().zip(prev).map(|(a, b)| a ^ b));
                    prev.copy_from_slice(block);
                }
                Ok(out)
            }
            PrivProtocol::Aes128 => {
                let iv = aes_iv(boots, time, params);
                let mut data = cipher_text.to_vec();
                aes_cfb(&self.priv_key[..16], iv, &mut data, false)?;
                Ok(data)
            }
        }
    }
}

fn aes_iv(boots: i64, time: i64, salt: &[u8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&(boots as u32).to_be_bytes());
    iv[4..8].copy_from_slice(&(time as u32).to_be_bytes());
    iv[8..].copy_from_slice(salt);
    iv
}

/// CFB-128: each keystream block is the encryption of the previous ciphertext block.
fn aes_cfb(key: &[u8], iv: [u8; 16], data: &mut [u8], encrypt: bool) -> Result<()> {
    let cipher = aes::Aes128::new_from_slice(key).context("AES key")?;
    let mut feedback = iv;
    for chunk in data.chunks_mut(16) {
        let mut ga = Block::<aes::Aes128>::default();
        ga.copy_from_slice(&feedback);
        cipher.encrypt_block(&mut ga);
        let mut next = [0u8; 16];
        for (i, b) in chunk.iter_mut().enumerate() {
            let received = *b;
            *b ^= ga[i];
            // The feedback is always the ciphertext: what was written when encrypting, what
            // was read when decrypting.
            next[i] = if encrypt { *b } else { received };
        }
        feedback = next;
    }
    Ok(())
}

/// The content span (offset, length) of the TLV starting at `at`, and where the TLV ends.
fn tlv(data: &[u8], at: usize) -> Result<(u8, usize, usize)> {
    let tag = *data.get(at).context("truncated BER")?;
    let first = *data.get(at + 1).context("truncated BER length")?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        ensure!((1..=4).contains(&n), "unsupported BER length form");
        let bytes = data
            .get(at + 2..at + 2 + n)
            .context("truncated BER length")?;
        (
            bytes.iter().fold(0usize, |a, b| (a << 8) | *b as usize),
            2 + n,
        )
    };
    let start = at + header;
    ensure!(
        start + len <= data.len(),
        "BER length runs past the message"
    );
    Ok((tag, start, len))
}

/// Where msgAuthenticationParameters' content sits in a received message: outer SEQUENCE →
/// third element (msgSecurityParameters OCTET STRING) → its SEQUENCE → fifth element.
pub fn auth_params_span(data: &[u8]) -> Result<(usize, usize)> {
    let (tag, outer, _) = tlv(data, 0)?;
    ensure!(tag == 0x30, "not a SEQUENCE");
    let mut at = outer;
    for _ in 0..2 {
        let (_, s, l) = tlv(data, at)?;
        at = s + l;
    }
    let (tag, sec, _) = tlv(data, at)?;
    ensure!(tag == 0x04, "msgSecurityParameters is not an OCTET STRING");
    let (tag, seq, _) = tlv(data, sec)?;
    ensure!(tag == 0x30, "UsmSecurityParameters is not a SEQUENCE");
    let mut at = seq;
    for _ in 0..4 {
        let (_, s, l) = tlv(data, at)?;
        at = s + l;
    }
    let (tag, s, l) = tlv(data, at)?;
    ensure!(
        tag == 0x04,
        "msgAuthenticationParameters is not an OCTET STRING"
    );
    Ok((s, l))
}

/// The length of the first TLV in `data` — a decrypted scoped PDU ends there, before padding.
pub fn first_tlv_len(data: &[u8]) -> Result<usize> {
    let (_, s, l) = tlv(data, 0)?;
    Ok(s + l)
}

fn int(v: &Integer) -> Result<i64> {
    i64::try_from(v.clone()).map_err(|_| anyhow::anyhow!("integer out of range"))
}

/// A decoded v3 message, before anything in it is believed.
pub struct Received {
    pub msg_id: i64,
    pub max_size: i64,
    pub flags: u8,
    pub usm: v3::USMSecurityParameters,
    pub data: v3::ScopedPduData,
}

/// Decode a v3 message's envelope.
///
/// The message is depth-screened before `rasn` sees it, and so are msgSecurityParameters'
/// contents before they are decoded in turn. The outer screen cannot cover the second: it reads
/// msgSecurityParameters as one primitive OCTET STRING and skips its contents, while the
/// UsmSecurityParameters inside are BER of their own whose OCTET STRINGs may be constructed —
/// `24 80` repeated buys one level of `rasn`'s unbounded recursion per two bytes, enough in one
/// datagram to overflow the stack and abort the process before any key is checked.
pub fn decode(data: &[u8]) -> Result<Received> {
    crate::server::snmp::check_ber_structure(data, crate::server::snmp::MAX_BER_DEPTH)
        .map_err(|e| anyhow::anyhow!("not an SNMPv3 message: {e}"))?;
    let msg: v3::Message =
        ber::decode(data).map_err(|e| anyhow::anyhow!("not an SNMPv3 message: {e}"))?;
    ensure!(int(&msg.version)? == 3, "not version 3");
    ensure!(
        int(&msg.global_data.security_model)? == USM_SECURITY_MODEL,
        "security model {} is not the USM",
        msg.global_data.security_model
    );
    ensure!(
        msg.global_data.flags.len() == 1,
        "msgFlags must be one byte"
    );
    crate::server::snmp::check_ber_structure(
        &msg.security_parameters,
        crate::server::snmp::MAX_BER_DEPTH,
    )
    .map_err(|e| anyhow::anyhow!("bad UsmSecurityParameters: {e}"))?;
    let usm: v3::USMSecurityParameters = ber::decode(&msg.security_parameters)
        .map_err(|e| anyhow::anyhow!("bad UsmSecurityParameters: {e}"))?;
    Ok(Received {
        msg_id: int(&msg.global_data.message_id)?,
        max_size: int(&msg.global_data.max_size)?,
        flags: msg.global_data.flags[0],
        usm,
        data: msg.scoped_data,
    })
}

/// Everything needed to put one outgoing message on the wire.
pub struct Outgoing<'a> {
    pub msg_id: i64,
    pub max_size: i64,
    pub flags: u8,
    pub engine_id: &'a [u8],
    pub boots: i64,
    pub time: i64,
    pub user: &'a [u8],
    /// Keys at the message's level; `None` for noAuthNoPriv.
    pub keys: Option<&'a Keys>,
    pub salt: u64,
    pub context_engine_id: &'a [u8],
    pub context_name: &'a [u8],
    pub pdu: v2::Pdus,
}

/// Build, encrypt and authenticate one message.
pub fn encode(out: Outgoing<'_>) -> Result<Vec<u8>> {
    let level = SecurityLevel::from_flags(out.flags)?;
    let scoped = v3::ScopedPdu {
        engine_id: out.context_engine_id.to_vec().into(),
        name: out.context_name.to_vec().into(),
        data: out.pdu,
    };
    let (scoped_data, priv_params) = if level == SecurityLevel::AuthPriv {
        let keys = out.keys.context("privacy needs keys")?;
        let plain = ber::encode(&scoped).map_err(|e| anyhow::anyhow!("scoped PDU: {e}"))?;
        let (cipher_text, params) = keys.encrypt(&plain, out.boots, out.time, out.salt)?;
        (v3::ScopedPduData::EncryptedPdu(cipher_text.into()), params)
    } else {
        (v3::ScopedPduData::CleartextPdu(scoped), Vec::new())
    };
    let mac_len = match level {
        SecurityLevel::NoAuthNoPriv => 0,
        _ => out
            .keys
            .context("authentication needs keys")?
            .auth
            .mac_len(),
    };
    let build = |mac: Vec<u8>| -> Result<Vec<u8>> {
        let usm = v3::USMSecurityParameters {
            authoritative_engine_id: out.engine_id.to_vec().into(),
            authoritative_engine_boots: out.boots.into(),
            authoritative_engine_time: out.time.into(),
            user_name: out.user.to_vec().into(),
            authentication_parameters: mac.into(),
            privacy_parameters: priv_params.clone().into(),
        };
        let message = v3::Message {
            version: 3.into(),
            global_data: v3::HeaderData {
                message_id: out.msg_id.into(),
                max_size: out.max_size.into(),
                flags: OctetString::from(vec![out.flags]),
                security_model: USM_SECURITY_MODEL.into(),
            },
            security_parameters: ber::encode(&usm)
                .map_err(|e| anyhow::anyhow!("security parameters: {e}"))?
                .into(),
            scoped_data: scoped_data.clone(),
        };
        ber::encode(&message).map_err(|e| anyhow::anyhow!("v3 message: {e}"))
    };
    let zeroed = build(vec![0; mac_len])?;
    if mac_len == 0 {
        return Ok(zeroed);
    }
    let keys = out.keys.context("authentication needs keys")?;
    let mac = keys.auth.mac(&keys.auth_key, &zeroed);
    let (at, len) = auth_params_span(&zeroed)?;
    ensure!(
        len == mac_len,
        "MAC field is {len} bytes, expected {mac_len}"
    );
    let mut message = zeroed;
    message[at..at + len].copy_from_slice(&mac);
    Ok(message)
}

/// Check a received message's MAC over the bytes as received.
pub fn verify(data: &[u8], keys: &Keys) -> bool {
    let Ok((at, len)) = auth_params_span(data) else {
        return false;
    };
    if len != keys.auth.mac_len() || len == 0 {
        return false;
    }
    let mut zeroed = data.to_vec();
    let offered = data[at..at + len].to_vec();
    zeroed[at..at + len].fill(0);
    let expected = keys.auth.mac(&keys.auth_key, &zeroed);
    // Constant-time comparison: the position of the first wrong byte is not to be learnt.
    expected
        .iter()
        .zip(&offered)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Recover the scoped PDU, decrypting it under `keys` when the message is encrypted.
pub fn scoped_pdu(rx: &Received, keys: Option<&Keys>) -> Result<v3::ScopedPdu> {
    match &rx.data {
        v3::ScopedPduData::CleartextPdu(p) => {
            ensure!(
                rx.flags & FLAG_PRIV == 0,
                "msgFlags says encrypted, the PDU is not"
            );
            Ok(p.clone())
        }
        v3::ScopedPduData::EncryptedPdu(c) => {
            ensure!(
                rx.flags & FLAG_PRIV != 0,
                "an encrypted PDU without the privacy flag"
            );
            let keys = keys.context("an encrypted PDU for a user without privacy")?;
            let plain = keys.decrypt(
                c,
                int(&rx.usm.authoritative_engine_boots)?,
                int(&rx.usm.authoritative_engine_time)?,
                &rx.usm.privacy_parameters,
            )?;
            crate::server::snmp::check_ber_structure(
                &plain[..first_tlv_len(&plain)?],
                crate::server::snmp::MAX_BER_DEPTH,
            )
            .map_err(|e| anyhow::anyhow!("decrypted PDU: {e}"))?;
            ber::decode(&plain[..first_tlv_len(&plain)?])
                .map_err(|e| anyhow::anyhow!("the decrypted scoped PDU does not decode: {e}"))
        }
    }
}

fn report_pdu(kind: ReportKind, count: u32, request_id: i32) -> v2::Pdus {
    v2::Pdus::Report(v2::Report(v2::Pdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![v2::VarBind {
            name: ObjectIdentifier::new_unchecked(kind.oid().into()),
            value: v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                rasn_smi::v2::ApplicationSyntax::Counter(rasn_smi::v1::Counter(count)),
            )),
        }],
    }))
}

/// The authoritative side: one engine, its users, and its counters.
pub struct Agent {
    pub engine_id: Vec<u8>,
    pub boots: i64,
    started: crate::utils::clock::Instant,
    users: HashMap<Vec<u8>, (User, Keys)>,
    counters: [AtomicU32; 6],
    salt: AtomicU64,
}

/// What the agent made of a request.
pub enum Inbound {
    /// A request at the level its user is configured for, ready for the handler.
    Request(Box<Request>),
    /// A report to send back (already encoded), and why.
    Report(Vec<u8>, ReportKind),
    /// Nothing to answer: not reportable, or not answerable at all.
    Drop(String),
}

/// An authenticated (or deliberately unauthenticated) request and how to answer it.
pub struct Request {
    pub msg_id: i64,
    pub max_size: i64,
    pub user: String,
    pub level: SecurityLevel,
    pub context_engine_id: Vec<u8>,
    pub context_name: Vec<u8>,
    pub pdu: v2::Pdus,
}

impl Agent {
    pub fn new(engine_id: Vec<u8>, boots: i64, users: Vec<User>) -> Result<Agent> {
        ensure!(
            (MIN_ENGINE_ID_BYTES..=MAX_ENGINE_ID_BYTES).contains(&engine_id.len()),
            "engine_id must be {MIN_ENGINE_ID_BYTES} to {MAX_ENGINE_ID_BYTES} bytes"
        );
        ensure!(
            (1..MAX_ENGINE_BOOTS).contains(&boots),
            "engine_boots must be 1 to {}",
            MAX_ENGINE_BOOTS - 1
        );
        ensure!(users.len() <= MAX_USERS, "at most {MAX_USERS} v3 users");
        let mut table = HashMap::new();
        for u in users {
            let keys = u.localize(&engine_id);
            ensure!(
                table
                    .insert(u.name.as_bytes().to_vec(), (u.clone(), keys))
                    .is_none(),
                "v3 user {} is configured twice",
                u.name
            );
        }
        Ok(Agent {
            engine_id,
            boots,
            started: crate::utils::clock::Instant::now(),
            users: table,
            counters: Default::default(),
            salt: AtomicU64::new(rand::random()),
        })
    }

    /// A fresh engine ID in RFC 3411 form: enterprise 0 with the high bit, format 5
    /// (administratively assigned octets), eight random octets.
    pub fn random_engine_id() -> Vec<u8> {
        let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x05];
        id.extend_from_slice(&rand::random::<[u8; 8]>());
        id
    }

    pub fn time(&self) -> i64 {
        self.started.elapsed().as_secs() as i64
    }

    pub fn counter(&self, kind: ReportKind) -> u32 {
        self.counters[kind.index()].load(Ordering::Relaxed)
    }

    fn report(
        &self,
        rx: &Received,
        kind: ReportKind,
        keys: Option<&Keys>,
        request_id: i32,
    ) -> Result<Vec<u8>> {
        let count = self.counters[kind.index()]
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        // The time report is authenticated so the manager can believe the clock it carries;
        // every other report goes out at noAuthNoPriv, as the user's keys are not usable.
        let flags = if keys.is_some() { FLAG_AUTH } else { 0 };
        encode(Outgoing {
            msg_id: rx.msg_id,
            max_size: MAX_MESSAGE_SIZE,
            flags,
            engine_id: &self.engine_id,
            boots: self.boots,
            time: self.time(),
            user: &rx.usm.user_name,
            keys,
            salt: 0,
            context_engine_id: &self.engine_id,
            context_name: b"",
            pdu: report_pdu(kind, count, request_id),
        })
    }

    /// RFC 3414 §3.2, in order.
    pub fn receive(&self, data: &[u8]) -> Inbound {
        let rx = match decode(data) {
            Ok(rx) => rx,
            Err(e) => return Inbound::Drop(e.to_string()),
        };
        let reportable = rx.flags & FLAG_REPORTABLE != 0;
        let level = match SecurityLevel::from_flags(rx.flags) {
            Ok(l) => l,
            Err(e) => return Inbound::Drop(e.to_string()),
        };
        let request_id = match &rx.data {
            v3::ScopedPduData::CleartextPdu(p) => pdu_request_id(&p.data),
            _ => 0,
        };
        let reply = |kind: ReportKind, keys: Option<&Keys>| -> Inbound {
            if !reportable {
                return Inbound::Drop(format!("{} (not reportable)", kind.name()));
            }
            match self.report(&rx, kind, keys, request_id) {
                Ok(bytes) => Inbound::Report(bytes, kind),
                Err(e) => Inbound::Drop(format!("report could not be built: {e}")),
            }
        };
        if rx.usm.authoritative_engine_id.as_ref() != self.engine_id.as_slice() {
            return reply(ReportKind::UnknownEngineIds, None);
        }
        let Some((user, keys)) = self.users.get(rx.usm.user_name.as_ref()) else {
            return reply(ReportKind::UnknownUserNames, None);
        };
        // A user is served only at the level it is configured for: one with keys is never
        // answered without them, which is what makes configuring them mean anything.
        if level != user.level() {
            return reply(ReportKind::UnsupportedSecLevels, None);
        }
        if level != SecurityLevel::NoAuthNoPriv {
            if !verify(data, keys) {
                return reply(ReportKind::WrongDigests, None);
            }
            let (Ok(boots), Ok(time)) = (
                int(&rx.usm.authoritative_engine_boots),
                int(&rx.usm.authoritative_engine_time),
            ) else {
                return reply(ReportKind::NotInTimeWindows, Some(keys));
            };
            // Both are the peer's numbers: range-checked before any arithmetic, and the
            // distance taken without a subtraction that could overflow.
            if !in_engine_range(boots)
                || !in_engine_range(time)
                || boots == MAX_ENGINE_BOOTS
                || boots != self.boots
                || time.abs_diff(self.time()) > TIME_WINDOW_SECS.unsigned_abs()
            {
                return reply(ReportKind::NotInTimeWindows, Some(keys));
            }
        }
        let scoped = match scoped_pdu(&rx, (level == SecurityLevel::AuthPriv).then_some(keys)) {
            Ok(s) => s,
            Err(_) if level == SecurityLevel::AuthPriv => {
                return reply(ReportKind::DecryptionErrors, None)
            }
            Err(e) => return Inbound::Drop(e.to_string()),
        };
        Inbound::Request(Box::new(Request {
            msg_id: rx.msg_id,
            max_size: rx.max_size,
            user: user.name.clone(),
            level,
            context_engine_id: scoped.engine_id.to_vec(),
            context_name: scoped.name.to_vec(),
            pdu: scoped.data,
        }))
    }

    /// Encode the agent's answer to `request`.
    pub fn respond(&self, request: &Request, pdu: v2::Pdus) -> Result<Vec<u8>> {
        let keys = match request.level {
            SecurityLevel::NoAuthNoPriv => None,
            _ => Some(
                &self
                    .users
                    .get(request.user.as_bytes())
                    .context("the user is no longer configured")?
                    .1,
            ),
        };
        encode(Outgoing {
            msg_id: request.msg_id,
            max_size: MAX_MESSAGE_SIZE,
            flags: request.level.flags(),
            engine_id: &self.engine_id,
            boots: self.boots,
            time: self.time(),
            user: request.user.as_bytes(),
            keys,
            salt: self.salt.fetch_add(1, Ordering::Relaxed),
            context_engine_id: &self.engine_id,
            context_name: &request.context_name,
            pdu,
        })
    }
}

/// A received message's snmpEngineBoots and snmpEngineTime, refused outside RFC 3414's range.
fn engine_clock(rx: &Received) -> Result<(i64, i64)> {
    let boots = int(&rx.usm.authoritative_engine_boots)?;
    let time = int(&rx.usm.authoritative_engine_time)?;
    ensure!(
        in_engine_range(boots),
        "snmpEngineBoots {boots} is outside 0..={MAX_ENGINE_BOOTS}"
    );
    ensure!(
        in_engine_range(time),
        "snmpEngineTime {time} is outside 0..={MAX_ENGINE_TIME}"
    );
    Ok((boots, time))
}

pub fn pdu_request_id(pdu: &v2::Pdus) -> i32 {
    match pdu {
        v2::Pdus::GetRequest(p) => p.0.request_id,
        v2::Pdus::GetNextRequest(p) => p.0.request_id,
        v2::Pdus::GetBulkRequest(p) => p.0.request_id,
        v2::Pdus::SetRequest(p) => p.0.request_id,
        v2::Pdus::Response(p) => p.0.request_id,
        v2::Pdus::InformRequest(p) => p.0.request_id,
        v2::Pdus::Trap(p) => p.0.request_id,
        v2::Pdus::Report(p) => p.0.request_id,
    }
}

/// The non-authoritative side: one user talking to one agent, whose engine it discovers.
pub struct Manager {
    pub user: User,
    engine: Mutex<Option<Engine>>,
    msg_id: AtomicU32,
    salt: AtomicU64,
    /// The message ids of the last few requests, any of which a reply may answer.
    outstanding: Mutex<std::collections::VecDeque<i64>>,
}

/// How many sent message ids a reply may still match.
pub const OUTSTANDING_MESSAGES: usize = 16;

#[derive(Clone)]
struct Engine {
    id: Vec<u8>,
    boots: i64,
    time: i64,
    at: crate::utils::clock::Instant,
    keys: Keys,
}

/// What the manager made of a reply.
pub enum Reply {
    Pdu(v2::Pdus),
    /// A report: which counter, and its value.
    Report(ReportKind, u64),
}

impl Manager {
    pub fn new(user: User) -> Manager {
        Manager {
            user,
            engine: Mutex::new(None),
            msg_id: AtomicU32::new(rand::random::<u32>() >> 1),
            salt: AtomicU64::new(rand::random()),
            outstanding: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Wrap a request and remember its message id for [`Manager::unwrap_reply`].
    pub fn wrap_request(&self, pdu: v2::Pdus, context_name: &[u8]) -> Result<Vec<u8>> {
        let (msg_id, bytes) = self.wrap(pdu, context_name)?;
        let mut ids = self
            .outstanding
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?;
        if ids.len() == OUTSTANDING_MESSAGES {
            ids.pop_front();
        }
        ids.push_back(msg_id);
        Ok(bytes)
    }

    /// Open a reply to any recently sent request; the request is then no longer outstanding.
    pub fn unwrap_reply(&self, data: &[u8]) -> Result<Reply> {
        let msg_id = decode(data)?.msg_id;
        let known = self
            .outstanding
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .contains(&msg_id);
        ensure!(
            known,
            "a reply to message {msg_id}, which this client did not send"
        );
        let reply = self.unwrap(data, msg_id)?;
        if let Ok(mut ids) = self.outstanding.lock() {
            ids.retain(|id| *id != msg_id);
        }
        Ok(reply)
    }

    pub fn engine_id(&self) -> Option<Vec<u8>> {
        self.engine.lock().ok()?.as_ref().map(|e| e.id.clone())
    }

    fn next_msg_id(&self) -> i64 {
        (self.msg_id.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as i64
    }

    /// The discovery probe (RFC 3414 §4): noAuthNoPriv, empty engine and user, reportable.
    pub fn discovery(&self) -> Result<(i64, Vec<u8>)> {
        let msg_id = self.next_msg_id();
        let bytes = encode(Outgoing {
            msg_id,
            max_size: MAX_MESSAGE_SIZE,
            flags: FLAG_REPORTABLE,
            engine_id: b"",
            boots: 0,
            time: 0,
            user: b"",
            keys: None,
            salt: 0,
            context_engine_id: b"",
            context_name: b"",
            pdu: v2::Pdus::GetRequest(v2::GetRequest(v2::Pdu {
                request_id: rand::random::<i32>() & 0x7fff_ffff,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            })),
        })?;
        Ok((msg_id, bytes))
    }

    /// Learn the engine from the discovery report.
    pub fn learn(&self, data: &[u8], msg_id: i64) -> Result<()> {
        let rx = decode(data)?;
        ensure!(
            rx.msg_id == msg_id,
            "the discovery reply answers another message"
        );
        let id = rx.usm.authoritative_engine_id.to_vec();
        ensure!(
            (MIN_ENGINE_ID_BYTES..=MAX_ENGINE_ID_BYTES).contains(&id.len()),
            "the agent reported a {}-byte engine ID",
            id.len()
        );
        // The discovery report is unauthenticated: its clock is the peer's word, and is held
        // to the range RFC 3414 gives it before anything adds to it.
        let (boots, time) = engine_clock(&rx)?;
        let keys = self.user.localize(&id);
        *self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine lock"))? = Some(Engine {
            id,
            boots,
            time,
            at: crate::utils::clock::Instant::now(),
            keys,
        });
        Ok(())
    }

    /// Wrap a request PDU at the user's level, against the discovered engine.
    pub fn wrap(&self, pdu: v2::Pdus, context_name: &[u8]) -> Result<(i64, Vec<u8>)> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine lock"))?
            .clone()
            .context("the agent's engine has not been discovered")?;
        let level = self.user.level();
        let msg_id = self.next_msg_id();
        let bytes = encode(Outgoing {
            msg_id,
            max_size: MAX_MESSAGE_SIZE,
            flags: level.flags() | FLAG_REPORTABLE,
            engine_id: &engine.id,
            boots: engine.boots,
            time: engine
                .time
                .saturating_add(i64::try_from(engine.at.elapsed().as_secs()).unwrap_or(i64::MAX))
                .min(MAX_ENGINE_TIME),
            user: self.user.name.as_bytes(),
            keys: (level != SecurityLevel::NoAuthNoPriv).then_some(&engine.keys),
            salt: self.salt.fetch_add(1, Ordering::Relaxed),
            context_engine_id: &engine.id,
            context_name,
            pdu,
        })?;
        Ok((msg_id, bytes))
    }

    /// Check and open a reply to `msg_id`. A report updates the engine's clock when it is
    /// authenticated (the only report whose clock may be believed) or names the engine.
    pub fn unwrap(&self, data: &[u8], msg_id: i64) -> Result<Reply> {
        let rx = decode(data)?;
        ensure!(
            rx.msg_id == msg_id,
            "a reply to message {} while {} is outstanding",
            rx.msg_id,
            msg_id
        );
        let mut guard = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine lock"))?;
        let engine = guard.as_mut().context("no engine discovered")?;
        ensure!(
            rx.usm.authoritative_engine_id.as_ref() == engine.id.as_slice(),
            "a reply from engine {} while talking to {}",
            hex::encode(&rx.usm.authoritative_engine_id),
            hex::encode(&engine.id)
        );
        let level = SecurityLevel::from_flags(rx.flags)?;
        let authenticated = level != SecurityLevel::NoAuthNoPriv;
        if authenticated {
            ensure!(
                verify(data, &engine.keys),
                "the reply's MAC does not verify"
            );
        }
        let scoped = scoped_pdu(
            &rx,
            (level == SecurityLevel::AuthPriv).then_some(&engine.keys),
        )?;
        if let v2::Pdus::Report(r) = &scoped.data {
            if authenticated {
                let (boots, time) = engine_clock(&rx)?;
                engine.boots = boots;
                engine.time = time;
                engine.at = crate::utils::clock::Instant::now();
            }
            let vb =
                r.0.variable_bindings
                    .first()
                    .context("a report with no varbind")?;
            let kind = ReportKind::from_oid(&vb.name.to_vec()).with_context(|| {
                format!(
                    "a report naming {}",
                    vb.name
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(".")
                )
            })?;
            let count = match &vb.value {
                v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                    rasn_smi::v2::ApplicationSyntax::Counter(c),
                )) => c.0 as u64,
                _ => 0,
            };
            return Ok(Reply::Report(kind, count));
        }
        // A response must come back at the level it was asked at (RFC 3412 §7.2.11).
        ensure!(
            level == self.user.level(),
            "the reply is {}, the request was {}",
            level.name(),
            self.user.level().name()
        );
        Ok(Reply::Pdu(scoped.data))
    }
}
