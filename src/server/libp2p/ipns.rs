//! What this host's DHT keeps in Rust: IPNS records (PUT_VALUE / GET_VALUE) and provider
//! records (ADD_PROVIDER / GET_PROVIDERS). Both are facts peers announce, not content the model
//! makes up, so they are validated and kept here, bounded, and expire.
//!
//! An IPNS record (the IPNS Record spec, as Kubo writes it) is an `IpnsEntry` protobuf whose
//! `data` is a DAG-CBOR map {Value, Validity, ValidityType, Sequence, TTL} signed with the
//! name's key (`signatureV2` over `"ipns-signature:" ‖ data`). A record is kept only when:
//! it is at most [`MAX_RECORD`] bytes; its key is `/ipns/<peer id>`; the signature verifies
//! with the Ed25519 key the peer id inlines (and `pubKey`, when present, is that key); the
//! CBOR is a flat map of the five fields; any V1 protobuf fields agree with it; and it has not
//! expired. A newer record replaces an older one by Sequence, then by Validity; an older one
//! is refused, as go-libp2p-kad-dht refuses it.
//!
//! The CBOR reader takes one flat map of scalars and nothing nested, so it cannot recurse.
use super::wire::{self, pb_bytes, pb_fields_bounded, PbValue};
use crate::utils::clock::Instant;
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;
use std::time::Duration;

/// A record is at most this long (the IPNS spec's own limit).
pub const MAX_RECORD: usize = 10 * 1024;
/// Names one host keeps records for.
pub const MAX_RECORDS: usize = 1024;
/// Content keys one host keeps providers for, and providers per key (Kademlia's k).
pub const MAX_PROVIDER_KEYS: usize = 4096;
pub const MAX_PROVIDERS_PER_KEY: usize = 20;
/// How long a provider record lasts (go-libp2p-kad-dht's `amino.DefaultProvideValidity`).
pub const PROVIDER_TTL: Duration = Duration::from_secs(48 * 3600);
/// Entries the CBOR map may carry.
const MAX_CBOR_ENTRIES: usize = 16;
const SIGNATURE_PREFIX: &[u8] = b"ipns-signature:";

/// A verified IPNS record.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// The name: the binary peer id after `/ipns/`.
    pub name: Vec<u8>,
    /// What the name points to, e.g. `/ipfs/bafy…`.
    pub value: Vec<u8>,
    pub sequence: u64,
    /// The end of validity, RFC 3339 as written.
    pub validity: String,
    pub validity_unix_nanos: i128,
    pub ttl_nanos: u64,
    /// The record as it travelled.
    pub bytes: Vec<u8>,
}

impl Record {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": wire::base58(&self.name),
            "value": String::from_utf8_lossy(&self.value),
            "sequence": self.sequence,
            "validity": self.validity,
            "ttl_secs": self.ttl_nanos / 1_000_000_000,
        })
    }
}

/// The name a DHT key names: `/ipns/` and a peer id.
pub fn name_of_key(key: &[u8]) -> Result<&[u8]> {
    let name = key
        .strip_prefix(b"/ipns/")
        .context("only /ipns/ records are kept")?;
    ensure!(
        name.len() >= 2 && name.len() <= 64,
        "an /ipns/ key names a peer id"
    );
    Ok(name)
}

/// The DHT key for an IPNS name given as a peer id in text (`12D3KooW…`).
pub fn key_for_name(name: &str) -> Result<Vec<u8>> {
    let id = super::kad::parse_peer_id(name.trim_start_matches("/ipns/"))?;
    let mut key = b"/ipns/".to_vec();
    key.extend(id);
    Ok(key)
}

// ---------------------------------------------------------------------------------------
// The CBOR subset: one map of text keys to unsigned integers, byte strings or text.

#[derive(Clone, Debug, PartialEq)]
pub enum Scalar {
    Uint(u64),
    Bytes(Vec<u8>),
}

fn cbor_head(b: &[u8], at: &mut usize) -> Result<(u8, u64)> {
    let first = *b.get(*at).context("truncated CBOR")?;
    *at += 1;
    let (major, info) = (first >> 5, first & 31);
    let n = match info {
        0..=23 => u64::from(info),
        24..=27 => {
            let len = 1usize << (info - 24);
            let bytes = b.get(*at..*at + len).context("truncated CBOR")?;
            *at += len;
            bytes.iter().fold(0u64, |acc, x| acc << 8 | u64::from(*x))
        }
        _ => bail!("indefinite or reserved CBOR lengths are not DAG-CBOR"),
    };
    Ok((major, n))
}

fn cbor_string(b: &[u8], at: &mut usize, n: u64) -> Result<Vec<u8>> {
    let n = usize::try_from(n)
        .ok()
        .filter(|n| *n <= b.len())
        .context("CBOR string too long")?;
    let s = b.get(*at..*at + n).context("truncated CBOR string")?;
    *at += n;
    Ok(s.to_vec())
}

/// The `data` of a record: one flat DAG-CBOR map of text keys to scalars. Anything nested is
/// refused, so the reader never recurses.
pub fn cbor_map(b: &[u8]) -> Result<HashMap<String, Scalar>> {
    let mut at = 0;
    let (major, entries) = cbor_head(b, &mut at)?;
    ensure!(major == 5, "IPNS data is not a CBOR map");
    ensure!(
        entries as usize <= MAX_CBOR_ENTRIES,
        "IPNS data has more than {MAX_CBOR_ENTRIES} entries"
    );
    let mut map = HashMap::new();
    for _ in 0..entries {
        let (km, kn) = cbor_head(b, &mut at)?;
        ensure!(km == 3, "IPNS data keys are text");
        let key = String::from_utf8(cbor_string(b, &mut at, kn)?).context("key is not UTF-8")?;
        let (vm, vn) = cbor_head(b, &mut at)?;
        let value = match vm {
            0 => Scalar::Uint(vn),
            2 | 3 => Scalar::Bytes(cbor_string(b, &mut at, vn)?),
            _ => bail!("IPNS data field {key:?} is not a scalar"),
        };
        ensure!(
            map.insert(key.clone(), value).is_none(),
            "IPNS data repeats {key:?}"
        );
    }
    ensure!(at == b.len(), "trailing bytes after the IPNS data");
    Ok(map)
}

fn cbor_put_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes())
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes())
        }
    }
}

/// The DAG-CBOR `data` of a record (keys in DAG-CBOR order: shorter first, then bytewise).
pub fn encode_data(value: &[u8], validity: &str, sequence: u64, ttl_nanos: u64) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_put_head(&mut out, 5, 5);
    let text = |out: &mut Vec<u8>, s: &str| {
        cbor_put_head(out, 3, s.len() as u64);
        out.extend(s.as_bytes());
    };
    let bytes = |out: &mut Vec<u8>, b: &[u8]| {
        cbor_put_head(out, 2, b.len() as u64);
        out.extend(b);
    };
    text(&mut out, "TTL");
    cbor_put_head(&mut out, 0, ttl_nanos);
    text(&mut out, "Value");
    bytes(&mut out, value);
    text(&mut out, "Sequence");
    cbor_put_head(&mut out, 0, sequence);
    text(&mut out, "Validity");
    bytes(&mut out, validity.as_bytes());
    text(&mut out, "ValidityType");
    cbor_put_head(&mut out, 0, 0);
    out
}

/// A V2-only record signed by `identity`, as an IPNS publisher writes it.
pub fn sign_record(
    identity: &super::noise::Identity,
    value: &[u8],
    validity: &str,
    sequence: u64,
    ttl_nanos: u64,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let data = encode_data(value, validity, sequence, ttl_nanos);
    let mut signed = SIGNATURE_PREFIX.to_vec();
    signed.extend(&data);
    let sig = identity.key.sign(&signed).to_bytes();
    let mut out = Vec::new();
    pb_bytes(&mut out, 8, &sig);
    pb_bytes(&mut out, 9, &data);
    out
}

/// Parse and verify a record stored under `key` (`/ipns/<peer id>`), at `now_unix_nanos`.
pub fn verify(key: &[u8], bytes: &[u8], now_unix_nanos: i128) -> Result<Record> {
    ensure!(
        bytes.len() <= MAX_RECORD,
        "an IPNS record is at most {MAX_RECORD} bytes"
    );
    let name = name_of_key(key)?;
    let mut v1 = HashMap::new();
    let (mut pub_key, mut sig, mut data) = (None, None, None);
    for (f, v) in pb_fields_bounded(bytes, 16)? {
        match (f, v) {
            (1 | 2 | 4, PbValue::Bytes(b)) => {
                v1.insert(f, Scalar::Bytes(b.to_vec()));
            }
            (3 | 5 | 6, PbValue::Varint(n)) => {
                v1.insert(f, Scalar::Uint(n));
            }
            (7, PbValue::Bytes(b)) => pub_key = Some(b),
            (8, PbValue::Bytes(b)) => sig = Some(b),
            (9, PbValue::Bytes(b)) => data = Some(b),
            _ => bail!("malformed IPNS record (field {f})"),
        }
    }
    let sig = sig.context("the record has no signatureV2 (V1-only records are refused)")?;
    let data = data.context("the record has no data")?;
    // The key: inlined in an identity-multihash peer id, and pubKey must agree with it.
    let key_proto = match name {
        [0x00, len, rest @ ..] if usize::from(*len) == rest.len() => rest.to_vec(),
        _ => {
            let pk = pub_key.context("the name is a hashed key and the record carries none")?;
            ensure!(
                wire::peer_id(pk) == name,
                "the record's pubKey is not the name's key"
            );
            pk.to_vec()
        }
    };
    if let Some(pk) = pub_key {
        ensure!(pk == key_proto, "the record's pubKey is not the name's key");
    }
    let ed = wire::parse_public_key(&key_proto)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&ed).context("invalid Ed25519 key")?;
    let sig = ed25519_dalek::Signature::from_slice(sig).context("signatureV2 must be 64 bytes")?;
    let mut signed = SIGNATURE_PREFIX.to_vec();
    signed.extend(data);
    use ed25519_dalek::Verifier;
    vk.verify(&signed, &sig)
        .context("signatureV2 does not verify with the name's key")?;
    let map = cbor_map(data)?;
    let bytes_of = |k: &str| match map.get(k) {
        Some(Scalar::Bytes(b)) => Ok(b.clone()),
        _ => bail!("IPNS data has no {k}"),
    };
    let uint_of = |k: &str| match map.get(k) {
        Some(Scalar::Uint(n)) => Ok(*n),
        _ => bail!("IPNS data has no {k}"),
    };
    let value = bytes_of("Value")?;
    let validity_bytes = bytes_of("Validity")?;
    let validity_type = uint_of("ValidityType")?;
    let sequence = uint_of("Sequence")?;
    let ttl = uint_of("TTL")?;
    ensure!(validity_type == 0, "only EOL validity is supported");
    // V1 fields, where a record still carries them, must say what the signed data says.
    for (field, expected) in [
        (1, Scalar::Bytes(value.clone())),
        (4, Scalar::Bytes(validity_bytes.clone())),
        (3, Scalar::Uint(validity_type)),
        (5, Scalar::Uint(sequence)),
        (6, Scalar::Uint(ttl)),
    ] {
        if let Some(v) = v1.get(&field) {
            ensure!(
                *v == expected,
                "the record's V1 field {field} disagrees with its data"
            );
        }
    }
    let validity = String::from_utf8(validity_bytes).context("Validity is not text")?;
    let eol = chrono::DateTime::parse_from_rfc3339(&validity)
        .with_context(|| format!("Validity {validity:?} is not RFC 3339"))?;
    let eol_nanos =
        i128::from(eol.timestamp()) * 1_000_000_000 + i128::from(eol.timestamp_subsec_nanos());
    ensure!(
        eol_nanos > now_unix_nanos,
        "the record expired at {validity}"
    );
    Ok(Record {
        name: name.to_vec(),
        value,
        sequence,
        validity,
        validity_unix_nanos: eol_nanos,
        ttl_nanos: ttl,
        bytes: bytes.to_vec(),
    })
}

/// Whether `new` should replace `old`: a higher sequence, or the same with a later EOL (the
/// IPNS validator's `Select`); the same record again is accepted.
pub fn better_or_same(new: &Record, old: &Record) -> bool {
    (new.sequence, new.validity_unix_nanos) >= (old.sequence, old.validity_unix_nanos)
}

pub fn now_unix_nanos() -> i128 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// The host's DHT state: IPNS records and provider records, each bounded.
#[derive(Default)]
pub struct Dht {
    records: std::sync::Mutex<HashMap<Vec<u8>, Record>>,
    providers: std::sync::Mutex<Providers>,
}

/// Content key to the peers that announced it, each with when.
type Providers = HashMap<Vec<u8>, Vec<(super::kad::Peer, Instant)>>;

/// What a PUT_VALUE came to.
#[derive(Debug, PartialEq)]
pub enum Put {
    Stored,
    Same,
}

impl Dht {
    /// Keep a record if it verifies and is not older than the one held.
    pub fn put(&self, key: &[u8], bytes: &[u8]) -> Result<(Put, Record)> {
        let now = now_unix_nanos();
        let rec = verify(key, bytes, now)?;
        let mut t = self.records.lock().unwrap_or_else(|e| e.into_inner());
        t.retain(|_, r| r.validity_unix_nanos > now);
        if let Some(old) = t.get(&rec.name) {
            ensure!(
                better_or_same(&rec, old),
                "the record held is newer (sequence {} over {})",
                old.sequence,
                rec.sequence
            );
            if old.bytes == rec.bytes {
                return Ok((Put::Same, rec));
            }
        } else {
            ensure!(
                t.len() < MAX_RECORDS,
                "this host keeps at most {MAX_RECORDS} names"
            );
        }
        t.insert(rec.name.clone(), rec.clone());
        Ok((Put::Stored, rec))
    }
    /// The record held for a key, if it has not expired.
    pub fn get(&self, key: &[u8]) -> Option<Record> {
        let name = name_of_key(key).ok()?;
        let now = now_unix_nanos();
        let t = self.records.lock().unwrap_or_else(|e| e.into_inner());
        t.get(name).filter(|r| r.validity_unix_nanos > now).cloned()
    }
    /// Remember a provider for a content key (a sha2-256 multihash).
    pub fn add_provider(&self, key: &[u8], peer: super::kad::Peer) {
        let mut t = self.providers.lock().unwrap_or_else(|e| e.into_inner());
        if !t.contains_key(key) && t.len() >= MAX_PROVIDER_KEYS {
            // Forget the key whose newest announcement is oldest.
            let stalest = t
                .iter()
                .min_by_key(|(_, v)| v.iter().map(|(_, at)| *at).max())
                .map(|(k, _)| k.clone());
            if let Some(k) = stalest {
                t.remove(&k);
            }
        }
        let list = t.entry(key.to_vec()).or_default();
        list.retain(|(p, at)| p.id != peer.id && at.elapsed() < PROVIDER_TTL);
        if list.len() >= MAX_PROVIDERS_PER_KEY {
            list.remove(0);
        }
        list.push((peer, Instant::now()));
    }
    /// The providers announced for a key and not yet expired.
    pub fn providers(&self, key: &[u8]) -> Vec<super::kad::Peer> {
        let mut t = self.providers.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = t.get_mut(key) else {
            return Vec::new();
        };
        list.retain(|(_, at)| at.elapsed() < PROVIDER_TTL);
        list.iter().map(|(p, _)| p.clone()).collect()
    }
    pub fn record_count(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// The Record protobuf a DHT message carries (field 3): key, value, and when it was received.
pub fn encode_dht_record(key: &[u8], value: &[u8], time_received: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    pb_bytes(&mut out, 1, key);
    pb_bytes(&mut out, 2, value);
    if let Some(t) = time_received {
        pb_bytes(&mut out, 5, t.as_bytes());
    }
    out
}

/// (key, value) of a DHT Record protobuf.
pub fn decode_dht_record(b: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (mut key, mut value) = (None, None);
    for (f, v) in pb_fields_bounded(b, 8)? {
        match (f, v) {
            (1, PbValue::Bytes(k)) => key = Some(k.to_vec()),
            (2, PbValue::Bytes(v)) => value = Some(v.to_vec()),
            (5, PbValue::Bytes(_)) => {}
            _ => bail!("malformed DHT record (field {f})"),
        }
    }
    Ok((key.unwrap_or_default(), value.unwrap_or_default()))
}
