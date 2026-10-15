//! Kerberos V5 (RFC 4120) wire helpers shared by the KDC and the client.
//!
//! The ASN.1 types are `picky-krb`'s; this module owns everything around them that has to be
//! right for a peer we did not write:
//!
//! * **A bounded DER walk before every decode** ([`check_der`]). `picky-asn1-der` is a serde
//!   deserializer and recurses with the nesting, so a peer that nests constructed elements
//!   deeply would otherwise choose our stack depth. The walk is iterative, refuses indefinite
//!   lengths, multi-byte tags, lengths past their parent, more than [`MAX_DER_ELEMENTS`]
//!   elements and nesting past [`MAX_DER_DEPTH`], and requires exactly one element spanning the
//!   whole buffer. Only then is the typed decoder run.
//! * **Keys** ([`Key`]): AES-CTS-HMAC-SHA1-96 (RFC 3962), 128 and 256, derived with PBKDF2 from
//!   a password and salt or drawn at random. Encryption is `picky-krb`'s; the integrity check on
//!   decryption is computed here and compared in constant time. `Key` is deliberately not
//!   `Debug`, and nothing in this module formats key bytes.
//! * Times, flags, integers, principal names and the error-code vocabulary.

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::Date;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    GeneralStringAsn1, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::data_types::{
    EncryptedData, EtypeInfo2Entry, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData,
    PrincipalName,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The ASN.1 types this module builds on, re-exported so the client and the suites name them
/// through NetGet's codec rather than reaching past it.
pub mod types {
    pub use picky_asn1::wrapper::*;
    pub use picky_krb::data_types::*;
    pub use picky_krb::messages::*;
}

/// The largest Kerberos message either role reads: a UDP datagram, or a TCP record's declared
/// length. RFC 4120 sets no maximum; 64 KiB holds any ticket this KDC issues many times over and
/// a PAC-bearing Active Directory TGT too.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Deepest constructed-element nesting accepted. The deepest legitimate path in a message this
/// code decodes is a TGS-REQ's additional ticket, about 14 levels; 24 leaves room without
/// letting a peer choose the decoder's stack depth.
pub const MAX_DER_DEPTH: usize = 24;

/// Most TLV elements accepted in one message, nested ones included.
pub const MAX_DER_ELEMENTS: usize = 4096;

/// Most components in a principal name (`host/fqdn` is two).
pub const MAX_NAME_COMPONENTS: usize = 8;

/// Longest single name component or realm, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// aes256-cts-hmac-sha1-96 (RFC 3962).
pub const ETYPE_AES256: i32 = 18;
/// aes128-cts-hmac-sha1-96 (RFC 3962).
pub const ETYPE_AES128: i32 = 17;
/// Every enctype NetGet speaks, strongest first. No DES, no RC4, no DES3.
pub const SUPPORTED_ETYPES: [i32; 2] = [ETYPE_AES256, ETYPE_AES128];

/// hmac-sha1-96-aes128 (RFC 3962 §7).
pub const CKSUM_HMAC_SHA1_96_AES128: i32 = 15;
/// hmac-sha1-96-aes256.
pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

/// PA-DATA types used here (RFC 4120 §7.5.2, RFC 6113).
pub const PA_TGS_REQ: i32 = 1;
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_ETYPE_INFO2: i32 = 19;

/// Key usage numbers (RFC 4120 §7.5.1).
pub const KU_PA_ENC_TIMESTAMP: i32 = 1;
pub const KU_TICKET: i32 = 2;
pub const KU_AS_REP_ENC_PART: i32 = 3;
pub const KU_TGS_REQ_AUTH_CKSUM: i32 = 6;
pub const KU_TGS_REQ_AUTHENTICATOR: i32 = 7;
pub const KU_TGS_REP_ENC_SESSION_KEY: i32 = 8;
pub const KU_TGS_REP_ENC_SUBKEY: i32 = 9;
pub const KU_AP_REQ_AUTHENTICATOR: i32 = 11;

/// Application tag bytes of the messages (constructed, application class).
pub const TAG_AS_REQ: u8 = 0x6a;
pub const TAG_AS_REP: u8 = 0x6b;
pub const TAG_TGS_REQ: u8 = 0x6c;
pub const TAG_TGS_REP: u8 = 0x6d;
pub const TAG_AP_REQ: u8 = 0x6e;
pub const TAG_KRB_ERROR: u8 = 0x7e;

/// Name types (RFC 4120 §6.2).
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;
pub const NT_SRV_HST: i32 = 3;

// ---------------------------------------------------------------------------------------------
// Flag bits. RFC 4120 numbers bits from the most significant end; `bit(n)` is that bit in the
// first 32 bits read as a big-endian integer, which is how both MIT and Heimdal store them.
// ---------------------------------------------------------------------------------------------

pub const fn bit(n: u32) -> u32 {
    1 << (31 - n)
}

/// KDC options (RFC 4120 §5.4.1).
pub mod kdc_options {
    use super::bit;
    pub const FORWARDABLE: u32 = bit(1);
    pub const FORWARDED: u32 = bit(2);
    pub const PROXIABLE: u32 = bit(3);
    pub const PROXY: u32 = bit(4);
    pub const ALLOW_POSTDATE: u32 = bit(5);
    pub const POSTDATED: u32 = bit(6);
    pub const RENEWABLE: u32 = bit(8);
    pub const CANONICALIZE: u32 = bit(15);
    pub const DISABLE_TRANSITED_CHECK: u32 = bit(26);
    pub const RENEWABLE_OK: u32 = bit(27);
    pub const ENC_TKT_IN_SKEY: u32 = bit(28);
    pub const RENEW: u32 = bit(30);
    pub const VALIDATE: u32 = bit(31);

    /// Options this KDC does not implement. A request carrying one is refused with
    /// KDC_ERR_BADOPTION rather than half-honoured.
    pub const UNSUPPORTED: u32 =
        FORWARDED | PROXY | ALLOW_POSTDATE | POSTDATED | ENC_TKT_IN_SKEY | RENEW | VALIDATE;

    pub const NAMES: &[(u32, &str)] = &[
        (FORWARDABLE, "forwardable"),
        (FORWARDED, "forwarded"),
        (PROXIABLE, "proxiable"),
        (PROXY, "proxy"),
        (ALLOW_POSTDATE, "allow_postdate"),
        (POSTDATED, "postdated"),
        (RENEWABLE, "renewable"),
        (CANONICALIZE, "canonicalize"),
        (DISABLE_TRANSITED_CHECK, "disable_transited_check"),
        (RENEWABLE_OK, "renewable_ok"),
        (ENC_TKT_IN_SKEY, "enc_tkt_in_skey"),
        (RENEW, "renew"),
        (VALIDATE, "validate"),
    ];
}

/// Ticket flags (RFC 4120 §5.3).
pub mod ticket_flags {
    use super::bit;
    pub const FORWARDABLE: u32 = bit(1);
    pub const FORWARDED: u32 = bit(2);
    pub const PROXIABLE: u32 = bit(3);
    pub const PROXY: u32 = bit(4);
    pub const MAY_POSTDATE: u32 = bit(5);
    pub const POSTDATED: u32 = bit(6);
    pub const INVALID: u32 = bit(7);
    pub const RENEWABLE: u32 = bit(8);
    pub const INITIAL: u32 = bit(9);
    pub const PRE_AUTHENT: u32 = bit(10);
    pub const HW_AUTHENT: u32 = bit(11);
    pub const TRANSITED_POLICY_CHECKED: u32 = bit(12);
    pub const OK_AS_DELEGATE: u32 = bit(13);
    pub const ENC_PA_REP: u32 = bit(15);

    pub const NAMES: &[(u32, &str)] = &[
        (FORWARDABLE, "forwardable"),
        (FORWARDED, "forwarded"),
        (PROXIABLE, "proxiable"),
        (PROXY, "proxy"),
        (MAY_POSTDATE, "may_postdate"),
        (POSTDATED, "postdated"),
        (INVALID, "invalid"),
        (RENEWABLE, "renewable"),
        (INITIAL, "initial"),
        (PRE_AUTHENT, "pre_authent"),
        (HW_AUTHENT, "hw_authent"),
        (TRANSITED_POLICY_CHECKED, "transited_policy_checked"),
        (OK_AS_DELEGATE, "ok_as_delegate"),
        (ENC_PA_REP, "enc_pa_rep"),
    ];
}

/// The names of the bits set in `value`, from a `(bit, name)` table.
pub fn flag_names(value: u32, table: &[(u32, &str)]) -> Vec<String> {
    table
        .iter()
        .filter(|(b, _)| value & b != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

/// The first 32 bits of a KerberosFlags BIT STRING as an integer. Shorter strings are padded
/// with zero bits; anything past bit 31 is ignored (RFC 4120 §5.2.8 allows it and assigns none).
pub fn flags_u32(flags: &KerberosFlags) -> u32 {
    let data = flags.0.as_bytes();
    let payload = data.get(1..).unwrap_or(&[]);
    let mut out = [0u8; 4];
    for (i, b) in payload.iter().take(4).enumerate() {
        out[i] = *b;
    }
    u32::from_be_bytes(out)
}

/// A 32-bit KerberosFlags BIT STRING.
pub fn flags(value: u32) -> KerberosFlags {
    BitStringAsn1(BitString::with_bytes(value.to_be_bytes().to_vec()))
}

// ---------------------------------------------------------------------------------------------
// The bounded DER walk.
// ---------------------------------------------------------------------------------------------

/// Why a buffer was refused before any typed decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DerError {
    #[error("empty input")]
    Empty,
    #[error("message is {0} bytes; the limit is {MAX_MESSAGE_LEN}")]
    TooLarge(usize),
    #[error("truncated element at offset {0}")]
    Truncated(usize),
    #[error("indefinite length at offset {0}; DER requires definite lengths")]
    Indefinite(usize),
    #[error("multi-byte tag at offset {0}; Kerberos uses none")]
    LongTag(usize),
    #[error("length at offset {0} is wider than four octets")]
    LengthTooWide(usize),
    #[error("element at offset {0} runs past its enclosing element")]
    Overrun(usize),
    #[error("nesting deeper than {MAX_DER_DEPTH} at offset {0}")]
    TooDeep(usize),
    #[error("more than {MAX_DER_ELEMENTS} elements")]
    TooManyElements,
    #[error("{0} trailing bytes after the message")]
    Trailing(usize),
}

/// One element's header: where its content starts and how long it is.
struct Header {
    tag: u8,
    content_start: usize,
    content_len: usize,
}

/// Read the header at `pos`, bounded by `limit` (the end of the enclosing element).
fn header_at(bytes: &[u8], pos: usize, limit: usize) -> Result<Header, DerError> {
    let tag = *bytes.get(pos).ok_or(DerError::Truncated(pos))?;
    if tag & 0x1f == 0x1f {
        return Err(DerError::LongTag(pos));
    }
    let first = *bytes.get(pos + 1).ok_or(DerError::Truncated(pos))?;
    let (content_len, header_len) = if first < 0x80 {
        (first as usize, 2)
    } else if first == 0x80 {
        return Err(DerError::Indefinite(pos));
    } else {
        let n = (first & 0x7f) as usize;
        if n > 4 {
            return Err(DerError::LengthTooWide(pos));
        }
        let start = pos + 2;
        let end = start.checked_add(n).ok_or(DerError::Truncated(pos))?;
        let octets = bytes.get(start..end).ok_or(DerError::Truncated(pos))?;
        let len = octets
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, 2 + n)
    };
    let content_start = pos + header_len;
    let end = content_start
        .checked_add(content_len)
        .ok_or(DerError::Overrun(pos))?;
    if end > limit || end > bytes.len() {
        return Err(DerError::Overrun(pos));
    }
    Ok(Header {
        tag,
        content_start,
        content_len,
    })
}

/// Validate `bytes` as exactly one bounded DER element. Iterative: the only memory it uses is
/// a stack of at most [`MAX_DER_DEPTH`] end offsets.
pub fn check_der(bytes: &[u8]) -> Result<(), DerError> {
    if bytes.is_empty() {
        return Err(DerError::Empty);
    }
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(DerError::TooLarge(bytes.len()));
    }
    let top = header_at(bytes, 0, bytes.len())?;
    let top_end = top.content_start + top.content_len;
    if top_end != bytes.len() {
        return Err(DerError::Trailing(bytes.len() - top_end));
    }
    // `ends` holds the end offset of every constructed element we are inside.
    let mut ends: Vec<usize> = Vec::with_capacity(MAX_DER_DEPTH);
    let mut elements = 1usize;
    let mut pos;
    if top.tag & 0x20 != 0 {
        ends.push(top_end);
        pos = top.content_start;
    } else {
        return Ok(());
    }
    while let Some(&end) = ends.last() {
        if pos == end {
            ends.pop();
            continue;
        }
        let h = header_at(bytes, pos, end)?;
        elements += 1;
        if elements > MAX_DER_ELEMENTS {
            return Err(DerError::TooManyElements);
        }
        let element_end = h.content_start + h.content_len;
        if h.tag & 0x20 != 0 {
            if ends.len() >= MAX_DER_DEPTH {
                return Err(DerError::TooDeep(pos));
            }
            ends.push(element_end);
            pos = h.content_start;
        } else {
            pos = element_end;
        }
    }
    Ok(())
}

/// Decode a bounded DER message into a `picky-krb` type.
///
/// [`check_der`] runs first, so the serde decoder only ever sees a buffer whose nesting and
/// lengths are already bounded. A panic inside the decoder is caught and reported as a refusal:
/// a peer must not be able to take a task down by sending bytes the library did not expect.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    check_der(bytes).map_err(|e| anyhow!("refused before decoding: {e}"))?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        picky_asn1_der::from_bytes::<T>(bytes)
    }));
    match result {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(anyhow!("DER decode failed: {e}")),
        Err(_) => Err(anyhow!("DER decoder panicked; refused")),
    }
}

/// Encode a `picky-krb` value.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    picky_asn1_der::to_vec(value).map_err(|e| anyhow!("DER encode failed: {e}"))
}

/// The raw DER of a KDC-REQ's `req-body` ([4] KDC-REQ-BODY), exactly as the peer sent it. The
/// TGS authenticator's checksum is computed over these bytes, so they must not be re-encoded.
pub fn req_body_bytes(message: &[u8]) -> Option<&[u8]> {
    check_der(message).ok()?;
    let app = header_at(message, 0, message.len()).ok()?;
    let seq = header_at(message, app.content_start, message.len()).ok()?;
    if seq.tag != 0x30 {
        return None;
    }
    let end = seq.content_start + seq.content_len;
    let mut pos = seq.content_start;
    while pos < end {
        let field = header_at(message, pos, end).ok()?;
        let field_end = field.content_start + field.content_len;
        if field.tag == 0xa4 {
            let body = header_at(message, field.content_start, field_end).ok()?;
            let body_end = body.content_start + body.content_len;
            if body.tag != 0x30 || body_end != field_end {
                return None;
            }
            return message.get(field.content_start..body_end);
        }
        pos = field_end;
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Integers, strings, times.
// ---------------------------------------------------------------------------------------------

/// A signed INTEGER as `i64`, or `None` when it does not fit.
pub fn int_i64(value: &IntegerAsn1) -> Option<i64> {
    let bytes = value.as_signed_bytes_be();
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let fill = if bytes[0] & 0x80 != 0 { 0xff } else { 0 };
    let mut buf = [fill; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Some(i64::from_be_bytes(buf))
}

/// `value` as a minimal signed DER INTEGER.
pub fn int(value: i64) -> IntegerAsn1 {
    IntegerAsn1::from_bytes_be_signed(value.to_be_bytes().to_vec())
}

/// A KerberosString from text. KerberosString is IA5 in practice (RFC 4120 §5.2.1).
pub fn kstring(s: &str) -> Result<KerberosStringAsn1> {
    Ok(GeneralStringAsn1(
        Ia5String::from_string(s.to_string())
            .map_err(|_| anyhow!("'{s}' is not an IA5 (ASCII) string"))?,
    ))
}

/// The text of a KerberosString.
pub fn kstring_text(s: &KerberosStringAsn1) -> String {
    s.0.as_utf8().to_string()
}

/// Seconds since the Unix epoch, now.
pub fn now_secs() -> i64 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A KerberosTime (`YYYYMMDDHHMMSSZ`) for `secs` since the epoch, clamped to what
/// GeneralizedTime can hold here.
pub fn ktime(secs: i64) -> KerberosTime {
    let secs = secs.clamp(0, 253_402_300_799); // 9999-12-31T23:59:59Z
    let dt = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    use chrono::{Datelike, Timelike};
    let date = Date::new(
        dt.year() as u16,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .unwrap_or_else(|| Date::new(1970, 1, 1, 0, 0, 0).expect("the epoch is a valid date"));
    GeneralizedTimeAsn1(date)
}

/// Seconds since the epoch of a KerberosTime, or `None` for a date that does not exist.
pub fn unix(t: &KerberosTime) -> Option<i64> {
    let d = &t.0;
    let date = chrono::NaiveDate::from_ymd_opt(d.year() as i32, d.month() as u32, d.day() as u32)?;
    let time = date.and_hms_opt(d.hour() as u32, d.minute() as u32, d.second() as u32)?;
    Some(time.and_utc().timestamp())
}

/// RFC 3339 text for event payloads.
pub fn rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Principal names.
// ---------------------------------------------------------------------------------------------

/// A principal name without its realm: a name type and one or more components.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    pub name_type: i32,
    pub components: Vec<String>,
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.components.join("/"))
    }
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Principal({self})")
    }
}

/// Refuse a name component or realm a peer sent that cannot be shown or compared safely.
fn check_component(s: &str, what: &str) -> Result<()> {
    if s.is_empty() {
        return Err(anyhow!("empty {what}"));
    }
    if s.len() > MAX_NAME_LEN {
        return Err(anyhow!(
            "{what} is {} bytes; the limit is {MAX_NAME_LEN}",
            s.len()
        ));
    }
    if crate::utils::sanitize::has_controls(s) {
        return Err(anyhow!("{what} contains a control character"));
    }
    if s.contains('/') || s.contains('@') || s.contains('\\') {
        return Err(anyhow!("{what} contains '/', '@' or '\\'"));
    }
    Ok(())
}

/// Refuse a realm a peer sent or the operator configured.
pub fn check_realm(realm: &str) -> Result<()> {
    if realm.is_empty() || realm.len() > MAX_NAME_LEN {
        return Err(anyhow!("realm must be 1-{MAX_NAME_LEN} bytes"));
    }
    if !realm.is_ascii() || crate::utils::sanitize::has_controls(realm) {
        return Err(anyhow!("realm must be printable ASCII"));
    }
    if realm.contains('/') || realm.contains('@') || realm.contains('\\') {
        return Err(anyhow!("realm contains '/', '@' or '\\'"));
    }
    Ok(())
}

impl Principal {
    /// `krbtgt/REALM`, the ticket-granting service.
    pub fn krbtgt(realm: &str) -> Self {
        Self {
            name_type: NT_SRV_INST,
            components: vec!["krbtgt".to_string(), realm.to_string()],
        }
    }

    /// Parse `a/b` or `a/b@REALM`. Returns the principal and the realm it named, if any.
    pub fn parse(text: &str) -> Result<(Self, Option<String>)> {
        let (name, realm) = match text.rsplit_once('@') {
            Some((n, r)) => {
                check_realm(r)?;
                (n, Some(r.to_string()))
            }
            None => (text, None),
        };
        let components: Vec<String> = name.split('/').map(str::to_string).collect();
        if components.len() > MAX_NAME_COMPONENTS {
            return Err(anyhow!(
                "'{name}' has more than {MAX_NAME_COMPONENTS} components"
            ));
        }
        for c in &components {
            check_component(c, "principal name component")?;
        }
        let name_type = if components.len() > 1 {
            NT_SRV_INST
        } else {
            NT_PRINCIPAL
        };
        Ok((
            Self {
                name_type,
                components,
            },
            realm,
        ))
    }

    /// Read a PrincipalName a peer sent, refusing anything unsafe to show or compare.
    pub fn from_asn1(name: &PrincipalName) -> Result<Self> {
        let name_type = int_i64(&name.name_type.0)
            .and_then(|v| i32::try_from(v).ok())
            .context("name-type out of range")?;
        let parts = &name.name_string.0 .0;
        if parts.is_empty() || parts.len() > MAX_NAME_COMPONENTS {
            return Err(anyhow!(
                "a principal name needs 1-{MAX_NAME_COMPONENTS} components, not {}",
                parts.len()
            ));
        }
        let mut components = Vec::with_capacity(parts.len());
        for p in parts {
            let s = kstring_text(p);
            check_component(&s, "principal name component")?;
            components.push(s);
        }
        Ok(Self {
            name_type,
            components,
        })
    }

    pub fn to_asn1(&self) -> Result<PrincipalName> {
        let mut parts = Vec::with_capacity(self.components.len());
        for c in &self.components {
            parts.push(kstring(c)?);
        }
        Ok(PrincipalName {
            name_type: ExplicitContextTag0(int(self.name_type as i64)),
            name_string: ExplicitContextTag1(Asn1SequenceOf(parts)),
        })
    }

    /// Same name, ignoring the name type (RFC 4120 §6.2: the type is a hint, not part of the
    /// name).
    pub fn same_name(&self, other: &Principal) -> bool {
        self.components == other.components
    }

    pub fn is_krbtgt(&self, realm: &str) -> bool {
        self.components.len() == 2 && self.components[0] == "krbtgt" && self.components[1] == realm
    }

    /// The default salt for this principal in `realm`: the realm followed by every component
    /// (RFC 3961 §4 / RFC 4120 §4).
    pub fn default_salt(&self, realm: &str) -> String {
        let mut s = realm.to_string();
        for c in &self.components {
            s.push_str(c);
        }
        s
    }
}

// ---------------------------------------------------------------------------------------------
// Enctypes and keys.
// ---------------------------------------------------------------------------------------------

/// The registered name of an enctype, for events.
pub fn etype_name(etype: i32) -> String {
    match etype {
        1 => "des-cbc-crc".into(),
        3 => "des-cbc-md5".into(),
        16 => "des3-cbc-sha1".into(),
        17 => "aes128-cts-hmac-sha1-96".into(),
        18 => "aes256-cts-hmac-sha1-96".into(),
        19 => "aes128-cts-hmac-sha256-128".into(),
        20 => "aes256-cts-hmac-sha384-192".into(),
        23 => "arcfour-hmac".into(),
        24 => "arcfour-hmac-exp".into(),
        25 => "camellia128-cts-cmac".into(),
        26 => "camellia256-cts-cmac".into(),
        other => format!("etype-{other}"),
    }
}

fn suite(etype: i32) -> Result<CipherSuite> {
    match etype {
        ETYPE_AES256 => Ok(CipherSuite::Aes256CtsHmacSha196),
        ETYPE_AES128 => Ok(CipherSuite::Aes128CtsHmacSha196),
        other => Err(anyhow!("enctype {} is not supported", etype_name(other))),
    }
}

fn key_len(etype: i32) -> usize {
    if etype == ETYPE_AES256 {
        32
    } else {
        16
    }
}

/// Why a decryption failed. Distinguished because the KDC answers them differently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported enctype {0}")]
    Etype(i32),
    #[error("ciphertext is too short")]
    Length,
    #[error("integrity check failed")]
    Integrity,
    #[error("cipher error")]
    Cipher,
}

/// A Kerberos key. Not `Debug`, not `Display`, not `Serialize`: the bytes leave this type only
/// as a ciphertext, a checksum, or the EncryptionKey inside an encrypted part.
#[derive(Clone)]
pub struct Key {
    etype: i32,
    bytes: Vec<u8>,
}

impl Key {
    /// Derive a key from a password with PBKDF2-HMAC-SHA1, 4096 iterations (RFC 3962 §4's
    /// default, and what both MIT and Heimdal use when no s2kparams are sent).
    pub fn from_password(etype: i32, password: &str, salt: &str) -> Result<Self> {
        let bytes = suite(etype)?
            .cipher()
            .generate_key_from_password(password.as_bytes(), salt.as_bytes())
            .map_err(|_| anyhow!("string-to-key failed for {}", etype_name(etype)))?;
        Ok(Self { etype, bytes })
    }

    /// A fresh random key from the operating system's generator.
    pub fn random(etype: i32) -> Result<Self> {
        suite(etype)?;
        let mut bytes = vec![0u8; key_len(etype)];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Ok(Self { etype, bytes })
    }

    /// A key a peer delivered inside an encrypted part (a session key or a subkey).
    pub fn from_wire(etype: i32, bytes: Vec<u8>) -> Result<Self> {
        suite(etype)?;
        if bytes.len() != key_len(etype) {
            return Err(anyhow!(
                "a {} key must be {} bytes",
                etype_name(etype),
                key_len(etype)
            ));
        }
        Ok(Self { etype, bytes })
    }

    pub fn etype(&self) -> i32 {
        self.etype
    }

    /// The EncryptionKey structure carrying this key, for an encrypted part only.
    pub fn to_asn1(&self) -> picky_krb::data_types::EncryptionKey {
        picky_krb::data_types::EncryptionKey {
            key_type: ExplicitContextTag0(int(self.etype as i64)),
            key_value: ExplicitContextTag1(OctetStringAsn1(self.bytes.clone())),
        }
    }

    /// Read an EncryptionKey out of a decrypted part.
    pub fn from_asn1(key: &picky_krb::data_types::EncryptionKey) -> Result<Self> {
        let etype = int_i64(&key.key_type.0)
            .and_then(|v| i32::try_from(v).ok())
            .context("key type out of range")?;
        Self::from_wire(etype, key.key_value.0 .0.clone())
    }

    /// The raw key bytes, for the client's credential cache file only.
    pub fn bytes_for_ccache(&self) -> &[u8] {
        &self.bytes
    }

    /// Encrypt `plaintext` under `usage` with a fresh random confounder.
    pub fn encrypt(&self, usage: i32, plaintext: &[u8]) -> Result<Vec<u8>> {
        suite(self.etype)?
            .cipher()
            .encrypt(&self.bytes, usage, plaintext)
            .map_err(|_| anyhow!("encryption failed"))
    }

    /// Encrypt into an EncryptedData with this key's enctype.
    pub fn encrypted_data(
        &self,
        usage: i32,
        plaintext: &[u8],
        kvno: Option<i64>,
    ) -> Result<EncryptedData> {
        Ok(EncryptedData {
            etype: ExplicitContextTag0(int(self.etype as i64)),
            kvno: Optional(kvno.map(|k| ExplicitContextTag1(int(k)))),
            cipher: ExplicitContextTag2(OctetStringAsn1(self.encrypt(usage, plaintext)?)),
        })
    }

    /// Decrypt and verify. The HMAC-SHA1-96 over confounder and plaintext is recomputed here
    /// and compared in constant time; nothing is returned unless it matches.
    pub fn decrypt(&self, usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = suite(self.etype)
            .map_err(|_| CryptoError::Etype(self.etype))?
            .cipher();
        if ciphertext.len() < 16 + 12 {
            return Err(CryptoError::Length);
        }
        let parts = cipher
            .decrypt_no_checksum(&self.bytes, usage, ciphertext)
            .map_err(|_| CryptoError::Cipher)?;
        let mut mac =
            Hmac::<sha1::Sha1>::new_from_slice(&parts.ki).map_err(|_| CryptoError::Cipher)?;
        mac.update(&parts.confounder);
        mac.update(&parts.plaintext);
        let full = mac.finalize().into_bytes();
        if !constant_time_eq(&full[..12], &parts.checksum) {
            return Err(CryptoError::Integrity);
        }
        Ok(parts.plaintext)
    }

    /// Decrypt an EncryptedData, refusing one whose enctype is not this key's.
    pub fn decrypt_data(&self, usage: i32, data: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        let etype = int_i64(&data.etype.0).unwrap_or(-1);
        if etype != self.etype as i64 {
            return Err(CryptoError::Etype(etype as i32));
        }
        self.decrypt(usage, &data.cipher.0 .0)
    }

    /// The keyed checksum type that goes with this key's enctype.
    pub fn checksum_type(&self) -> i32 {
        if self.etype == ETYPE_AES256 {
            CKSUM_HMAC_SHA1_96_AES256
        } else {
            CKSUM_HMAC_SHA1_96_AES128
        }
    }

    /// The keyed checksum of `data` under `usage`: HMAC-SHA1-96 with the checksum key
    /// Kc = DK(key, usage | 0x99) (RFC 3961 §5.3, RFC 3962). Not the encryption integrity key
    /// Ki (usage | 0x55): the two differ, and only Heimdal's TGS-REQ showed it, since NetGet's
    /// client and KDC agreed with each other on the wrong one.
    pub fn checksum(&self, usage: i32, data: &[u8]) -> Result<Vec<u8>> {
        let suite = if self.etype == ETYPE_AES256 {
            ChecksumSuite::HmacSha196Aes256
        } else {
            ChecksumSuite::HmacSha196Aes128
        };
        suite
            .hasher()
            .checksum(&self.bytes, usage, data)
            .map_err(|_| anyhow!("checksum failed"))
    }

    /// Verify a keyed checksum. Only this key's own checksum type is accepted: an unkeyed or
    /// foreign checksum type would let a peer that does not hold the key forge one.
    pub fn verify_checksum(
        &self,
        cksumtype: i32,
        usage: i32,
        data: &[u8],
        expected: &[u8],
    ) -> bool {
        if cksumtype != self.checksum_type() {
            return false;
        }
        match self.checksum(usage, data) {
            Ok(sum) => constant_time_eq(&sum, expected),
            Err(_) => false,
        }
    }
}

/// Compare two byte strings without an early exit on the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------------------------
// PA-DATA helpers.
// ---------------------------------------------------------------------------------------------

pub fn padata(padata_type: i32, value: Vec<u8>) -> PaData {
    PaData {
        padata_type: ExplicitContextTag1(int(padata_type as i64)),
        padata_data: ExplicitContextTag2(OctetStringAsn1(value)),
    }
}

pub fn padata_type(p: &PaData) -> i64 {
    int_i64(&p.padata_type.0).unwrap_or(-1)
}

/// The DER of an ETYPE-INFO2 (RFC 4120 §5.2.7.5) naming each `(etype, salt)`.
pub fn etype_info2(entries: &[(i32, String)]) -> Result<Vec<u8>> {
    let mut list = Vec::with_capacity(entries.len());
    for (etype, salt) in entries {
        list.push(EtypeInfo2Entry {
            etype: ExplicitContextTag0(int(*etype as i64)),
            salt: Optional(Some(ExplicitContextTag1(kstring(salt)?))),
            s2kparams: Optional(None),
        });
    }
    encode(&Asn1SequenceOf(list))
}

// ---------------------------------------------------------------------------------------------
// Error codes (RFC 4120 §7.5.9).
// ---------------------------------------------------------------------------------------------

pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_NEVER_VALID: i32 = 11;
pub const KDC_ERR_POLICY: i32 = 12;
pub const KDC_ERR_BADOPTION: i32 = 13;
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
pub const KRB_AP_ERR_REPEAT: i32 = 34;
pub const KRB_AP_ERR_BADMATCH: i32 = 36;
pub const KRB_AP_ERR_SKEW: i32 = 37;
pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
pub const KRB_AP_ERR_MODIFIED: i32 = 41;
pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
pub const KRB_ERR_GENERIC: i32 = 60;
pub const KRB_ERR_FIELD_TOOLONG: i32 = 61;
pub const KDC_ERR_WRONG_REALM: i32 = 68;

/// Every error code with its RFC name.
pub const ERROR_NAMES: &[(i32, &str)] = &[
    (0, "KDC_ERR_NONE"),
    (1, "KDC_ERR_NAME_EXP"),
    (2, "KDC_ERR_SERVICE_EXP"),
    (3, "KDC_ERR_BAD_PVNO"),
    (4, "KDC_ERR_C_OLD_MAST_KVNO"),
    (5, "KDC_ERR_S_OLD_MAST_KVNO"),
    (6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"),
    (7, "KDC_ERR_S_PRINCIPAL_UNKNOWN"),
    (8, "KDC_ERR_PRINCIPAL_NOT_UNIQUE"),
    (9, "KDC_ERR_NULL_KEY"),
    (10, "KDC_ERR_CANNOT_POSTDATE"),
    (11, "KDC_ERR_NEVER_VALID"),
    (12, "KDC_ERR_POLICY"),
    (13, "KDC_ERR_BADOPTION"),
    (14, "KDC_ERR_ETYPE_NOSUPP"),
    (15, "KDC_ERR_SUMTYPE_NOSUPP"),
    (16, "KDC_ERR_PADATA_TYPE_NOSUPP"),
    (17, "KDC_ERR_TRTYPE_NOSUPP"),
    (18, "KDC_ERR_CLIENT_REVOKED"),
    (19, "KDC_ERR_SERVICE_REVOKED"),
    (20, "KDC_ERR_TGT_REVOKED"),
    (21, "KDC_ERR_CLIENT_NOTYET"),
    (22, "KDC_ERR_SERVICE_NOTYET"),
    (23, "KDC_ERR_KEY_EXPIRED"),
    (24, "KDC_ERR_PREAUTH_FAILED"),
    (25, "KDC_ERR_PREAUTH_REQUIRED"),
    (26, "KDC_ERR_SERVER_NOMATCH"),
    (27, "KDC_ERR_MUST_USE_USER2USER"),
    (28, "KDC_ERR_PATH_NOT_ACCEPTED"),
    (29, "KDC_ERR_SVC_UNAVAILABLE"),
    (31, "KRB_AP_ERR_BAD_INTEGRITY"),
    (32, "KRB_AP_ERR_TKT_EXPIRED"),
    (33, "KRB_AP_ERR_TKT_NYV"),
    (34, "KRB_AP_ERR_REPEAT"),
    (35, "KRB_AP_ERR_NOT_US"),
    (36, "KRB_AP_ERR_BADMATCH"),
    (37, "KRB_AP_ERR_SKEW"),
    (38, "KRB_AP_ERR_BADADDR"),
    (39, "KRB_AP_ERR_BADVERSION"),
    (40, "KRB_AP_ERR_MSG_TYPE"),
    (41, "KRB_AP_ERR_MODIFIED"),
    (42, "KRB_AP_ERR_BADORDER"),
    (44, "KRB_AP_ERR_BADKEYVER"),
    (45, "KRB_AP_ERR_NOKEY"),
    (46, "KRB_AP_ERR_MUT_FAIL"),
    (47, "KRB_AP_ERR_BADDIRECTION"),
    (48, "KRB_AP_ERR_METHOD"),
    (49, "KRB_AP_ERR_BADSEQ"),
    (50, "KRB_AP_ERR_INAPP_CKSUM"),
    (51, "KRB_AP_PATH_NOT_ACCEPTED"),
    (52, "KRB_ERR_RESPONSE_TOO_BIG"),
    (60, "KRB_ERR_GENERIC"),
    (61, "KRB_ERR_FIELD_TOOLONG"),
    (68, "KDC_ERR_WRONG_REALM"),
];

/// The RFC name of an error code.
pub fn error_name(code: i32) -> String {
    ERROR_NAMES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("KRB_ERROR_{code}"))
}

/// The refusals the model may choose. KDC_ERR_SVC_UNAVAILABLE and KRB_ERR_GENERIC are absent on
/// purpose: they are what the server sends when no decision was produced, and keeping them out
/// of the model's vocabulary keeps "the model refused" and "nobody decided" apart on the wire.
pub const MODEL_REFUSALS: &[i32] = &[
    1, 2, 6, 7, 10, 11, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24, 27,
];

/// Resolve a refusal the model named — `C_PRINCIPAL_UNKNOWN`, `KDC_ERR_POLICY`, `policy` or the
/// number — to a code in [`MODEL_REFUSALS`].
pub fn model_refusal_code(value: &serde_json::Value) -> Result<i32> {
    let code = if let Some(n) = value.as_i64() {
        i32::try_from(n).ok()
    } else if let Some(s) = value.as_str() {
        let wanted = s.trim().to_ascii_uppercase().replace(['-', ' '], "_");
        ERROR_NAMES
            .iter()
            .find(|(_, name)| {
                *name == wanted
                    || name.strip_prefix("KDC_ERR_") == Some(wanted.as_str())
                    || name.strip_prefix("KRB_AP_ERR_") == Some(wanted.as_str())
            })
            .map(|(c, _)| *c)
    } else {
        None
    };
    match code {
        Some(c) if MODEL_REFUSALS.contains(&c) => Ok(c),
        _ => Err(anyhow!(
            "'error' must be one of: {}",
            MODEL_REFUSALS
                .iter()
                .map(|c| error_name(*c).trim_start_matches("KDC_ERR_").to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}
