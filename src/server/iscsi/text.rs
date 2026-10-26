//! iSCSI text keys (RFC 7143 §6): `key=value` pairs separated by NUL, and the negotiation of
//! the operational keys both roles exchange during login.
//!
//! The peer chooses every key, value and count here, so each is bounded: a key name is at most
//! 63 bytes (§6.1), a value at most [`MAX_VALUE`], a negotiation at most [`MAX_KEYS`] keys, and
//! the text of one exchange (continued over PDUs with the C bit) at most [`MAX_TEXT`] bytes.

/// Key names are at most 63 bytes (RFC 7143 §6.1).
pub const MAX_KEY: usize = 63;
/// A value is at most 255 bytes, except the binary CHAP values and SendTargets lists, which
/// may run to 8192 (§6.1, §12.1.3).
pub const MAX_VALUE: usize = 8192;
/// Keys in one login or text exchange.
pub const MAX_KEYS: usize = 128;
/// Bytes of text in one exchange, across continued PDUs.
pub const MAX_TEXT: usize = 64 * 1024;

/// Our MaxRecvDataSegmentLength, which we declare in every login.
pub const OUR_MAX_RECV_DATA_SEGMENT: u32 = 262_144;
/// What we offer for MaxBurstLength and FirstBurstLength.
pub const OUR_MAX_BURST: u32 = 262_144;
pub const OUR_FIRST_BURST: u32 = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub enum TextError {
    Malformed(&'static str),
    TooMany,
    TooLong,
    Duplicate(String),
}

impl std::fmt::Display for TextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed text: {why}"),
            Self::TooMany => write!(f, "more than {MAX_KEYS} keys"),
            Self::TooLong => write!(f, "a key or value over its length bound"),
            Self::Duplicate(k) => write!(f, "key {k} sent twice"),
        }
    }
}

/// Parse `key=value\0…` text. Keys are checked for the RFC's character set, and a key sent
/// twice in one exchange is an error.
pub fn parse(data: &[u8]) -> Result<Vec<(String, String)>, TextError> {
    if data.len() > MAX_TEXT {
        return Err(TextError::TooLong);
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for item in data.split(|b| *b == 0) {
        if item.is_empty() {
            continue;
        }
        if out.len() >= MAX_KEYS {
            return Err(TextError::TooMany);
        }
        let eq = item
            .iter()
            .position(|b| *b == b'=')
            .ok_or(TextError::Malformed("a key without ="))?;
        let (k, v) = (&item[..eq], &item[eq + 1..]);
        if k.is_empty() || k.len() > MAX_KEY || v.len() > MAX_VALUE {
            return Err(TextError::TooLong);
        }
        if !k
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'@' | b'_'))
        {
            return Err(TextError::Malformed("a key outside the RFC character set"));
        }
        let key = String::from_utf8_lossy(k).into_owned();
        let value = std::str::from_utf8(v)
            .map_err(|_| TextError::Malformed("a value that is not UTF-8"))?
            .to_string();
        if out.iter().any(|(existing, _)| *existing == key) {
            return Err(TextError::Duplicate(key));
        }
        out.push((key, value));
    }
    Ok(out)
}

/// Encode pairs as `key=value\0…`.
pub fn encode<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in pairs {
        out.extend(k.as_ref().as_bytes());
        out.push(b'=');
        out.extend(v.as_ref().as_bytes());
        out.push(0);
    }
    out
}

/// The value of a key, if present.
pub fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The operational parameters a connection runs with once login has negotiated them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub header_digest: bool,
    pub data_digest: bool,
    /// What the peer accepts in one PDU's data segment (it declared this).
    pub peer_max_recv_data_segment: u32,
    /// What we accept, as we declared it.
    pub our_max_recv_data_segment: u32,
    pub max_burst: u32,
    pub first_burst: u32,
    pub initial_r2t: bool,
    pub immediate_data: bool,
    pub max_outstanding_r2t: u32,
    pub data_pdu_in_order: bool,
    pub data_sequence_in_order: bool,
    pub default_time2wait: u32,
    pub default_time2retain: u32,
    pub error_recovery_level: u32,
    pub max_connections: u32,
}

impl Default for Params {
    /// The RFC 7143 §13 defaults, which hold for any key the exchange did not mention.
    fn default() -> Self {
        Self {
            header_digest: false,
            data_digest: false,
            peer_max_recv_data_segment: 8192,
            our_max_recv_data_segment: 8192,
            max_burst: 262_144,
            first_burst: 65_536,
            initial_r2t: true,
            immediate_data: true,
            max_outstanding_r2t: 1,
            data_pdu_in_order: true,
            data_sequence_in_order: true,
            default_time2wait: 2,
            default_time2retain: 20,
            error_recovery_level: 0,
            max_connections: 1,
        }
    }
}

/// What this side supports for the digests, in its order of preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestPreference {
    /// Accept CRC32C or None, choosing whichever the initiator lists first.
    Either,
    /// CRC32C only.
    Crc32c,
    /// None only.
    None,
}

impl DigestPreference {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "either" | "any" | "crc32c,none" | "none,crc32c" => Some(Self::Either),
            "crc32c" => Some(Self::Crc32c),
            "none" => Some(Self::None),
            _ => None,
        }
    }
    fn supports(self, v: &str) -> bool {
        match self {
            Self::Either => v == "CRC32C" || v == "None",
            Self::Crc32c => v == "CRC32C",
            Self::None => v == "None",
        }
    }
    /// The list an initiator offers.
    pub fn offer(self) -> &'static str {
        match self {
            Self::Either => "None,CRC32C",
            Self::Crc32c => "CRC32C",
            Self::None => "None",
        }
    }
}

fn number(v: &str) -> Option<u64> {
    if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        v.parse().ok()
    }
}

fn yes_no(v: &str) -> Option<bool> {
    match v {
        "Yes" => Some(true),
        "No" => Some(false),
        _ => None,
    }
}

fn yn(b: bool) -> String {
    if b { "Yes" } else { "No" }.into()
}

/// What the target is prepared to agree to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetOffer {
    pub digests: DigestPreference,
    /// The target's own InitialR2T (OR'd with the initiator's).
    pub initial_r2t: bool,
    /// The most connections one session may have (MaxConnections; minimum function).
    pub max_connections: u32,
    /// The highest ErrorRecoveryLevel supported (minimum function).
    pub error_recovery_level: u32,
}

impl Default for TargetOffer {
    fn default() -> Self {
        Self {
            digests: DigestPreference::Either,
            initial_r2t: true,
            max_connections: 1,
            error_recovery_level: 0,
        }
    }
}

/// DefaultTime2Retain as this target proposes it (RFC 7143's default): the most it keeps a
/// failed connection's tasks for reassignment, after Time2Wait.
pub const OUR_TIME2RETAIN: u32 = 20;
/// DefaultTime2Wait as this target proposes it (the RFC default).
pub const OUR_TIME2WAIT: u32 = 2;

/// Keys only the leading login of a session negotiates (RFC 7143 §13, "LO"). A later
/// connection of the same session is answered with the session's value.
pub const LEADING_ONLY: &[&str] = &[
    "MaxConnections",
    "InitialR2T",
    "ImmediateData",
    "MaxBurstLength",
    "FirstBurstLength",
    "DefaultTime2Wait",
    "DefaultTime2Retain",
    "MaxOutstandingR2T",
    "DataPDUInOrder",
    "DataSequenceInOrder",
    "ErrorRecoveryLevel",
];

/// The value a session already runs with for a leading-only key.
pub fn session_value(p: &Params, key: &str) -> Option<String> {
    Some(match key {
        "MaxConnections" => p.max_connections.to_string(),
        "InitialR2T" => yn(p.initial_r2t),
        "ImmediateData" => yn(p.immediate_data),
        "MaxBurstLength" => p.max_burst.to_string(),
        "FirstBurstLength" => p.first_burst.to_string(),
        "DefaultTime2Wait" => p.default_time2wait.to_string(),
        "DefaultTime2Retain" => p.default_time2retain.to_string(),
        "MaxOutstandingR2T" => p.max_outstanding_r2t.to_string(),
        "DataPDUInOrder" => yn(p.data_pdu_in_order),
        "DataSequenceInOrder" => yn(p.data_sequence_in_order),
        "ErrorRecoveryLevel" => p.error_recovery_level.to_string(),
        _ => return None,
    })
}

/// The target's answer to one operational key an initiator proposed, applying the result to
/// `p`. `None` means the key is not an operational one (the caller deals with it); an answer
/// of `Reject` leaves the parameter at its default.
pub fn negotiate_as_target(
    p: &mut Params,
    key: &str,
    value: &str,
    offer: &TargetOffer,
) -> Option<String> {
    let digests = offer.digests;
    let target_initial_r2t = offer.initial_r2t;
    let reject = || Some("Reject".to_string());
    let clamp = |v: &str, lo: u64, hi: u64| number(v).filter(|n| (lo..=hi).contains(n));
    match key {
        "HeaderDigest" | "DataDigest" => {
            let chosen = value.split(',').find(|v| digests.supports(v));
            match chosen {
                Some(c) => {
                    let on = c == "CRC32C";
                    if key == "HeaderDigest" {
                        p.header_digest = on;
                    } else {
                        p.data_digest = on;
                    }
                    Some(c.to_string())
                }
                None => reject(),
            }
        }
        "MaxConnections" => clamp(value, 1, 65535).map_or_else(reject, |n| {
            p.max_connections = (n as u32).min(offer.max_connections.max(1));
            Some(p.max_connections.to_string())
        }),
        "InitialR2T" => yes_no(value).map_or_else(reject, |v| {
            // OR: unsolicited data flows only when neither side requires an R2T first.
            p.initial_r2t = v || target_initial_r2t;
            Some(yn(p.initial_r2t))
        }),
        "ImmediateData" => yes_no(value).map_or_else(reject, |v| {
            // AND: we accept immediate data, so the initiator decides.
            p.immediate_data = v;
            Some(yn(v))
        }),
        "MaxRecvDataSegmentLength" => clamp(value, 512, (1 << 24) - 1).map_or_else(reject, |n| {
            // Declarative: the initiator says what it accepts; we answer with ours.
            p.peer_max_recv_data_segment = n as u32;
            Some(p.our_max_recv_data_segment.to_string())
        }),
        "MaxBurstLength" => clamp(value, 512, (1 << 24) - 1).map_or_else(reject, |n| {
            p.max_burst = (n as u32).min(OUR_MAX_BURST);
            if p.first_burst > p.max_burst {
                p.first_burst = p.max_burst;
            }
            Some(p.max_burst.to_string())
        }),
        "FirstBurstLength" => clamp(value, 512, (1 << 24) - 1).map_or_else(reject, |n| {
            p.first_burst = (n as u32).min(OUR_FIRST_BURST).min(p.max_burst);
            Some(p.first_burst.to_string())
        }),
        "DefaultTime2Wait" => clamp(value, 0, 3600).map_or_else(reject, |n| {
            // Maximum function.
            p.default_time2wait = (n as u32).max(OUR_TIME2WAIT);
            Some(p.default_time2wait.to_string())
        }),
        "DefaultTime2Retain" => clamp(value, 0, 3600).map_or_else(reject, |n| {
            // Minimum function: at most what this target keeps.
            p.default_time2retain = (n as u32).min(OUR_TIME2RETAIN);
            Some(p.default_time2retain.to_string())
        }),
        "MaxOutstandingR2T" => clamp(value, 1, 65535).map_or_else(reject, |_| {
            p.max_outstanding_r2t = 1;
            Some("1".into())
        }),
        "DataPDUInOrder" => yes_no(value).map_or_else(reject, |_| {
            // OR with our Yes.
            p.data_pdu_in_order = true;
            Some("Yes".into())
        }),
        "DataSequenceInOrder" => yes_no(value).map_or_else(reject, |_| {
            p.data_sequence_in_order = true;
            Some("Yes".into())
        }),
        "ErrorRecoveryLevel" => clamp(value, 0, 2).map_or_else(reject, |n| {
            p.error_recovery_level = (n as u32).min(offer.error_recovery_level.min(2));
            Some(p.error_recovery_level.to_string())
        }),
        "IFMarker" | "OFMarker" => yes_no(value).map_or_else(reject, |_| Some("No".into())),
        "OFMarkInt" | "IFMarkInt" => Some("Irrelevant".into()),
        _ => None,
    }
}

/// The initiator applying a target's answer to a key it proposed. `Err` names a value outside
/// what was offered.
pub fn apply_as_initiator(p: &mut Params, key: &str, value: &str) -> Result<(), String> {
    let num = |lo: u64, hi: u64| {
        number(value)
            .filter(|n| (lo..=hi).contains(n))
            .ok_or_else(|| format!("{key}={value} is out of range"))
    };
    match key {
        "HeaderDigest" | "DataDigest" => {
            let on = match value {
                "CRC32C" => true,
                "None" => false,
                _ => return Err(format!("{key}={value} is neither CRC32C nor None")),
            };
            if key == "HeaderDigest" {
                p.header_digest = on;
            } else {
                p.data_digest = on;
            }
        }
        "MaxRecvDataSegmentLength" => {
            p.peer_max_recv_data_segment = num(512, (1 << 24) - 1)? as u32
        }
        "MaxBurstLength" => p.max_burst = num(512, (1 << 24) - 1)? as u32,
        "FirstBurstLength" => p.first_burst = num(512, (1 << 24) - 1)? as u32,
        "InitialR2T" => p.initial_r2t = yes_no(value).ok_or("InitialR2T is Yes or No")?,
        "ImmediateData" => p.immediate_data = yes_no(value).ok_or("ImmediateData is Yes or No")?,
        "MaxOutstandingR2T" => p.max_outstanding_r2t = num(1, 65535)? as u32,
        "MaxConnections" => p.max_connections = num(1, 65535)? as u32,
        "ErrorRecoveryLevel" => p.error_recovery_level = num(0, 2)? as u32,
        "DefaultTime2Wait" => p.default_time2wait = num(0, 3600)? as u32,
        "DefaultTime2Retain" => p.default_time2retain = num(0, 3600)? as u32,
        "DataPDUInOrder" => p.data_pdu_in_order = yes_no(value).unwrap_or(true),
        "DataSequenceInOrder" => p.data_sequence_in_order = yes_no(value).unwrap_or(true),
        _ => {}
    }
    if p.first_burst > p.max_burst {
        return Err("FirstBurstLength is larger than MaxBurstLength".into());
    }
    Ok(())
}

/// The operational keys an initiator proposes, in the order Linux's open-iscsi sends them.
pub fn initiator_offer(digests: DigestPreference, our_mrdsl: u32) -> Vec<(String, String)> {
    initiator_offer_with(digests, our_mrdsl, 0, 1)
}

/// [`initiator_offer`] proposing an ErrorRecoveryLevel and MaxConnections.
pub fn initiator_offer_with(
    digests: DigestPreference,
    our_mrdsl: u32,
    error_recovery_level: u32,
    max_connections: u32,
) -> Vec<(String, String)> {
    let retain = if error_recovery_level >= 2 {
        OUR_TIME2RETAIN
    } else {
        0
    };
    [
        ("HeaderDigest", digests.offer().to_string()),
        ("DataDigest", digests.offer().to_string()),
        (
            "ErrorRecoveryLevel",
            error_recovery_level.min(2).to_string(),
        ),
        ("InitialR2T", "No".into()),
        ("ImmediateData", "Yes".into()),
        ("MaxBurstLength", OUR_MAX_BURST.to_string()),
        ("FirstBurstLength", OUR_FIRST_BURST.to_string()),
        ("MaxOutstandingR2T", "1".into()),
        (
            "MaxConnections",
            max_connections.clamp(1, 65535).to_string(),
        ),
        ("DataPDUInOrder", "Yes".into()),
        ("DataSequenceInOrder", "Yes".into()),
        ("DefaultTime2Wait", OUR_TIME2WAIT.to_string()),
        ("DefaultTime2Retain", retain.to_string()),
        ("MaxRecvDataSegmentLength", our_mrdsl.to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}
