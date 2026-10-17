//! The Semtech UDP packet-forwarder protocol (`PROTOCOL.TXT` of `packet_forwarder`, versions 1
//! and 2): a 4-byte header (version, random token, identifier), the gateway EUI on the
//! gateway's messages, and JSON carrying `rxpk`, `stat`, `txpk` and `txpk_ack`.
//!
//! Every bound is checked before the JSON is parsed: datagram size, nesting depth (scanned
//! iteratively, so a deep document is refused without recursing into it), the number of
//! `rxpk`, and the base64 length of each frame.
use super::mac::{self, Eui};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PUSH_DATA: u8 = 0x00;
pub const PUSH_ACK: u8 = 0x01;
pub const PULL_DATA: u8 = 0x02;
pub const PULL_RESP: u8 = 0x03;
pub const PULL_ACK: u8 = 0x04;
pub const TX_ACK: u8 = 0x05;

/// The version NetGet writes when it starts an exchange; replies echo the peer's.
pub const PROTOCOL_VERSION: u8 = 2;

/// The largest datagram either side accepts. `lora_pkt_fwd` sends at most
/// `540 * NB_PKT_MAX + 30 + STATUS_SIZE` (≈ 4.6 KiB) upstream.
pub const MAX_DATAGRAM: usize = 8192;
/// `rxpk` entries one PUSH_DATA may carry (`lora_pkt_fwd`'s NB_PKT_MAX is 8).
pub const MAX_RXPK: usize = 16;
/// JSON nesting allowed: `{"rxpk":[{...}]}` is depth 3; a few levels of slack.
pub const MAX_JSON_DEPTH: usize = 8;
/// base64 of the largest PHYPayload.
pub const MAX_DATA_B64: usize = mac::MAX_PHY_PAYLOAD.div_ceil(3) * 4;

pub fn identifier_name(id: u8) -> &'static str {
    match id {
        PUSH_DATA => "PUSH_DATA",
        PUSH_ACK => "PUSH_ACK",
        PULL_DATA => "PULL_DATA",
        PULL_RESP => "PULL_RESP",
        PULL_ACK => "PULL_ACK",
        TX_ACK => "TX_ACK",
        _ => "unknown",
    }
}

/// How deep `json` nests, without recursing; refuses past `max`.
pub fn check_json_depth(json: &[u8], max: usize) -> Result<()> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in json {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                ensure!(depth <= max, "JSON nests deeper than {max} levels");
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// One received frame as a gateway reports it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Rxpk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmms: Option<u64>,
    /// The concentrator's microsecond counter at the end of the frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmst: Option<u32>,
    pub freq: f64,
    #[serde(default)]
    pub chan: u8,
    #[serde(default)]
    pub rfch: u8,
    /// 1 CRC OK, -1 CRC bad, 0 no CRC.
    #[serde(default = "crc_ok")]
    pub stat: i8,
    pub modu: String,
    /// `"SF7BW125"` for LoRa; a bit rate number for FSK.
    pub datr: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codr: Option<String>,
    #[serde(default)]
    pub rssi: i32,
    #[serde(default)]
    pub lsnr: f64,
    pub size: u32,
    pub data: String,
}

fn crc_ok() -> i8 {
    1
}

/// A gateway's status report. Every field is optional on the wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Stat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lati: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alti: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rxnb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rxok: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rxfw: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ackr: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dwnb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txnb: Option<u32>,
}

/// A frame for the gateway to transmit.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Txpk {
    /// Send immediately, ignoring `tmst`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub imme: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmms: Option<u64>,
    pub freq: f64,
    #[serde(default)]
    pub rfch: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub powe: Option<i32>,
    pub modu: String,
    pub datr: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codr: Option<String>,
    /// Inverted polarity: true for every LoRaWAN downlink.
    #[serde(default)]
    pub ipol: bool,
    pub size: u32,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ncrc: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct PushBody {
    #[serde(default)]
    rxpk: Vec<Rxpk>,
    stat: Option<Stat>,
}

#[derive(Debug, Deserialize)]
struct PullRespBody {
    txpk: Txpk,
}

#[derive(Debug, Default, Deserialize)]
struct TxAckInner {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TxAckBody {
    #[serde(default)]
    txpk_ack: Option<TxAckInner>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    PushData {
        version: u8,
        token: u16,
        gateway: Eui,
        rxpk: Vec<Rxpk>,
        stat: Option<Stat>,
    },
    PushAck {
        version: u8,
        token: u16,
    },
    PullData {
        version: u8,
        token: u16,
        gateway: Eui,
    },
    PullResp {
        version: u8,
        token: u16,
        txpk: Txpk,
    },
    PullAck {
        version: u8,
        token: u16,
    },
    TxAck {
        version: u8,
        token: u16,
        gateway: Eui,
        /// `None` or `"NONE"` is success.
        error: Option<String>,
    },
}

fn gateway_of(d: &[u8]) -> Result<Eui> {
    let mut g = [0u8; 8];
    g.copy_from_slice(
        d.get(4..12)
            .context("datagram shorter than its gateway EUI")?,
    );
    Ok(g)
}

fn json_body(d: &[u8]) -> Result<&[u8]> {
    check_json_depth(d, MAX_JSON_DEPTH)?;
    Ok(d)
}

/// Parse one datagram, enforcing every bound before parsing its JSON.
pub fn parse(d: &[u8]) -> Result<Packet> {
    ensure!(
        d.len() <= MAX_DATAGRAM,
        "datagram of {} bytes exceeds {MAX_DATAGRAM}",
        d.len()
    );
    ensure!(d.len() >= 4, "datagram shorter than the 4-byte header");
    let version = d[0];
    ensure!(
        version == 1 || version == 2,
        "protocol version {version} is not 1 or 2"
    );
    let token = u16::from_be_bytes([d[1], d[2]]);
    Ok(match d[3] {
        PUSH_DATA => {
            let gateway = gateway_of(d)?;
            let body: PushBody = serde_json::from_slice(json_body(&d[12..])?)
                .context("PUSH_DATA JSON is not an rxpk/stat object")?;
            ensure!(
                body.rxpk.len() <= MAX_RXPK,
                "{} rxpk in one PUSH_DATA exceeds {MAX_RXPK}",
                body.rxpk.len()
            );
            for r in &body.rxpk {
                ensure!(
                    r.data.len() <= MAX_DATA_B64,
                    "an rxpk's data exceeds a 255-byte PHYPayload"
                );
            }
            Packet::PushData {
                version,
                token,
                gateway,
                rxpk: body.rxpk,
                stat: body.stat,
            }
        }
        PUSH_ACK => Packet::PushAck { version, token },
        PULL_DATA => Packet::PullData {
            version,
            token,
            gateway: gateway_of(d)?,
        },
        PULL_RESP => {
            let body: PullRespBody = serde_json::from_slice(json_body(&d[4..])?)
                .context("PULL_RESP JSON is not a txpk object")?;
            ensure!(
                body.txpk.data.len() <= MAX_DATA_B64,
                "txpk data exceeds a 255-byte PHYPayload"
            );
            Packet::PullResp {
                version,
                token,
                txpk: body.txpk,
            }
        }
        PULL_ACK => Packet::PullAck { version, token },
        TX_ACK => {
            let gateway = gateway_of(d).unwrap_or([0; 8]);
            let rest = d.get(12..).unwrap_or_default();
            // Version 1 TX_ACKs and successful version 2 ones may carry no JSON at all.
            let trimmed: Vec<u8> = rest.iter().copied().filter(|b| *b != 0).collect();
            let error = if trimmed.iter().all(u8::is_ascii_whitespace) {
                None
            } else {
                let body: TxAckBody = serde_json::from_slice(json_body(&trimmed)?)
                    .context("TX_ACK JSON is not a txpk_ack object")?;
                body.txpk_ack.and_then(|a| a.error)
            };
            Packet::TxAck {
                version,
                token,
                gateway,
                error,
            }
        }
        other => bail!("identifier {other:#04x} is not a packet-forwarder message"),
    })
}

fn header(version: u8, token: u16, id: u8) -> Vec<u8> {
    let t = token.to_be_bytes();
    vec![version, t[0], t[1], id]
}

pub fn encode(p: &Packet) -> Result<Vec<u8>> {
    let out = match p {
        Packet::PushData {
            version,
            token,
            gateway,
            rxpk,
            stat,
        } => {
            let mut b = header(*version, *token, PUSH_DATA);
            b.extend(gateway);
            let mut body = serde_json::Map::new();
            if !rxpk.is_empty() {
                body.insert("rxpk".into(), serde_json::to_value(rxpk)?);
            }
            if let Some(s) = stat {
                body.insert("stat".into(), serde_json::to_value(s)?);
            }
            b.extend(serde_json::to_vec(&Value::Object(body))?);
            b
        }
        Packet::PushAck { version, token } => header(*version, *token, PUSH_ACK),
        Packet::PullData {
            version,
            token,
            gateway,
        } => {
            let mut b = header(*version, *token, PULL_DATA);
            b.extend(gateway);
            b
        }
        Packet::PullResp {
            version,
            token,
            txpk,
        } => {
            let mut b = header(*version, *token, PULL_RESP);
            b.extend(serde_json::to_vec(&serde_json::json!({ "txpk": txpk }))?);
            b
        }
        Packet::PullAck { version, token } => header(*version, *token, PULL_ACK),
        Packet::TxAck {
            version,
            token,
            gateway,
            error,
        } => {
            let mut b = header(*version, *token, TX_ACK);
            b.extend(gateway);
            let e = error.as_deref().unwrap_or("NONE");
            b.extend(serde_json::to_vec(
                &serde_json::json!({"txpk_ack": {"error": e}}),
            )?);
            b
        }
    };
    ensure!(out.len() <= MAX_DATAGRAM, "datagram exceeds {MAX_DATAGRAM}");
    Ok(out)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len() <= MAX_DATA_B64, "frame data exceeds 255 bytes");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim_end_matches('='))
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('='))
        })
        .context("frame data is not base64")?;
    ensure!(
        bytes.len() <= mac::MAX_PHY_PAYLOAD,
        "frame data exceeds 255 bytes"
    );
    Ok(bytes)
}

pub fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The data rate of a LoRa rxpk/txpk as an EU868 DR index.
pub fn lora_data_rate(modu: &str, datr: &Value) -> Result<u8> {
    ensure!(
        modu.eq_ignore_ascii_case("LORA"),
        "modulation {modu} is not LoRa"
    );
    super::region::data_rate_index(datr.as_str().context("a LoRa datr is a string")?)
}

/// The descriptive names of the TX_ACK error codes (PROTOCOL.TXT §6).
pub const TX_ACK_ERRORS: &[&str] = &[
    "NONE",
    "TOO_LATE",
    "TOO_EARLY",
    "COLLISION_PACKET",
    "COLLISION_BEACON",
    "TX_FREQ",
    "TX_POWER",
    "GPS_UNLOCKED",
];
