//! SNMP notifications, both ways: traps (v1 Trap-PDU, v2c SNMPv2-Trap) and v2c informs.
//!
//! **Received** on the agent's socket, a notification is decoded here into the
//! `snmp_notification` event — kind, version, community, the v2 `sysUpTime.0` and
//! `snmpTrapOID.0` (or v1's enterprise, agent address, generic and specific trap and
//! timestamp), and every variable binding typed — and an inform is acknowledged with a
//! Response echoing its request-id and bindings only when the handler says so.
//!
//! **Sent** by `send_trap`: a v1 or v2c trap, or a v2c inform that is retried until a
//! Response with its request-id arrives. Encoding and decoding are rasn's; the values the
//! model writes and reads are `{oid, type, value}`.
use anyhow::{bail, ensure, Context, Result};
use rasn::ber;
use rasn::types::{FixedOctetString, Integer, ObjectIdentifier, OctetString};
use rasn_smi::{v1 as smi1, v2 as smi2};
use rasn_snmp::{v1, v2, v2c};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";
pub const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";
/// The default trap port (RFC 3417 §3).
pub const TRAP_PORT: u16 = 162;
/// Variable bindings a sent notification may carry.
pub const MAX_VARIABLES: usize = 64;
/// How long an inform waits for its Response, and how many times it is sent.
pub const INFORM_TIMEOUT: Duration = Duration::from_secs(2);
pub const INFORM_ATTEMPTS: usize = 3;

/// A notification that arrived.
pub struct Received {
    pub kind: &'static str,
    /// The `snmp_notification` event's data (without `client_ip`).
    pub data: Value,
    /// For an inform: the Response that acknowledges it.
    pub acknowledgement: Option<Vec<u8>>,
}

fn integer(i: &Integer) -> i64 {
    match i {
        Integer::Primitive(v) => *v as i64,
        Integer::Variable(big) => big.to_string().parse().unwrap_or(0),
    }
}

fn octets(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) if !crate::utils::sanitize::has_controls(s) => {
            json!({"type": "string", "value": s})
        }
        _ => json!({"type": "string", "encoding": "hex", "value": hex::encode(bytes)}),
    }
}

fn ipv4(a: &smi1::IpAddress) -> String {
    let b: &[u8] = a.0.as_ref();
    Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
}

fn v2_value(v: &v2::VarBindValue) -> Value {
    use smi2::{ApplicationSyntax as A, ObjectSyntax as O, SimpleSyntax as S};
    match v {
        v2::VarBindValue::Value(O::Simple(S::Integer(i))) => {
            json!({"type": "integer", "value": integer(i)})
        }
        v2::VarBindValue::Value(O::Simple(S::String(s))) => octets(s),
        v2::VarBindValue::Value(O::Simple(S::ObjectId(o))) => {
            json!({"type": "oid", "value": o.to_string()})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::Address(a))) => {
            json!({"type": "ipaddress", "value": ipv4(a)})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::Counter(c))) => {
            json!({"type": "counter", "value": c.0})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::Ticks(t))) => {
            json!({"type": "timeticks", "value": t.0})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::Unsigned(g))) => {
            json!({"type": "gauge", "value": g.0})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::BigCounter(c))) => {
            json!({"type": "counter64", "value": c.0})
        }
        v2::VarBindValue::Value(O::ApplicationWide(A::Arbitrary(o))) => {
            json!({"type": "opaque", "encoding": "hex", "value": hex::encode(o.as_ref())})
        }
        v2::VarBindValue::Unspecified => json!({"type": "null", "value": null}),
        v2::VarBindValue::NoSuchObject => json!({"type": "noSuchObject", "value": null}),
        v2::VarBindValue::NoSuchInstance => json!({"type": "noSuchInstance", "value": null}),
        v2::VarBindValue::EndOfMibView => json!({"type": "endOfMibView", "value": null}),
    }
}

fn v1_value(v: &smi1::ObjectSyntax) -> Value {
    use smi1::{ApplicationSyntax as A, NetworkAddress as N, ObjectSyntax as O, SimpleSyntax as S};
    match v {
        O::Simple(S::Number(i)) => json!({"type": "integer", "value": integer(i)}),
        O::Simple(S::String(s)) => octets(s),
        O::Simple(S::Object(o)) => json!({"type": "oid", "value": o.to_string()}),
        O::Simple(S::Empty) => json!({"type": "null", "value": null}),
        O::ApplicationWide(A::Address(N::Internet(a))) => {
            json!({"type": "ipaddress", "value": ipv4(a)})
        }
        O::ApplicationWide(A::Counter(c)) => json!({"type": "counter", "value": c.0}),
        O::ApplicationWide(A::Gauge(g)) => json!({"type": "gauge", "value": g.0}),
        O::ApplicationWide(A::Ticks(t)) => json!({"type": "timeticks", "value": t.0}),
        O::ApplicationWide(A::Arbitrary(o)) => {
            json!({"type": "opaque", "encoding": "hex", "value": hex::encode(o.as_ref())})
        }
    }
}

fn binding(oid: String, mut typed: Value) -> Value {
    typed["oid"] = json!(oid);
    typed
}

/// Decode a notification; `None` for any other datagram (requests go the usual way).
pub fn parse(data: &[u8]) -> Option<Received> {
    // Screened here as well as by the receive loop, so no caller reaches `rasn` without it.
    if super::check_ber_structure(data, super::MAX_BER_DEPTH).is_err() {
        return None;
    }
    if let Ok(msg) = ber::decode::<v2c::Message<v2::Pdus>>(data) {
        let (kind, pdu) = match &msg.data {
            v2::Pdus::Trap(t) => ("trap", &t.0),
            v2::Pdus::InformRequest(i) => ("inform", &i.0),
            _ => return None,
        };
        let mut variables = Vec::new();
        let (mut uptime, mut trap_oid) = (Value::Null, Value::Null);
        for vb in &pdu.variable_bindings {
            let oid = vb.name.to_string();
            let typed = v2_value(&vb.value);
            if oid == SYS_UPTIME_OID {
                uptime = typed["value"].clone();
            } else if oid == SNMP_TRAP_OID {
                trap_oid = typed["value"].clone();
            } else {
                variables.push(binding(oid, typed));
            }
        }
        let acknowledgement = (kind == "inform")
            .then(|| {
                ber::encode(&v2c::Message {
                    version: msg.version.clone(),
                    community: msg.community.clone(),
                    data: v2::Pdus::Response(v2::Response(v2::Pdu {
                        request_id: pdu.request_id,
                        error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                        error_index: 0,
                        variable_bindings: pdu.variable_bindings.clone(),
                    })),
                })
                .ok()
            })
            .flatten();
        return Some(Received {
            kind,
            data: json!({
                "kind": kind, "version": "v2c",
                "community": String::from_utf8_lossy(&msg.community),
                "request_id": pdu.request_id, "uptime": uptime, "trap_oid": trap_oid,
                "variables": variables,
            }),
            acknowledgement,
        });
    }
    let msg = ber::decode::<v1::Message<v1::Pdus>>(data).ok()?;
    let v1::Pdus::Trap(trap) = &msg.data else {
        return None;
    };
    let smi1::NetworkAddress::Internet(agent) = &trap.agent_addr;
    Some(Received {
        kind: "trap",
        data: json!({
            "kind": "trap", "version": "v1",
            "community": String::from_utf8_lossy(&msg.community),
            "enterprise": trap.enterprise.to_string(),
            "agent_addr": ipv4(agent),
            "generic_trap": integer(&trap.generic_trap),
            "specific_trap": integer(&trap.specific_trap),
            "uptime": trap.time_stamp.0,
            "variables": trap.variable_bindings.iter()
                .map(|vb| binding(vb.name.to_string(), v1_value(&vb.value)))
                .collect::<Vec<_>>(),
        }),
        acknowledgement: None,
    })
}

pub fn oid(text: &str) -> Result<ObjectIdentifier> {
    let arcs: Vec<u32> = text
        .trim_start_matches('.')
        .split('.')
        .map(|a| a.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("{text:?} is not a dotted-decimal OID"))?;
    ObjectIdentifier::new(arcs).with_context(|| format!("{text:?} is not a valid OID"))
}

fn u32_of(v: &Value, what: &str) -> Result<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .with_context(|| format!("{what} is an unsigned 32-bit number"))
}

fn ip_of(v: &Value) -> Result<smi1::IpAddress> {
    let ip: Ipv4Addr = v
        .as_str()
        .context("an ipaddress value is a dotted IPv4 address")?
        .parse()
        .context("an ipaddress value is a dotted IPv4 address")?;
    Ok(smi1::IpAddress(FixedOctetString::from(ip.octets())))
}

fn string_of(v: &Value, encoding: Option<&str>) -> Result<OctetString> {
    let s = v.as_str().context("a string value is text")?;
    Ok(match encoding {
        Some("hex") => OctetString::from(hex::decode(s).context("value is not hex")?),
        None | Some("utf8") => OctetString::from(s.as_bytes().to_vec()),
        Some(other) => bail!("encoding is utf8 or hex, not {other:?}"),
    })
}

/// One `{oid, type, value}` as a v2 binding.
fn v2_binding(var: &Value) -> Result<v2::VarBind> {
    use smi2::{ApplicationSyntax as A, ObjectSyntax as O, SimpleSyntax as S};
    let name = oid(var["oid"].as_str().context("each variable has an oid")?)?;
    let value = &var["value"];
    let syntax = match var["type"].as_str().unwrap_or("string") {
        "integer" => O::Simple(S::Integer(Integer::from(
            value.as_i64().context("an integer value is a number")?,
        ))),
        "string" => O::Simple(S::String(string_of(value, var["encoding"].as_str())?)),
        "oid" => O::Simple(S::ObjectId(oid(value.as_str().context("an oid value is text")?)?)),
        "ipaddress" => O::ApplicationWide(A::Address(ip_of(value)?)),
        "counter" => O::ApplicationWide(A::Counter(smi1::Counter(u32_of(value, "a counter")?))),
        "gauge" => O::ApplicationWide(A::Unsigned(smi1::Gauge(u32_of(value, "a gauge")?))),
        "timeticks" => O::ApplicationWide(A::Ticks(smi1::TimeTicks(u32_of(value, "timeticks")?))),
        "counter64" => O::ApplicationWide(A::BigCounter(smi2::Counter64(
            value.as_u64().context("a counter64 is an unsigned number")?,
        ))),
        "null" => {
            return Ok(v2::VarBind {
                name,
                value: v2::VarBindValue::Unspecified,
            })
        }
        other => bail!("variable type {other:?} is not one of integer, string, oid, ipaddress, counter, gauge, timeticks, counter64, null"),
    };
    Ok(v2::VarBind {
        name,
        value: v2::VarBindValue::Value(syntax),
    })
}

fn v1_binding(var: &Value) -> Result<v1::VarBind> {
    use smi1::{ApplicationSyntax as A, NetworkAddress as N, ObjectSyntax as O, SimpleSyntax as S};
    let name = oid(var["oid"].as_str().context("each variable has an oid")?)?;
    let value = &var["value"];
    let syntax = match var["type"].as_str().unwrap_or("string") {
        "integer" => O::Simple(S::Number(Integer::from(
            value.as_i64().context("an integer value is a number")?,
        ))),
        "string" => O::Simple(S::String(string_of(value, var["encoding"].as_str())?)),
        "oid" => O::Simple(S::Object(oid(value.as_str().context("an oid value is text")?)?)),
        "null" => O::Simple(S::Empty),
        "ipaddress" => O::ApplicationWide(A::Address(N::Internet(ip_of(value)?))),
        "counter" => O::ApplicationWide(A::Counter(smi1::Counter(u32_of(value, "a counter")?))),
        "gauge" => O::ApplicationWide(A::Gauge(smi1::Gauge(u32_of(value, "a gauge")?))),
        "timeticks" => O::ApplicationWide(A::Ticks(smi1::TimeTicks(u32_of(value, "timeticks")?))),
        other => bail!("variable type {other:?} is not one SNMPv1 carries (integer, string, oid, null, ipaddress, counter, gauge, timeticks)"),
    };
    Ok(v1::VarBind {
        name,
        value: syntax,
    })
}

/// A notification ready to send.
pub struct Outgoing {
    pub target: String,
    pub inform: bool,
    pub request_id: i32,
    pub packet: Vec<u8>,
}

/// Process uptime in hundredths of a second, the default `sysUpTime.0`.
fn uptime_ticks() -> u32 {
    static START: std::sync::OnceLock<crate::utils::clock::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(crate::utils::clock::Instant::now);
    (start.elapsed().as_millis() / 10) as u32
}

/// Validate and encode a `send_trap` action.
pub fn build(action: &Value) -> Result<Outgoing> {
    let target = action["target"]
        .as_str()
        .context("Missing 'target' (host or host:port; port 162 when omitted)")?;
    ensure!(
        !target.is_empty() && target.len() <= 255 && !target.contains(char::is_whitespace),
        "target is host or host:port"
    );
    let target = if target.parse::<SocketAddr>().is_ok()
        || target
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        target.to_string()
    } else if let Ok(ip) = target.trim_matches(['[', ']']).parse::<IpAddr>() {
        SocketAddr::new(ip, TRAP_PORT).to_string()
    } else {
        format!("{target}:{TRAP_PORT}")
    };
    let version = action["version"].as_str().unwrap_or("v2c");
    let inform = action["inform"].as_bool().unwrap_or(false);
    let community = action["community"].as_str().unwrap_or("public");
    ensure!(community.len() <= 255, "community is at most 255 bytes");
    let variables = match action.get("variables") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => v
            .as_array()
            .context("variables is an array of {oid, type, value}")?
            .clone(),
    };
    ensure!(
        variables.len() <= MAX_VARIABLES,
        "at most {MAX_VARIABLES} variables"
    );
    let uptime = match action.get("uptime") {
        None | Some(Value::Null) => uptime_ticks(),
        Some(v) => u32_of(v, "uptime (timeticks)")?,
    };
    let request_id = (rand::random::<u32>() & 0x7fff_ffff) as i32;
    let packet = match version {
        "v2c" => {
            let trap_oid = oid(action["trap_oid"]
                .as_str()
                .context("a v2c notification names its trap_oid (snmpTrapOID.0), e.g. 1.3.6.1.6.3.1.1.5.3 (linkDown)")?)?;
            let mut bindings = vec![
                v2::VarBind {
                    name: oid(SYS_UPTIME_OID)?,
                    value: v2::VarBindValue::Value(smi2::ObjectSyntax::ApplicationWide(
                        smi2::ApplicationSyntax::Ticks(smi1::TimeTicks(uptime)),
                    )),
                },
                v2::VarBind {
                    name: oid(SNMP_TRAP_OID)?,
                    value: v2::VarBindValue::Value(smi2::ObjectSyntax::Simple(
                        smi2::SimpleSyntax::ObjectId(trap_oid),
                    )),
                },
            ];
            for var in &variables {
                bindings.push(v2_binding(var)?);
            }
            let pdu = v2::Pdu {
                request_id,
                error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                error_index: 0,
                variable_bindings: bindings,
            };
            ber::encode(&v2c::Message {
                version: Integer::from(1),
                community: OctetString::from(community.as_bytes().to_vec()),
                data: if inform {
                    v2::Pdus::InformRequest(v2::InformRequest(pdu))
                } else {
                    v2::Pdus::Trap(v2::Trap(pdu))
                },
            })
            .map_err(|e| anyhow::anyhow!("encoding the notification: {e}"))?
        }
        "v1" => {
            ensure!(!inform, "an inform is SNMPv2c; SNMPv1 has only traps");
            let generic = action["generic_trap"].as_i64().unwrap_or(6);
            ensure!(
                (0..=6).contains(&generic),
                "generic_trap is 0..=6 (6 = enterpriseSpecific)"
            );
            let bindings = variables
                .iter()
                .map(v1_binding)
                .collect::<Result<Vec<_>>>()?;
            let agent = match action.get("agent_addr") {
                None | Some(Value::Null) => smi1::IpAddress(FixedOctetString::from([0, 0, 0, 0])),
                Some(v) => ip_of(v)?,
            };
            ber::encode(&v1::Message {
                version: Integer::from(0),
                community: OctetString::from(community.as_bytes().to_vec()),
                data: v1::Pdus::Trap(v1::Trap {
                    enterprise: oid(action["enterprise"]
                        .as_str()
                        .unwrap_or("1.3.6.1.4.1.8072.9999"))?,
                    agent_addr: smi1::NetworkAddress::Internet(agent),
                    generic_trap: Integer::from(generic),
                    specific_trap: Integer::from(action["specific_trap"].as_i64().unwrap_or(0)),
                    time_stamp: smi1::TimeTicks(uptime),
                    variable_bindings: bindings,
                }),
            })
            .map_err(|e| anyhow::anyhow!("encoding the trap: {e}"))?
        }
        other => bail!("version is v1 or v2c (SNMPv3 is not implemented), not {other:?}"),
    };
    Ok(Outgoing {
        target,
        inform,
        request_id,
        packet,
    })
}

/// Send a notification. A trap is fire-and-forget; an inform is resent until a Response with
/// its request-id arrives, and the result says whether one did.
pub async fn send(out: &Outgoing) -> Result<Value> {
    let target = tokio::net::lookup_host(&out.target)
        .await?
        .next()
        .with_context(|| format!("{} did not resolve", out.target))?;
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    if !out.inform {
        socket.send_to(&out.packet, target).await?;
        return Ok(json!({"sent": true, "target": target.to_string(), "kind": "trap"}));
    }
    let mut buf = vec![0u8; 65535];
    for attempt in 1..=INFORM_ATTEMPTS {
        socket.send_to(&out.packet, target).await?;
        let deadline = tokio::time::Instant::now() + INFORM_TIMEOUT;
        while let Ok(Ok((n, from))) =
            tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        {
            if from.ip() != target.ip() {
                continue;
            }
            // The acknowledgement is the target's bytes: screened for nesting depth before
            // `rasn`'s unbounded recursion sees them, as every other received datagram is.
            if super::check_ber_structure(&buf[..n], super::MAX_BER_DEPTH).is_err() {
                continue;
            }
            if let Ok(msg) = ber::decode::<v2c::Message<v2::Pdus>>(&buf[..n]) {
                if let v2::Pdus::Response(r) = msg.data {
                    if r.0.request_id == out.request_id {
                        return Ok(
                            json!({"sent": true, "target": target.to_string(), "kind": "inform",
                            "acknowledged": true, "attempts": attempt, "error_status": r.0.error_status}),
                        );
                    }
                }
            }
        }
    }
    Ok(
        json!({"sent": true, "target": target.to_string(), "kind": "inform", "acknowledged": false, "attempts": INFORM_ATTEMPTS}),
    )
}
