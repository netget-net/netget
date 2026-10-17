//! DHCPv6 (RFC 8415) protocol actions.
//!
//! The model answers a client message with one semantic action and NetGet encodes the packet:
//! `send_dhcpv6_advertise` for a SOLICIT, `send_dhcpv6_reply` for everything else (and for a
//! SOLICIT carrying Rapid Commit), or `no_response` for deliberate silence.
//!
//! Nothing here keeps a lease. There is no binding table, no address pool and no memory of a
//! previous exchange: every address, prefix, lifetime and status code in a reply came from the
//! model that answered *this* datagram. See `CLAUDE.md` in this directory for the consequence.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use dhcproto::v6;
use dhcproto::{Encodable, Encoder};
use serde_json::json;
use std::net::Ipv6Addr;
use std::sync::LazyLock;

/// Everything a reply has to echo from the message being answered.
///
/// A DHCPv6 client matches a reply to its request by the 3-byte transaction id and by the
/// Client Identifier option, and discards anything else without a word — so a wrong echo
/// presents as a timeout, never as an error. The IAID of the client's IA_NA / IA_PD is the
/// same kind of value: addresses handed back under a different IAID belong to an identity
/// association the client never asked about, and are ignored.
#[derive(Clone, Debug)]
pub struct Dhcpv6RequestContext {
    /// RFC 8415 §8: the transaction id is **three** octets, not four.
    pub xid: [u8; 3],
    pub msg_type: v6::MessageType,
    /// Raw DUID bytes from option 1. Absent is legal in an INFORMATION-REQUEST.
    pub client_duid: Option<Vec<u8>>,
    /// Raw DUID bytes from option 2 — the server the client addressed, when it named one
    /// (REQUEST, RENEW, RELEASE). Read only by [`Dhcpv6Protocol::server_failure_reply`].
    pub addressed_server_duid: Option<Vec<u8>>,
    /// IAID of the client's IA_NA (option 3), if it sent one.
    pub ia_na_id: Option<u32>,
    /// IAID of the client's IA_PD (option 25), if it asked for a delegated prefix.
    pub ia_pd_id: Option<u32>,
    /// The client asked for the two-message exchange (option 14).
    pub rapid_commit: bool,
}

pub struct Dhcpv6Protocol {
    request_context: std::sync::Arc<std::sync::Mutex<Option<Dhcpv6RequestContext>>>,
}

impl Dhcpv6Protocol {
    pub fn new() -> Self {
        Self {
            request_context: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn set_request_context(&self, context: Dhcpv6RequestContext) {
        if let Ok(mut slot) = self.request_context.lock() {
            *slot = Some(context);
        }
    }
}

impl Dhcpv6Protocol {
    /// The one reply this server builds without the model: a REPLY whose only status is a
    /// top-level Status Code **UnspecFail**, for a message whose answer is a REPLY.
    ///
    /// RFC 8415 §21.13 defines UnspecFail as "failure, reason unspecified", and §18.2.10 as the
    /// server being "unable to process the client's message" — the client may retry, rate-
    /// limited. It asserts nothing about addresses, prefixes or resolvers, which is what makes
    /// it safe to send when the model could not decide. The status message is the fixed
    /// [`crate::utils::WireFailure`] text, never the error.
    ///
    /// Returns `Ok(None)` for a SOLICIT: its answer is an ADVERTISE, and every status an
    /// ADVERTISE could carry is a statement about the lease. The Server Identifier is the one
    /// the client addressed, where it named one, so the client matches the reply to the server
    /// it asked; otherwise the default server DUID.
    pub fn server_failure_reply(
        &self,
        failure: crate::utils::WireFailure,
    ) -> Result<Option<Vec<u8>>> {
        let Some(context) = self
            .request_context
            .lock()
            .map_err(|_| anyhow!("DHCPv6 request context lock was poisoned"))?
            .clone()
        else {
            return Ok(None);
        };
        if context.msg_type == v6::MessageType::Solicit {
            return Ok(None);
        }

        let mut msg = v6::Message::new_with_id(v6::MessageType::Reply, context.xid);
        if let Some(duid) = context.client_duid {
            msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));
        }
        let server_duid = context
            .addressed_server_duid
            .unwrap_or_else(default_server_duid);
        msg.opts_mut().insert(v6::DhcpOption::ServerId(server_duid));
        msg.opts_mut()
            .insert(v6::DhcpOption::StatusCode(v6::StatusCode {
                status: v6::Status::UnspecFail,
                msg: failure.text().to_string(),
            }));

        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        msg.encode(&mut encoder)
            .map_err(|e| anyhow!("Failed to encode the DHCPv6 UnspecFail reply: {e}"))?;
        Ok(Some(buf))
    }
}

impl Default for Dhcpv6Protocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DUID handling
// ============================================================================
//
// A DUID is the only identity DHCPv6 has: there is no chaddr. It is opaque on the wire, but
// it is *not* opaque to a reader — the first two octets name one of four documented shapes —
// so events surface the decoded shape and actions accept the same shape back. Neither side
// ever asks the model to handle a base64 blob.

/// IANA's reserved "example" Private Enterprise Number (RFC 5612 §5). Used for the default
/// server DUID so NetGet never squats on a real organisation's number.
const EXAMPLE_ENTERPRISE_NUMBER: u32 = 32473;

/// DUID-EN carrying the documentation enterprise number and the identifier `netget`.
///
/// Constant on purpose. A client sends its REQUEST to the Server Identifier it saw in the
/// ADVERTISE and checks that the REPLY carries the same one, so the default has to be stable
/// across two separate model calls that share no state. It is a placeholder identity, not a
/// registered one — a deployment should pass `server_duid` explicitly.
fn default_server_duid() -> Vec<u8> {
    let mut duid = Vec::with_capacity(12);
    duid.extend_from_slice(&2u16.to_be_bytes());
    duid.extend_from_slice(&EXAMPLE_ENTERPRISE_NUMBER.to_be_bytes());
    duid.extend_from_slice(b"netget");
    duid
}

/// Render bytes the way DUIDs and link-layer addresses are conventionally written.
fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse hex that may be written with `:`, `-`, `.` or spaces between the bytes.
fn parse_hex_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-' && *c != '.')
        .collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned)
        .to_string();

    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!(
            "Invalid '{field}' {value:?}: expected hex, two digits per byte, e.g. \
             \"00:11:22:33:44:55\""
        ));
    }
    hex::decode(&cleaned)
        .map_err(|e| anyhow!("Invalid '{field}' {value:?}: {e}. Use only the digits 0-9 and a-f"))
}

/// RFC 826 hardware types, for the two DUID forms that carry one.
fn hardware_type_name(htype: u16) -> &'static str {
    match htype {
        1 => "ethernet",
        6 => "ieee802",
        7 => "arcnet",
        11 => "localtalk",
        16 => "atm",
        27 => "eui64",
        32 => "infiniband",
        _ => "unknown",
    }
}

/// Decode a DUID into the structured form the events publish.
///
/// Always includes `type` and `text`; the remaining fields depend on the form. `text` is the
/// canonical colon-hex spelling — the string an operator would recognise as "this client" and
/// the one to match on in a handler.
pub fn describe_duid(raw: &[u8]) -> serde_json::Value {
    let text = colon_hex(raw);

    if raw.len() < 2 {
        return json!({ "type": "unknown", "text": text, "length": raw.len() });
    }
    let duid_type = u16::from_be_bytes([raw[0], raw[1]]);
    let body = &raw[2..];

    match duid_type {
        // DUID-LLT: hardware type, seconds since 2000-01-01 UTC, link-layer address
        1 if body.len() >= 6 => {
            let htype = u16::from_be_bytes([body[0], body[1]]);
            let time = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
            json!({
                "type": "llt",
                "text": text,
                "hardware_type": htype,
                "hardware_type_name": hardware_type_name(htype),
                "time": time,
                "link_layer_address": colon_hex(&body[6..]),
            })
        }
        // DUID-EN: enterprise number, then a vendor-chosen identifier
        2 if body.len() >= 4 => {
            let enterprise = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let id = &body[4..];
            let mut value = json!({
                "type": "en",
                "text": text,
                "enterprise_number": enterprise,
            });
            // The identifier is vendor-defined bytes. Publish it as text only when it really
            // is text; `text` above always carries the exact bytes either way.
            if !id.is_empty() && id.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                value["identifier"] = json!(String::from_utf8_lossy(id));
            }
            value
        }
        // DUID-LL: hardware type, link-layer address
        3 if body.len() >= 2 => {
            let htype = u16::from_be_bytes([body[0], body[1]]);
            json!({
                "type": "ll",
                "text": text,
                "hardware_type": htype,
                "hardware_type_name": hardware_type_name(htype),
                "link_layer_address": colon_hex(&body[2..]),
            })
        }
        // DUID-UUID (RFC 6355)
        4 if body.len() == 16 => {
            let h = hex::encode(body);
            json!({
                "type": "uuid",
                "text": text,
                "uuid": format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]),
            })
        }
        other => json!({
            "type": "unknown",
            "text": text,
            "duid_type_code": other,
        }),
    }
}

/// Encode the structured `server_duid` parameter back into DUID bytes.
///
/// Hand-encoded rather than built with `dhcproto::v6::duid::Duid`, whose `link_layer` and
/// `link_layer_time` constructors take the link-layer address as an `Ipv6Addr` and therefore
/// always write **16** octets. A DUID-LL for Ethernet carries a 6-octet MAC, so those two
/// constructors cannot express the common case. `enterprise` and `uuid` are correct there;
/// all four are done the same way here so the shapes stay side by side.
fn encode_duid(spec: &serde_json::Value) -> Result<Vec<u8>> {
    let obj = spec.as_object().ok_or_else(|| {
        anyhow!(
            "'server_duid' must be an object naming the DUID form, e.g. \
             {{\"type\": \"ll\", \"hardware_type\": 1, \"link_layer_address\": \
             \"00:11:22:33:44:55\"}}, got {spec}"
        )
    })?;

    let form = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("'server_duid' needs a 'type' of \"llt\", \"en\", \"ll\" or \"uuid\"")
        })?
        .to_ascii_lowercase();

    let htype = |default: u16| -> Result<u16> {
        match obj.get("hardware_type") {
            None => Ok(default),
            Some(v) => {
                let n = v.as_u64().ok_or_else(|| {
                    anyhow!("'server_duid.hardware_type' must be a number, e.g. 1 for Ethernet")
                })?;
                u16::try_from(n)
                    .map_err(|_| anyhow!("'server_duid.hardware_type' {n} does not fit in 16 bits"))
            }
        }
    };

    let link_layer_address = || -> Result<Vec<u8>> {
        let s = obj
            .get("link_layer_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "'server_duid' of type \"{form}\" needs 'link_layer_address', e.g. \
                     \"00:11:22:33:44:55\""
                )
            })?;
        parse_hex_bytes(s, "server_duid.link_layer_address")
    };

    let mut out = Vec::new();
    match form.as_str() {
        "llt" | "1" => {
            let time = obj.get("time").and_then(|v| v.as_u64()).unwrap_or(0);
            let time = u32::try_from(time).map_err(|_| {
                anyhow!("'server_duid.time' {time} does not fit in the 32-bit DUID-LLT time field")
            })?;
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&htype(1)?.to_be_bytes());
            out.extend_from_slice(&time.to_be_bytes());
            out.extend_from_slice(&link_layer_address()?);
        }
        "en" | "2" => {
            let enterprise = obj
                .get("enterprise_number")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| {
                    anyhow!(
                        "'server_duid' of type \"en\" needs 'enterprise_number' (an IANA Private \
                         Enterprise Number; 32473 is reserved for examples)"
                    )
                })?;
            let enterprise = u32::try_from(enterprise).map_err(|_| {
                anyhow!("'server_duid.enterprise_number' {enterprise} does not fit in 32 bits")
            })?;
            let identifier = obj
                .get("identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("netget");
            out.extend_from_slice(&2u16.to_be_bytes());
            out.extend_from_slice(&enterprise.to_be_bytes());
            out.extend_from_slice(identifier.as_bytes());
        }
        "ll" | "3" => {
            out.extend_from_slice(&3u16.to_be_bytes());
            out.extend_from_slice(&htype(1)?.to_be_bytes());
            out.extend_from_slice(&link_layer_address()?);
        }
        "uuid" | "4" => {
            let s = obj
                .get("uuid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("'server_duid' of type \"uuid\" needs 'uuid'"))?;
            let bytes = parse_hex_bytes(s, "server_duid.uuid")?;
            if bytes.len() != 16 {
                return Err(anyhow!(
                    "'server_duid.uuid' decodes to {} bytes; RFC 6355 requires exactly 16",
                    bytes.len()
                ));
            }
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        other => {
            return Err(anyhow!(
                "Unknown 'server_duid.type' {other:?}. Use \"llt\", \"en\", \"ll\" or \"uuid\""
            ))
        }
    }
    Ok(out)
}

// ============================================================================
// Field parsing
// ============================================================================

/// Parse the 3-octet transaction id, given as a number (0..=16777215) or as hex.
fn parse_xid(value: &serde_json::Value) -> Result<[u8; 3]> {
    let n = if let Some(n) = value.as_u64() {
        n
    } else if let Some(s) = value.as_str() {
        let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(trimmed, 16).map_err(|e| {
            anyhow!(
                "Invalid 'transaction_id' {s:?}: {e}. Expected a number, or hex like \"0x100874\""
            )
        })?
    } else {
        return Err(anyhow!(
            "Invalid 'transaction_id': expected the number from the event, got {value}"
        ));
    };

    if n > 0x00FF_FFFF {
        return Err(anyhow!(
            "'transaction_id' {n} does not fit in the DHCPv6 transaction id, which is 3 octets \
             (max 16777215) — not 4 as in DHCPv4"
        ));
    }
    let b = (n as u32).to_be_bytes();
    Ok([b[1], b[2], b[3]])
}

fn parse_ipv6(value: &serde_json::Value, field: &str) -> Result<Ipv6Addr> {
    let s = value.as_str().ok_or_else(|| {
        anyhow!("'{field}' must be an IPv6 address string, e.g. \"2001:db8::100\", got {value}")
    })?;
    s.parse::<Ipv6Addr>().map_err(|e| {
        anyhow!("Invalid '{field}' {s:?}: {e}. Expected an IPv6 address, e.g. \"2001:db8::100\"")
    })
}

fn u32_field(obj: &serde_json::Value, field: &str, default: u32) -> Result<u32> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| anyhow!("'{field}' must be a number of seconds, got {v}"))?;
            u32::try_from(n)
                .map_err(|_| anyhow!("'{field}' {n} exceeds the 32-bit field (max 4294967295)"))
        }
    }
}

/// One `{address, preferred_lifetime, valid_lifetime}` entry → an IA Address option.
fn parse_ia_addr(entry: &serde_json::Value) -> Result<v6::IAAddr> {
    let addr = parse_ipv6(
        entry.get("address").ok_or_else(|| {
            anyhow!("Each entry in 'addresses' needs an 'address', e.g. {{\"address\": \"2001:db8::100\"}}")
        })?,
        "addresses[].address",
    )?;

    let preferred = u32_field(entry, "preferred_lifetime", 3600)?;
    let valid = u32_field(entry, "valid_lifetime", 7200)?;

    // RFC 8415 §21.6: a client discards an IA Address whose preferred lifetime is greater than
    // its valid lifetime. Refusing here is better than shipping an option the client drops.
    if preferred > valid {
        return Err(anyhow!(
            "'preferred_lifetime' {preferred} is greater than 'valid_lifetime' {valid} for \
             address {addr}. RFC 8415 §21.6 requires preferred <= valid; a client silently \
             discards the address otherwise"
        ));
    }

    Ok(v6::IAAddr {
        addr,
        preferred_life: preferred,
        valid_life: valid,
        opts: v6::DhcpOptions::new(),
    })
}

/// One `{prefix, prefix_length, …}` entry → an IA Prefix option.
fn parse_ia_prefix(entry: &serde_json::Value) -> Result<v6::IAPrefix> {
    let prefix_ip = parse_ipv6(
        entry.get("prefix").ok_or_else(|| {
            anyhow!(
                "Each entry in 'prefixes' needs a 'prefix', e.g. \
                 {{\"prefix\": \"2001:db8:1::\", \"prefix_length\": 56}}"
            )
        })?,
        "prefixes[].prefix",
    )?;

    let len = entry
        .get("prefix_length")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("Each entry in 'prefixes' needs a 'prefix_length', e.g. 56"))?;
    if len > 128 {
        return Err(anyhow!(
            "'prefix_length' {len} is out of range; an IPv6 prefix length is 0..=128"
        ));
    }

    let preferred = u32_field(entry, "preferred_lifetime", 3600)?;
    let valid = u32_field(entry, "valid_lifetime", 7200)?;
    if preferred > valid {
        return Err(anyhow!(
            "'preferred_lifetime' {preferred} is greater than 'valid_lifetime' {valid} for \
             prefix {prefix_ip}/{len}. RFC 8415 §21.22 requires preferred <= valid"
        ));
    }

    Ok(v6::IAPrefix {
        preferred_lifetime: preferred,
        valid_lifetime: valid,
        prefix_len: len as u8,
        prefix_ip,
        opts: v6::DhcpOptions::new(),
    })
}

/// `{"code": "NoAddrsAvail", "message": "…"}` → a Status Code option (13).
fn parse_status_code(value: &serde_json::Value) -> Result<v6::StatusCode> {
    let obj = value.as_object().ok_or_else(|| {
        anyhow!(
            "'status_code' must be an object, e.g. \
             {{\"code\": \"NoAddrsAvail\", \"message\": \"pool exhausted\"}}, got {value}"
        )
    })?;

    let code = obj
        .get("code")
        .ok_or_else(|| anyhow!("'status_code' needs a 'code'"))?;

    let status = if let Some(n) = code.as_u64() {
        v6::Status::from(u16::try_from(n).map_err(|_| {
            anyhow!("'status_code.code' {n} does not fit in the 16-bit status field")
        })?)
    } else if let Some(name) = code.as_str() {
        match name
            .to_ascii_lowercase()
            .replace(['-', '_', ' '], "")
            .as_str()
        {
            "success" => v6::Status::Success,
            "unspecfail" => v6::Status::UnspecFail,
            "noaddrsavail" => v6::Status::NoAddrsAvail,
            "nobinding" => v6::Status::NoBinding,
            "notonlink" => v6::Status::NotOnLink,
            "usemulticast" => v6::Status::UseMulticast,
            "noprefixavail" => v6::Status::NoPrefixAvail,
            other => {
                return Err(anyhow!(
                    "Unknown 'status_code.code' {other:?}. RFC 8415 §21.13 defines Success, \
                     UnspecFail, NoAddrsAvail, NoBinding, NotOnLink, UseMulticast and \
                     NoPrefixAvail; a numeric code is also accepted"
                ))
            }
        }
    } else {
        return Err(anyhow!(
            "'status_code.code' must be a name like \"NoAddrsAvail\" or a number, got {code}"
        ));
    };

    let msg = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(v6::StatusCode { status, msg })
}

/// Parse the search domains into the RFC 1035 name form option 24 carries.
fn parse_domain_search(values: &[serde_json::Value]) -> Result<Vec<dhcproto::Name>> {
    let mut names = Vec::with_capacity(values.len());
    for entry in values {
        let s = entry.as_str().ok_or_else(|| {
            anyhow!("'domain_search' must be an array of domain names, got {entry}")
        })?;
        // A search-list entry is a fully qualified name; force the root label so it encodes
        // with its terminating zero whether or not the caller wrote the trailing dot.
        let fqdn = if s.ends_with('.') {
            s.to_string()
        } else {
            format!("{}.", s)
        };
        names.push(fqdn.parse::<dhcproto::Name>().map_err(|e| {
            anyhow!("Invalid entry {s:?} in 'domain_search': {e}. Expected a domain name, e.g. \"lab.example.com\"")
        })?);
    }
    Ok(names)
}

// ============================================================================
// Protocol trait
// ============================================================================

impl Protocol for Dhcpv6Protocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // DHCPv6 has no IPv4 form at all, so the default host is an IPv6 one. Loopback by
        // default like every other protocol here; pass host "::" to serve a real link, which
        // is also the only case where the multicast join below can succeed.
        //
        // The port here is 0 because the default port is not this binding's to decide:
        // `metadata()` declares the well-known 547, and `protocol::default_port` takes it when
        // this process can bind a privileged port and falls back to an OS-assigned one when it
        // cannot, instead of refusing to start.
        Some(crate::protocol::BindingDefaults::port_based("::1", 0))
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "multicast_interface_index".to_string(),
            type_hint: "number".to_string(),
            description:
                "Interface index on which to join FF02::1:2 (All_DHCP_Relay_Agents_and_Servers), \
                 the multicast group real clients send to. Only attempted when the server binds \
                 the unspecified address (host \"::\"); 0 lets the kernel choose. A failed join \
                 is logged and does not stop the server — unicast still works"
                    .to_string(),
            required: false,
            example: json!(0),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_dhcpv6_advertise_action(),
            send_dhcpv6_reply_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "DHCPv6"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_dhcpv6_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IPv6>UDP>DHCPv6"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["dhcpv6", "dhcp6"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure where the protocol has a word for it: a message answered by a REPLY
            // gets a REPLY whose Status Code is UnspecFail (RFC 8415 18.2.10, "unable to process the
            // client's message"), which asserts nothing about the lease. SOLICIT stays silent: every
            // status an ADVERTISE could carry is a statement about addresses.
            .answers_on_failure()
            // Experimental, and it cannot be more than that on the evidence available. Beta
            // means "works against real clients"; no real DHCPv6 client can be pointed at this
            // server. dhclient -6, dhcpcd and odhcp6c bind UDP/546, need root, and drive a
            // kernel interface rather than an ephemeral loopback port; macOS has no DHCPv6
            // client binary at all (ipconfig drives configd on a real interface). The test peer
            // is an RFC 8415 encoder/decoder written in the test file — an independent reading
            // of the spec, not an independent implementation, and deliberately not `dhcproto`,
            // which is the codec this server encodes with.
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(547))
            .well_known_udp_port(547)
            .implementation("dhcproto v0.12 v6 module for encode/decode; DUIDs hand-encoded")
            .llm_control(
                "Every reply: addresses, prefixes, lifetimes, DNS, search list, status code",
            )
            .e2e_testing("tests/server/dhcpv6/e2e_test.rs, 9 LLM calls. The peer is an RFC 8415 encoder/decoder written in the test file, independent of the dhcproto codec the server encodes with. It asserts SOLICIT->ADVERTISE->REQUEST->REPLY, the Rapid Commit two-message exchange, INFORMATION-REQUEST->REPLY, and that an LLM failure puts nothing on the wire. Checked per reply: message type, the echoed 3-octet transaction id, the echoed Client Identifier, a Server Identifier, the IA_NA IAID, IA_ADDR address and lifetimes, IA_PD/IAPREFIX, options 23 and 24, and option 14 on the rapid-commit REPLY. Not covered: a real client, multicast delivery to FF02::1:2, relay (RELAY-FORW/RELAY-REPL), CONFIRM and DECLINE")
            .notes("No lease database of any kind: the model picks every address, prefix and lifetime, and nothing stops it handing the same address to two clients. The transaction id is 3 octets, the Client Identifier and the IA_NA/IA_PD IAIDs are echoed from the request automatically. CONFIRM, DECLINE, RECONFIGURE and RELAY-FORW are dropped without reaching the model. An LLM failure sends nothing — a DHCPv6 reply writes an address, lifetimes and resolvers into the client's stack, and the protocol has no way to say 'ask again later'")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "DHCPv6 server (RFC 8415) for IPv6 address assignment and prefix delegation"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a DHCPv6 server assigning addresses from 2001:db8::/64 with DNS 2001:4860:4860::8888"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 547,
                "base_stack": "dhcpv6",
                "instruction": "DHCPv6 server: advertise and assign addresses from 2001:db8:1::/64 with a 1 hour preferred and 2 hour valid lifetime, DNS 2001:4860:4860::8888, search domain lab.example.com"
            }),
            json!({
                "type": "open_server",
                "port": 547,
                "base_stack": "dhcpv6",
                "event_handlers": [{
                    "event_pattern": "dhcpv6_solicit",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Rapid Commit collapses SOLICIT/ADVERTISE/REQUEST/REPLY into two messages\nif event.get('rapid_commit'):\n    respond([{'type': 'send_dhcpv6_reply', 'rapid_commit': True, 'addresses': [{'address': '2001:db8:1::100', 'preferred_lifetime': 3600, 'valid_lifetime': 7200}], 'dns_servers': ['2001:4860:4860::8888']}])\nelse:\n    respond([{'type': 'send_dhcpv6_advertise', 'addresses': [{'address': '2001:db8:1::100', 'preferred_lifetime': 3600, 'valid_lifetime': 7200}], 'dns_servers': ['2001:4860:4860::8888']}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 547,
                "base_stack": "dhcpv6",
                "event_handlers": [{
                    "event_pattern": "dhcpv6_information_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dhcpv6_reply",
                            "dns_servers": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
                            "domain_search": ["lab.example.com"]
                        }]
                    }
                }]
            }),
        )
    }
}

// ============================================================================
// Server trait
// ============================================================================

impl Server for Dhcpv6Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dhcpv6::Dhcpv6Server;

            // Propagate a bad parameter rather than unwrapping it: over MCP a panic here kills
            // the request task before it can reply, and the caller hangs on a server stuck in
            // Starting.
            let multicast_interface_index = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u32("multicast_interface_index"))
                .transpose()?
                .flatten()
                .unwrap_or(0);

            let listen_addr = ctx.socket_addr().ok_or_else(|| {
                anyhow!("DHCPv6 requires a host and a port to bind (default [::1]:547)")
            })?;

            Dhcpv6Server::spawn_with_llm_actions(
                listen_addr,
                multicast_interface_index,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_dhcpv6_advertise" => self.execute_send(action, v6::MessageType::Advertise),
            "send_dhcpv6_reply" => self.execute_send(action, v6::MessageType::Reply),
            "no_response" => Ok(ActionResult::NoAction),
            _ => Err(anyhow!("Unknown DHCPv6 action: {}", action_type)),
        }
    }
}

impl Dhcpv6Protocol {
    /// Build and encode an ADVERTISE or a REPLY from the model's semantic parameters.
    fn execute_send(
        &self,
        action: serde_json::Value,
        msg_type: v6::MessageType,
    ) -> Result<ActionResult> {
        let context = self
            .request_context
            .lock()
            .map_err(|_| anyhow!("DHCPv6 request context lock was poisoned"))?
            .clone();

        // ---- header ------------------------------------------------------------------
        //
        // A client matches a reply to its request by the transaction id and drops anything
        // else without a word, so a wrong echo presents as a timeout rather than an error.
        let xid = match action.get("transaction_id") {
            Some(v) => parse_xid(v)?,
            None => context.as_ref().map(|c| c.xid).ok_or_else(|| {
                anyhow!(
                    "No DHCPv6 request context available and no 'transaction_id' given: cannot \
                     build a reply the client will accept. Pass the 'transaction_id' from the \
                     event being answered."
                )
            })?,
        };

        let mut msg = v6::Message::new_with_id(msg_type, xid);

        // RFC 8415 §16: a Reply/Advertise carries the Client Identifier from the message it
        // answers. An INFORMATION-REQUEST may legitimately have sent none.
        if let Some(duid) = context.as_ref().and_then(|c| c.client_duid.clone()) {
            msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));
        }

        let server_duid = match action.get("server_duid") {
            Some(spec) => encode_duid(spec)?,
            None => default_server_duid(),
        };
        msg.opts_mut().insert(v6::DhcpOption::ServerId(server_duid));

        // ---- rapid commit ------------------------------------------------------------
        //
        // RFC 8415 §21.14: the server includes option 14 in the REPLY it sends *instead of*
        // an ADVERTISE. Refuse it on an ADVERTISE, where it means nothing.
        let rapid_commit = action
            .get("rapid_commit")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if rapid_commit {
            if msg_type != v6::MessageType::Reply {
                return Err(anyhow!(
                    "'rapid_commit' belongs on send_dhcpv6_reply, not on an ADVERTISE: RFC 8415 \
                     §18.3.1 defines it as answering the SOLICIT with a REPLY instead of an \
                     ADVERTISE"
                ));
            }
            msg.opts_mut().insert(v6::DhcpOption::RapidCommit);
        }

        // ---- preference --------------------------------------------------------------
        if let Some(pref) = action.get("preference") {
            let n = pref
                .as_u64()
                .ok_or_else(|| anyhow!("'preference' must be a number 0-255, got {pref}"))?;
            let n = u8::try_from(n).map_err(|_| {
                anyhow!("'preference' {n} is out of range; RFC 8415 §21.8 allows 0-255")
            })?;
            msg.opts_mut().insert(v6::DhcpOption::Preference(n));
        }

        // ---- identity associations ---------------------------------------------------
        let t1 = u32_field(&action, "t1", 0)?;
        let t2 = u32_field(&action, "t2", 0)?;
        if t1 != 0 && t2 != 0 && t1 > t2 {
            return Err(anyhow!(
                "'t1' {t1} is greater than 't2' {t2}. RFC 8415 §21.4 requires T1 <= T2; a client \
                 discards an IA whose timers are inverted. Use 0 to let the client choose"
            ));
        }

        if let Some(entries) = action.get("addresses") {
            let entries = entries.as_array().ok_or_else(|| {
                anyhow!(
                    "'addresses' must be an array of \
                     {{address, preferred_lifetime, valid_lifetime}} objects, got {entries}"
                )
            })?;
            if !entries.is_empty() {
                let ia_id = match action.get("ia_id") {
                    Some(v) => v
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| anyhow!("'ia_id' must be a 32-bit number, got {v}"))?,
                    None => context.as_ref().and_then(|c| c.ia_na_id).ok_or_else(|| {
                        anyhow!(
                            "The message being answered carried no IA_NA, so there is no IAID to \
                             put these addresses under and the client would ignore them. Either \
                             drop 'addresses' or pass 'ia_id' explicitly."
                        )
                    })?,
                };

                let mut opts = v6::DhcpOptions::new();
                for entry in entries {
                    opts.insert(v6::DhcpOption::IAAddr(parse_ia_addr(entry)?));
                }
                msg.opts_mut().insert(v6::DhcpOption::IANA(v6::IANA {
                    id: ia_id,
                    t1,
                    t2,
                    opts,
                }));
            }
        }

        if let Some(entries) = action.get("prefixes") {
            let entries = entries.as_array().ok_or_else(|| {
                anyhow!(
                    "'prefixes' must be an array of {{prefix, prefix_length, …}} objects, \
                     got {entries}"
                )
            })?;
            if !entries.is_empty() {
                let ia_pd_id = match action.get("ia_pd_id") {
                    Some(v) => v
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| anyhow!("'ia_pd_id' must be a 32-bit number, got {v}"))?,
                    None => context.as_ref().and_then(|c| c.ia_pd_id).ok_or_else(|| {
                        anyhow!(
                            "The message being answered carried no IA_PD, so it is not asking for \
                             a delegated prefix and would ignore one. Either drop 'prefixes' or \
                             pass 'ia_pd_id' explicitly."
                        )
                    })?,
                };

                let mut opts = v6::DhcpOptions::new();
                for entry in entries {
                    opts.insert(v6::DhcpOption::IAPrefix(parse_ia_prefix(entry)?));
                }
                msg.opts_mut().insert(v6::DhcpOption::IAPD(v6::IAPD {
                    id: ia_pd_id,
                    t1,
                    t2,
                    opts,
                }));
            }
        }

        // ---- configuration -----------------------------------------------------------
        //
        // An unparseable entry is an error rather than being skipped: shipping a shorter
        // resolver list than the caller asked for is worse than saying the value was wrong.
        if let Some(entries) = action.get("dns_servers") {
            let entries = entries.as_array().ok_or_else(|| {
                anyhow!("'dns_servers' must be an array of IPv6 address strings, got {entries}")
            })?;
            let mut servers = Vec::with_capacity(entries.len());
            for entry in entries {
                servers.push(parse_ipv6(entry, "dns_servers[]")?);
            }
            if !servers.is_empty() {
                msg.opts_mut()
                    .insert(v6::DhcpOption::DomainNameServers(servers));
            }
        }

        if let Some(entries) = action.get("domain_search") {
            let entries = entries.as_array().ok_or_else(|| {
                anyhow!("'domain_search' must be an array of domain names, got {entries}")
            })?;
            let names = parse_domain_search(entries)?;
            if !names.is_empty() {
                msg.opts_mut()
                    .insert(v6::DhcpOption::DomainSearchList(names));
            }
        }

        if let Some(status) = action.get("status_code") {
            msg.opts_mut()
                .insert(v6::DhcpOption::StatusCode(parse_status_code(status)?));
        }

        // ---- encode ------------------------------------------------------------------
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        msg.encode(&mut encoder)
            .map_err(|e| anyhow!("Failed to encode the DHCPv6 message: {e}"))?;
        Ok(ActionResult::Output(buf))
    }
}

// ============================================================================
// Action definitions
// ============================================================================

/// The configuration parameters `send_dhcpv6_advertise` and `send_dhcpv6_reply` share.
fn shared_reply_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "addresses".to_string(),
            type_hint: "array of objects".to_string(),
            description: "Addresses to hand this client, each {\"address\": \"2001:db8:1::100\", \
                 \"preferred_lifetime\": 3600, \"valid_lifetime\": 7200}. Lifetimes are in \
                 seconds and default to 3600/7200; preferred must not exceed valid. They go into \
                 the IA_NA under the IAID the client sent, which is filled in for you"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "prefixes".to_string(),
            type_hint: "array of objects".to_string(),
            description:
                "Delegated prefixes, each {\"prefix\": \"2001:db8:100::\", \"prefix_length\": 56, \
                 \"preferred_lifetime\": 3600, \"valid_lifetime\": 7200}. Only send these when the \
                 event reported an 'ia_pd_id' — a client that did not ask for a prefix ignores one"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "dns_servers".to_string(),
            type_hint: "array of strings".to_string(),
            description: "Recursive resolvers in preference order (option 23), e.g. \
                 [\"2001:4860:4860::8888\"]. Every entry must be an IPv6 address"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "domain_search".to_string(),
            type_hint: "array of strings".to_string(),
            description: "Domain search list (option 24), e.g. [\"lab.example.com\"]".to_string(),
            required: false,
        },
        Parameter {
            name: "t1".to_string(),
            type_hint: "number".to_string(),
            description:
                "Seconds after which the client should RENEW with this server (IA_NA/IA_PD T1). \
                 0, the default, lets the client choose. Must not exceed t2"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "t2".to_string(),
            type_hint: "number".to_string(),
            description:
                "Seconds after which the client should REBIND to any server (T2). 0, the default, \
                 lets the client choose"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "status_code".to_string(),
            type_hint: "object".to_string(),
            description:
                "Say why there is nothing to give, e.g. {\"code\": \"NoAddrsAvail\", \"message\": \
                 \"pool exhausted\"}. Names: Success, UnspecFail, NoAddrsAvail, NoBinding, \
                 NotOnLink, UseMulticast, NoPrefixAvail. This is a statement about the client's \
                 lease, never about this server's health"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "server_duid".to_string(),
            type_hint: "object".to_string(),
            description:
                "This server's identity (option 2), as {\"type\": \"ll\", \"hardware_type\": 1, \
                 \"link_layer_address\": \"00:11:22:33:44:55\"}, or type \"en\" with \
                 'enterprise_number'/'identifier', \"llt\" with 'time' as well, or \"uuid\" with \
                 'uuid'. Omit it and a stable placeholder DUID-EN is used — but it must be the \
                 SAME in the ADVERTISE and the REPLY of one exchange, so if you set it, set it \
                 identically in both"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "ia_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "IAID for the IA_NA carrying 'addresses'. Omit it: the server reuses the IAID the \
                 client sent, which is the only one it will accept"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "ia_pd_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "IAID for the IA_PD carrying 'prefixes'. Omit it: the server reuses the client's"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "The 3-octet transaction id to echo (0-16777215 — DHCPv6 uses three octets, not \
                 four as DHCPv4 does). Omit it: the server echoes the id of the message being \
                 answered, and a client silently discards a reply whose id differs"
                    .to_string(),
            required: false,
        },
    ]
}

fn send_dhcpv6_advertise_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcpv6_advertise".to_string(),
        description:
            "Answer a SOLICIT with an ADVERTISE offering addresses and configuration. The client \
             normally follows up with a REQUEST for the same addresses, which you answer with \
             send_dhcpv6_reply carrying identical values. The transaction id, the client's DUID \
             and the IA_NA/IA_PD identifiers are echoed from the SOLICIT for you. If the SOLICIT \
             asked for Rapid Commit, prefer send_dhcpv6_reply with rapid_commit instead — that is \
             the two-message exchange the client asked for."
                .to_string(),
        parameters: {
            let mut params = shared_reply_parameters();
            params.push(Parameter {
                name: "preference".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Preference value 0-255 (option 7). 255 tells the client to stop waiting for \
                     other servers and request from this one immediately"
                        .to_string(),
                required: false,
            });
            params
        },
        example: json!({
            "type": "send_dhcpv6_advertise",
            "addresses": [{
                "address": "2001:db8:1::100",
                "preferred_lifetime": 3600,
                "valid_lifetime": 7200
            }],
            "dns_servers": ["2001:4860:4860::8888"],
            "domain_search": ["lab.example.com"],
            "t1": 1800,
            "t2": 2880
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCPv6 ADVERTISE")
                .with_debug("DHCPv6 send_dhcpv6_advertise: addresses={addresses}"),
        ),
    }
}

fn send_dhcpv6_reply_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcpv6_reply".to_string(),
        description:
            "Send a REPLY. This answers REQUEST, RENEW, REBIND, RELEASE and INFORMATION-REQUEST, \
             and — with rapid_commit set — a SOLICIT that asked for the two-message exchange. \
             For a REQUEST or RENEW, send the same addresses and lifetimes you advertised: a \
             client that gets different values may start over. For a RELEASE, reply with a \
             status_code of Success and no addresses. For an INFORMATION-REQUEST, send only \
             configuration (dns_servers, domain_search) and no addresses — that client has an \
             address already and asked for nothing else."
                .to_string(),
        parameters: {
            let mut params = shared_reply_parameters();
            params.push(Parameter {
                name: "rapid_commit".to_string(),
                type_hint: "boolean".to_string(),
                description: "Set true only when answering a SOLICIT whose event reported \
                     rapid_commit: true. It includes option 14, which is what tells the client \
                     this REPLY is a committed assignment rather than a stray message"
                    .to_string(),
                required: false,
            });
            params
        },
        example: json!({
            "type": "send_dhcpv6_reply",
            "addresses": [{
                "address": "2001:db8:1::100",
                "preferred_lifetime": 3600,
                "valid_lifetime": 7200
            }],
            "dns_servers": ["2001:4860:4860::8888"],
            "t1": 1800,
            "t2": 2880
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCPv6 REPLY")
                .with_debug("DHCPv6 send_dhcpv6_reply: addresses={addresses}"),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description:
            "Answer this message with nothing at all. DHCPv6 clients retransmit with backoff, so \
             silence is a real answer — use it to ignore a client rather than inventing a lease \
             for it. This is not the same as a status_code: a status code is a statement about \
             the client's lease, silence says nothing."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "no_response" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DHCPv6 message ignored")
                .with_debug("DHCPv6 no_response"),
        ),
    }
}

// ============================================================================
// Event types
// ============================================================================

/// The fields every DHCPv6 client message reports.
fn common_event_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "The client's 3-octet transaction id (0-16777215). Echoed into your reply \
                 automatically; you only need it if you build a reply out of band"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "client_duid".to_string(),
            type_hint: "object".to_string(),
            description:
                "Who the client is (option 1), decoded: 'type' is \"llt\", \"en\", \"ll\", \
                 \"uuid\" or \"unknown\"; 'text' is the canonical colon-hex spelling and is the \
                 stable key to match on; 'link_layer_address' carries the MAC for the \"llt\" and \
                 \"ll\" forms. Absent only in an INFORMATION-REQUEST, where it is optional. \
                 Echoed into your reply automatically"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "requested_options".to_string(),
            type_hint: "array of strings".to_string(),
            description: "The option names the client asked for (its Option Request Option), e.g. \
                 [\"DomainNameServers\", \"DomainSearchList\"]. Sending what it asked for is the \
                 point of this list; sending more is allowed"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "ia_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "IAID of the client's IA_NA — the identity association your addresses belong to. \
                 Absent means the client is not asking for an address. Echoed automatically"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "ia_pd_id".to_string(),
            type_hint: "number".to_string(),
            description:
                "IAID of the client's IA_PD. Present only when the client wants a delegated \
                 prefix. Echoed automatically"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "client_addresses".to_string(),
            type_hint: "array of objects".to_string(),
            description:
                "Addresses the client named in its own IA_NA — a hint in a SOLICIT, the address \
                 it holds in a RENEW/REBIND, the one it is giving up in a RELEASE"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "client_prefixes".to_string(),
            type_hint: "array of objects".to_string(),
            description: "Prefixes the client named in its own IA_PD, same idea as \
                          client_addresses"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description:
                "IPv6 address the datagram came from — a link-local address for a client on the \
                 link, or a relay's address"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "source_port".to_string(),
            type_hint: "number".to_string(),
            description: "UDP source port; 546 for a real client, 547 for a relay".to_string(),
            required: false,
        },
    ]
}

/// The advertise/reply pair a SOLICIT can be answered with.
fn solicit_actions() -> Vec<ActionDefinition> {
    vec![
        send_dhcpv6_advertise_action(),
        send_dhcpv6_reply_action(),
        no_response_action(),
    ]
}

/// Everything except SOLICIT is answered with a REPLY; an ADVERTISE would be ignored.
fn reply_actions() -> Vec<ActionDefinition> {
    vec![send_dhcpv6_reply_action(), no_response_action()]
}

fn address_reply_example() -> serde_json::Value {
    json!({
        "type": "send_dhcpv6_reply",
        "addresses": [{
            "address": "2001:db8:1::100",
            "preferred_lifetime": 3600,
            "valid_lifetime": 7200
        }],
        "dns_servers": ["2001:4860:4860::8888"]
    })
}

pub static DHCPV6_SOLICIT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_solicit",
        "A client is looking for a DHCPv6 server (SOLICIT). Answer with send_dhcpv6_advertise \
         offering an address; if 'rapid_commit' is true the client wants the two-message \
         exchange instead, so answer with send_dhcpv6_reply and rapid_commit: true",
        json!({
            "type": "send_dhcpv6_advertise",
            "addresses": [{
                "address": "2001:db8:1::100",
                "preferred_lifetime": 3600,
                "valid_lifetime": 7200
            }],
            "dns_servers": ["2001:4860:4860::8888"]
        }),
    )
    .with_parameters({
        let mut params = common_event_parameters();
        params.push(Parameter {
            name: "rapid_commit".to_string(),
            type_hint: "boolean".to_string(),
            description:
                "The client sent option 14: it will accept a REPLY straight away instead of \
                 waiting for the REQUEST round trip. Answer with send_dhcpv6_reply and \
                 rapid_commit: true, or ignore the request and ADVERTISE as usual"
                    .to_string(),
            required: false,
        });
        params
    })
    .with_actions(solicit_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 SOLICIT from {source_address}")
            .with_debug("DHCPv6 SOLICIT: ia_id={ia_id}, rapid_commit={rapid_commit}")
            .with_trace("DHCPv6 SOLICIT: {json_pretty(.)}"),
    )
});

pub static DHCPV6_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_request",
        "The client is requesting the addresses you advertised (REQUEST). Answer with \
         send_dhcpv6_reply carrying the same addresses and lifetimes you offered",
        address_reply_example(),
    )
    .with_parameters(common_event_parameters())
    .with_actions(reply_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 REQUEST from {source_address}")
            .with_debug("DHCPv6 REQUEST: ia_id={ia_id}")
            .with_trace("DHCPv6 REQUEST: {json_pretty(.)}"),
    )
});

pub static DHCPV6_RENEW_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_renew",
        "The client's T1 elapsed and it is asking this server to extend its lease (RENEW). \
         Answer with send_dhcpv6_reply carrying the same addresses and fresh lifetimes, or a \
         status_code of NoBinding if you will not extend them",
        address_reply_example(),
    )
    .with_parameters(common_event_parameters())
    .with_actions(reply_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 RENEW from {source_address}")
            .with_debug("DHCPv6 RENEW: ia_id={ia_id}, addresses={client_addresses}")
            .with_trace("DHCPv6 RENEW: {json_pretty(.)}"),
    )
});

pub static DHCPV6_REBIND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_rebind",
        "The client's T2 elapsed with no answer from the server that gave it the lease, so it is \
         asking any server (REBIND). Answer with send_dhcpv6_reply if you are willing to take \
         the lease over; ignore it with no_response if you are not, since RFC 8415 §18.3.5 says \
         a server with no knowledge of the binding stays silent",
        address_reply_example(),
    )
    .with_parameters(common_event_parameters())
    .with_actions(reply_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 REBIND from {source_address}")
            .with_debug("DHCPv6 REBIND: ia_id={ia_id}, addresses={client_addresses}")
            .with_trace("DHCPv6 REBIND: {json_pretty(.)}"),
    )
});

pub static DHCPV6_RELEASE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_release",
        "The client is giving its addresses back (RELEASE). Acknowledge with send_dhcpv6_reply \
         carrying a Success status code and no addresses — RFC 8415 §18.3.7 requires a Reply",
        json!({
            "type": "send_dhcpv6_reply",
            "status_code": {"code": "Success", "message": "Released"}
        }),
    )
    .with_parameters(common_event_parameters())
    .with_actions(reply_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 RELEASE from {source_address}")
            .with_debug("DHCPv6 RELEASE: ia_id={ia_id}, addresses={client_addresses}")
            .with_trace("DHCPv6 RELEASE: {json_pretty(.)}"),
    )
});

pub static DHCPV6_INFORMATION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcpv6_information_request",
        "A stateless client already has an address and wants configuration only \
         (INFORMATION-REQUEST). Answer with send_dhcpv6_reply carrying dns_servers and \
         domain_search and NO addresses — it is not asking for one",
        json!({
            "type": "send_dhcpv6_reply",
            "dns_servers": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
            "domain_search": ["lab.example.com"]
        }),
    )
    .with_parameters(common_event_parameters())
    .with_actions(reply_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCPv6 INFORMATION-REQUEST from {source_address}")
            .with_debug("DHCPv6 INFORMATION-REQUEST: requested={requested_options}")
            .with_trace("DHCPv6 INFORMATION-REQUEST: {json_pretty(.)}"),
    )
});

pub fn get_dhcpv6_event_types() -> Vec<EventType> {
    vec![
        DHCPV6_SOLICIT_EVENT.clone(),
        DHCPV6_REQUEST_EVENT.clone(),
        DHCPV6_RENEW_EVENT.clone(),
        DHCPV6_REBIND_EVENT.clone(),
        DHCPV6_RELEASE_EVENT.clone(),
        DHCPV6_INFORMATION_REQUEST_EVENT.clone(),
    ]
}
