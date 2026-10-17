//! DHCP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

use dhcproto::{v4, Encodable, Encoder};

pub struct DhcpProtocol {
    request_context: std::sync::Arc<std::sync::Mutex<Option<DhcpRequestContext>>>,
}

#[derive(Clone)]
pub struct DhcpRequestContext {
    pub xid: u32,        // Transaction ID
    pub chaddr: Vec<u8>, // Client MAC address
    pub message_type: v4::MessageType,
    pub ciaddr: Ipv4Addr,               // Client IP address (if set)
    pub giaddr: Ipv4Addr,               // Relay agent address the request came through
    pub broadcast: bool,                // Client's broadcast flag
    pub requested_ip: Option<Ipv4Addr>, // Requested IP from options
}

impl DhcpProtocol {
    pub fn new() -> Self {
        Self {
            request_context: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn set_request_context(&self, context: DhcpRequestContext) {
        *self.request_context.lock().unwrap() = Some(context);
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DhcpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_dhcp_offer_action(),
            send_dhcp_ack_action(),
            send_dhcp_nak_action(),
            send_dhcp_response_action(),
            ignore_request_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DHCP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_dhcp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DHCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dhcp"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Experimental, not Beta. Beta means "works against real clients", and this
            // protocol's own e2e_testing note below states that no real DHCP client can be
            // pointed at it: dhclient/ipconfig bind UDP/68, need root, and cannot target an
            // ephemeral loopback port. The test peer is an RFC 2131/2132 decoder written in the
            // test file — a genuinely independent reading of the spec, and a good test, but not
            // a third-party implementation. Promoting again means decoding the replies with an
            // independent codec crate as well.
            .state(DevelopmentState::Experimental)
            // Deliberately silent: Every DHCP server message is an offer, an acknowledgement
            // or a refusal of a specific lease. A fabricated one reconfigures a real host.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(67))
            .well_known_udp_port(67)
            .implementation("dhcproto v0.12 for parsing and encoding")
            .llm_control("Discover→Offer, Request→Ack flow + lease options")
            .e2e_testing("tests/server/dhcp/test.rs, 6 LLM calls. No real DHCP client can be pointed at these servers (dhclient/ipconfig bind UDP/68, need root, and cannot target an ephemeral loopback port), so the peer is an RFC 2131/2132 decoder written in the test file, independent of the dhcproto codec the server encodes with. It asserts OFFER, ACK and NAK against RFC 2131 table 3: op/htype/hlen, the echoed xid, chaddr and broadcast flag, yiaddr, and options 1/3/6/51/54/56. Not covered: a full DORA exchange against a real client, relayed (giaddr) delivery, and option 82")
            .notes("No lease database: the LLM picks every address. xid, chaddr, giaddr and the broadcast flag are echoed from the request automatically. A datagram that does not decode, or carries no message-type option, is dropped without reaching the model")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DHCP server for IP address assignment"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a DHCP server on interface eth0"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 67,
                "base_stack": "dhcp",
                "instruction": "DHCP server assigning IPs from 192.168.1.100-200, subnet 255.255.255.0, gateway 192.168.1.1, DNS 8.8.8.8"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 67,
                "base_stack": "dhcp",
                "event_handlers": [{
                    "event_pattern": "dhcp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle DHCP Discover/Request (message_type is capitalised, not upper case)\nif event.get('message_type') == 'Discover':\n    respond([{'type': 'send_dhcp_offer', 'offered_ip': '192.168.1.100', 'subnet_mask': '255.255.255.0', 'router': '192.168.1.1', 'dns_servers': ['8.8.8.8'], 'lease_time': 86400}])\nelif event.get('message_type') == 'Request':\n    respond([{'type': 'send_dhcp_ack', 'assigned_ip': '192.168.1.100', 'subnet_mask': '255.255.255.0', 'router': '192.168.1.1', 'dns_servers': ['8.8.8.8'], 'lease_time': 86400}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 67,
                "base_stack": "dhcp",
                "event_handlers": [{
                    "event_pattern": "dhcp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dhcp_offer",
                            "offered_ip": "192.168.1.100",
                            "subnet_mask": "255.255.255.0",
                            "router": "192.168.1.1",
                            "dns_servers": ["8.8.8.8"],
                            "lease_time": 86400
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DhcpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dhcp::DhcpServer;
            DhcpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
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
            "send_dhcp_offer" => self.execute_send_dhcp_offer(action),
            "send_dhcp_ack" => self.execute_send_dhcp_ack(action),
            "send_dhcp_nak" => self.execute_send_dhcp_nak(action),
            "send_dhcp_response" => self.execute_send_dhcp_response(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown DHCP action: {}", action_type)),
        }
    }
}

impl DhcpProtocol {
    /// Start a reply that the client will actually accept: BOOTREPLY carrying this
    /// request's transaction id, hardware address, relay address and broadcast flag.
    ///
    /// A DHCP client silently drops any reply whose `xid` differs from the request it
    /// sent, so the echo has to be right or the exchange just looks like a timeout. The
    /// values come from the request context this instance was built with; an explicit
    /// `xid` / `client_mac` in the action overrides them for out-of-band replies.
    fn base_reply(&self, action: &serde_json::Value, server_ip: Ipv4Addr) -> Result<v4::Message> {
        let context = self
            .request_context
            .lock()
            .map_err(|_| anyhow!("DHCP request context lock was poisoned"))?
            .clone();

        let xid = match action.get("xid") {
            Some(v) => parse_xid(v)?,
            None => context.as_ref().map(|c| c.xid).ok_or_else(|| {
                anyhow!(
                    "No DHCP request context available and no 'xid' given: cannot build a reply \
                     the client will accept. Pass the 'xid' from the dhcp_request event."
                )
            })?,
        };

        let chaddr = match action.get("client_mac").and_then(|v| v.as_str()) {
            Some(mac) => parse_mac(mac)?,
            None => context.as_ref().map(|c| c.chaddr.clone()).ok_or_else(|| {
                anyhow!(
                    "No DHCP request context available and no 'client_mac' given. Pass the \
                     'client_mac' from the dhcp_request event."
                )
            })?,
        };

        // Relay address must be echoed or a relayed client never sees the reply.
        let giaddr = parse_ipv4(action, "gateway_ip")?.unwrap_or_else(|| {
            context
                .as_ref()
                .map(|c| c.giaddr)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        });

        // RFC 2131 4.1: honour the client's broadcast flag. When the request is unknown,
        // broadcast is the safe choice - a client with no address yet cannot receive a
        // unicast reply on every stack.
        let broadcast = context.as_ref().map(|c| c.broadcast).unwrap_or(true);
        let flags = if broadcast {
            v4::Flags::default().set_broadcast()
        } else {
            v4::Flags::default()
        };

        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootReply)
            .set_xid(xid)
            .set_flags(flags)
            .set_siaddr(server_ip)
            .set_giaddr(giaddr)
            .set_chaddr(&chaddr);

        Ok(msg)
    }

    /// Apply the network-configuration options shared by OFFER and ACK.
    fn apply_config_options(
        msg: &mut v4::Message,
        action: &serde_json::Value,
        server_ip: Ipv4Addr,
    ) -> Result<()> {
        let lease_time = action
            .get("lease_time")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);
        let lease_time = u32::try_from(lease_time).map_err(|_| {
            anyhow!("'lease_time' {lease_time} exceeds the 32-bit seconds field (max 4294967295)")
        })?;

        msg.opts_mut()
            .insert(v4::DhcpOption::ServerIdentifier(server_ip));
        msg.opts_mut()
            .insert(v4::DhcpOption::AddressLeaseTime(lease_time));

        if let Some(mask) = parse_ipv4(action, "subnet_mask")? {
            msg.opts_mut().insert(v4::DhcpOption::SubnetMask(mask));
        }

        if let Some(gw) = parse_ipv4(action, "router")? {
            msg.opts_mut().insert(v4::DhcpOption::Router(vec![gw]));
        }

        // Unparseable DNS entries are an error rather than being dropped: silently
        // shipping a shorter list than asked for is worse than saying so.
        if let Some(arr) = action.get("dns_servers").and_then(|v| v.as_array()) {
            let mut dns = Vec::with_capacity(arr.len());
            for entry in arr {
                let s = entry.as_str().ok_or_else(|| {
                    anyhow!("'dns_servers' must be an array of IPv4 strings, got {entry}")
                })?;
                dns.push(s.parse::<Ipv4Addr>().map_err(|e| {
                    anyhow!("Invalid entry {s:?} in 'dns_servers': {e}. Expected dotted-quad IPv4")
                })?);
            }
            if !dns.is_empty() {
                msg.opts_mut().insert(v4::DhcpOption::DomainNameServer(dns));
            }
        }

        if let Some(domain) = action.get("domain_name").and_then(|v| v.as_str()) {
            msg.opts_mut()
                .insert(v4::DhcpOption::DomainName(domain.to_string()));
        }

        Ok(())
    }

    fn encode_message(msg: &v4::Message) -> Result<ActionResult> {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        msg.encode(&mut encoder)?;
        Ok(ActionResult::Output(buf))
    }

    fn execute_send_dhcp_offer(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_ip = parse_ipv4(&action, "server_ip")?.unwrap_or(Ipv4Addr::UNSPECIFIED);

        let offered_ip = parse_ipv4(&action, "offered_ip")?
            .ok_or_else(|| anyhow!("Missing 'offered_ip' parameter"))?;

        let mut msg = self.base_reply(&action, server_ip)?;
        msg.set_yiaddr(offered_ip);
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));
        Self::apply_config_options(&mut msg, &action, server_ip)?;

        Self::encode_message(&msg)
    }

    fn execute_send_dhcp_ack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_ip = parse_ipv4(&action, "server_ip")?.unwrap_or(Ipv4Addr::UNSPECIFIED);

        let assigned_ip = parse_ipv4(&action, "assigned_ip")?
            .ok_or_else(|| anyhow!("Missing 'assigned_ip' parameter"))?;

        let mut msg = self.base_reply(&action, server_ip)?;
        msg.set_yiaddr(assigned_ip);
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Ack));
        Self::apply_config_options(&mut msg, &action, server_ip)?;

        Self::encode_message(&msg)
    }

    fn execute_send_dhcp_nak(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_ip = parse_ipv4(&action, "server_ip")?.unwrap_or(Ipv4Addr::UNSPECIFIED);

        let mut msg = self.base_reply(&action, server_ip)?;
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Nak));
        msg.opts_mut()
            .insert(v4::DhcpOption::ServerIdentifier(server_ip));

        // Optional message
        if let Some(message) = action.get("message").and_then(|v| v.as_str()) {
            msg.opts_mut()
                .insert(v4::DhcpOption::Message(message.to_string()));
        }

        Self::encode_message(&msg)
    }

    fn execute_send_dhcp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        let bytes = decode_hex_packet(data)?;

        if bytes.len() < 236 {
            return Err(anyhow!(
                "'data' decodes to {} bytes; a DHCP packet is at least 236 bytes before options \
                 (300 in practice). Prefer send_dhcp_offer / send_dhcp_ack, which build a \
                 well-formed packet for you.",
                bytes.len()
            ));
        }

        Ok(ActionResult::Output(bytes))
    }
}

/// Decode the `data` field of the raw-packet action.
///
/// The parameter is documented as hex, so it is decoded strictly as hex: an unparseable
/// value is an error rather than being silently put on the wire as ASCII, which would
/// produce a packet no DHCP client can read. Whitespace and `:` separators are tolerated
/// because models emit them, and a leading `0x` is stripped.
fn decode_hex_packet(data: &str) -> Result<Vec<u8>> {
    let cleaned: String = data
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);

    if cleaned.len() % 2 != 0 {
        return Err(anyhow!(
            "Invalid hex in 'data': got {} hex digits, which is odd - every byte is exactly two \
             digits. Value was {data:?}",
            cleaned.len()
        ));
    }

    hex::decode(cleaned).map_err(|e| {
        anyhow!(
            "Invalid hex in 'data' ({data:?}): {e}. Use only the digits 0-9 and a-f, two per byte. \
             This field is the raw packet - there is no text mode."
        )
    })
}

/// Parse an optional dotted-quad IPv4 field, reporting the field name on failure.
fn parse_ipv4(action: &serde_json::Value, field: &str) -> Result<Option<Ipv4Addr>> {
    match action.get(field).and_then(|v| v.as_str()) {
        Some(s) => s.parse::<Ipv4Addr>().map(Some).map_err(|e| {
            anyhow!(
                "Invalid '{field}' {s:?}: {e}. Expected dotted-quad IPv4, e.g. \"192.168.1.100\""
            )
        }),
        None => Ok(None),
    }
}

/// Parse a transaction id given either as a JSON number or as a hex string ("0x6395a3e3").
fn parse_xid(value: &serde_json::Value) -> Result<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).map_err(|_| {
            anyhow!("'xid' {n} does not fit in the 32-bit DHCP transaction id field")
        });
    }
    if let Some(s) = value.as_str() {
        let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        return u32::from_str_radix(trimmed, 16).map_err(|e| {
            anyhow!("Invalid 'xid' {s:?}: {e}. Expected a number, or hex like \"0x6395a3e3\"")
        });
    }
    Err(anyhow!(
        "Invalid 'xid': expected the number from the dhcp_request event, got {value}"
    ))
}

/// Parse a hardware address written as `00:11:22:33:44:55`, `00-11-22-...` or bare hex.
fn parse_mac(mac: &str) -> Result<Vec<u8>> {
    let cleaned: String = mac
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-' && *c != '.')
        .collect();

    if cleaned.is_empty() || cleaned.len() % 2 != 0 || cleaned.len() > 32 {
        return Err(anyhow!(
            "Invalid 'client_mac' {mac:?}: expected up to 16 bytes of hex, e.g. \
             \"00:11:22:33:44:55\""
        ));
    }

    hex::decode(&cleaned).map_err(|e| {
        anyhow!("Invalid 'client_mac' {mac:?}: {e}. Expected hex, e.g. \"00:11:22:33:44:55\"")
    })
}

fn send_dhcp_offer_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcp_offer".to_string(),
        description:
            "Answer a DISCOVER with a DHCP OFFER proposing an address and its network configuration. The server fills in the transaction id, the client's hardware address, the relay address and the broadcast flag from the request being answered, so you only supply the configuration below. The client will normally follow up with a REQUEST for the same address, which you answer with send_dhcp_ack."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "offered_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Address being offered, dotted-quad, e.g. '192.168.1.100'. Goes in the yiaddr field"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "server_ip".to_string(),
                type_hint: "string".to_string(),
                description: "This DHCP server's own address. Used for both siaddr and the Server Identifier option (54), which the client quotes in its REQUEST. Default '0.0.0.0'".to_string(),
                required: false,
            },
            Parameter {
                name: "subnet_mask".to_string(),
                type_hint: "string".to_string(),
                description: "Subnet mask for the offered address, e.g. '255.255.255.0' (option 1)".to_string(),
                required: false,
            },
            Parameter {
                name: "router".to_string(),
                type_hint: "string".to_string(),
                description: "Default gateway the client should use, e.g. '192.168.1.1' (option 3)".to_string(),
                required: false,
            },
            Parameter {
                name: "dns_servers".to_string(),
                type_hint: "array of strings".to_string(),
                description: "DNS resolvers in preference order, e.g. ['8.8.8.8', '8.8.4.4'] (option 6). Every entry must be dotted-quad IPv4".to_string(),
                required: false,
            },
            Parameter {
                name: "domain_name".to_string(),
                type_hint: "string".to_string(),
                description: "DNS search domain, e.g. 'lan.example.com' (option 15)".to_string(),
                required: false,
            },
            Parameter {
                name: "lease_time".to_string(),
                type_hint: "number".to_string(),
                description: "Lease duration in seconds (option 51). Default 86400 (24 hours)".to_string(),
                required: false,
            },
            Parameter {
                name: "gateway_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Relay agent address (giaddr). Defaults to the giaddr of the request, which is what a relayed client needs - only set it if you are deliberately redirecting the reply".to_string(),
                required: false,
            },
            Parameter {
                name: "xid".to_string(),
                type_hint: "number".to_string(),
                description: "Transaction id to echo. Omit it: the server reuses the xid of the request being answered. Only set it (to the 'xid' from the dhcp_request event) if you are constructing a reply out of band - a client discards any reply whose xid does not match its request".to_string(),
                required: false,
            },
            Parameter {
                name: "client_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Hardware address to address the reply to, written either as '001122334455' or '00:11:22:33:44:55'. Omit it: the server reuses the request's chaddr".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dhcp_offer",
            "offered_ip": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "router": "192.168.1.1",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "lease_time": 86400
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCP OFFER {offered_ip}")
                .with_debug("DHCP send_dhcp_offer: IP={offered_ip}, lease={lease_time}s"),
        ),
    }
}

fn send_dhcp_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcp_ack".to_string(),
        description:
            "Answer a REQUEST with a DHCP ACK, confirming the address and its configuration. Same fields as send_dhcp_offer; the transaction id, hardware address, relay address and broadcast flag are taken from the request being answered. Send the same configuration you offered - a client that gets different values may restart the exchange."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "assigned_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Address being confirmed, dotted-quad, e.g. '192.168.1.100'. Normally the same address you offered. Goes in the yiaddr field"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "server_ip".to_string(),
                type_hint: "string".to_string(),
                description: "This DHCP server's own address (siaddr and Server Identifier option 54). Default '0.0.0.0'".to_string(),
                required: false,
            },
            Parameter {
                name: "subnet_mask".to_string(),
                type_hint: "string".to_string(),
                description: "Subnet mask, e.g. '255.255.255.0' (option 1)".to_string(),
                required: false,
            },
            Parameter {
                name: "router".to_string(),
                type_hint: "string".to_string(),
                description: "Default gateway, e.g. '192.168.1.1' (option 3)".to_string(),
                required: false,
            },
            Parameter {
                name: "dns_servers".to_string(),
                type_hint: "array of strings".to_string(),
                description: "DNS resolvers in preference order, e.g. ['8.8.8.8', '8.8.4.4'] (option 6). Every entry must be dotted-quad IPv4".to_string(),
                required: false,
            },
            Parameter {
                name: "domain_name".to_string(),
                type_hint: "string".to_string(),
                description: "DNS search domain, e.g. 'lan.example.com' (option 15)".to_string(),
                required: false,
            },
            Parameter {
                name: "lease_time".to_string(),
                type_hint: "number".to_string(),
                description: "Lease duration in seconds (option 51). Default 86400 (24 hours)".to_string(),
                required: false,
            },
            Parameter {
                name: "gateway_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Relay agent address (giaddr). Defaults to the giaddr of the request".to_string(),
                required: false,
            },
            Parameter {
                name: "xid".to_string(),
                type_hint: "number".to_string(),
                description: "Transaction id to echo. Omit it - the server reuses the request's xid, and a mismatch makes the client ignore the reply".to_string(),
                required: false,
            },
            Parameter {
                name: "client_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Hardware address to address the reply to, written either as '001122334455' or '00:11:22:33:44:55'. Omit it: the server reuses the request's chaddr".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dhcp_ack",
            "assigned_ip": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "router": "192.168.1.1",
            "dns_servers": ["8.8.8.8"],
            "lease_time": 86400
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCP ACK {assigned_ip}")
                .with_debug("DHCP send_dhcp_ack: IP={assigned_ip}, lease={lease_time}s"),
        ),
    }
}

fn send_dhcp_nak_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcp_nak".to_string(),
        description: "Reject a REQUEST with a DHCP NAK: the address the client asked for is not valid here, and it should start over with a DISCOVER. Use this to refuse a client, or when a client renews a lease that no longer applies. Transaction id and hardware address are echoed from the request.".to_string(),
        parameters: vec![
            Parameter {
                name: "server_ip".to_string(),
                type_hint: "string".to_string(),
                description: "This DHCP server's own address (Server Identifier option 54). Default '0.0.0.0'".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable reason sent in option 56, e.g. 'Unauthorized device'. Some clients log it".to_string(),
                required: false,
            },
            Parameter {
                name: "gateway_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Relay agent address (giaddr). Defaults to the giaddr of the request".to_string(),
                required: false,
            },
            Parameter {
                name: "xid".to_string(),
                type_hint: "number".to_string(),
                description: "Transaction id to echo. Omit it - the server reuses the request's xid".to_string(),
                required: false,
            },
            Parameter {
                name: "client_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Hardware address to address the reply to. Omit it: the server reuses the request's chaddr".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dhcp_nak",
            "message": "Requested IP address not available"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCP NAK: {message}")
                .with_debug("DHCP send_dhcp_nak: {message}"),
        ),
    }
}

fn send_dhcp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dhcp_response".to_string(),
        description: "Escape hatch: send a complete DHCP packet you assembled yourself, byte for byte. Prefer send_dhcp_offer / send_dhcp_ack / send_dhcp_nak - they echo the transaction id and hardware address and encode options correctly. Use this only for options those actions cannot express, or for deliberately malformed packets. Nothing is echoed for you here: if the xid at bytes 4-7 does not match the request, the client ignores the packet.".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The whole packet as hex, two digits per byte (spaces and ':' are allowed and ignored). Decoded strictly as hex - it is never sent as text - and must be at least 236 bytes".to_string(),
            required: true,
        }],
        // A complete, decodable DHCPOFFER: the 236-byte BOOTP base (op=2 htype=1
        // hlen=6, xid=0x3903f326, yiaddr=192.168.1.100, siaddr=192.168.1.1,
        // chaddr=00:11:22:33:44:55), the RFC 2131 magic cookie 63825363, then
        // options 53 (OFFER), 54 (server id), 1 (mask), 3 (router), 51 (lease) and
        // 255 (end). Written out in full on purpose - the shortest packet this
        // action accepts is 236 bytes, so an abbreviated example is one the
        // executor rejects.
        example: json!({
            "type": "send_dhcp_response",
            "data": "020106003903f3260000000000000000c0a80164c0a80101000000000011223344550000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     0000638253633501023604c0a801010104ffffff000304c0a80101330400015180ff"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHCP raw response ({data_len}B)")
                .with_debug("DHCP send_dhcp_response: {data_len} bytes"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Ignore this DHCP request without sending a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DHCP request ignored")
                .with_debug("DHCP ignore_request"),
        ),
    }
}

// ============================================================================
// DHCP Event Type Constants
// ============================================================================

pub static DHCP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcp_request",
        "DHCP client sent a message. Normal flow: Discover -> you send an offer, then Request -> you send an ack",
        json!({
            "type": "send_dhcp_offer",
            "offered_ip": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "router": "192.168.1.1",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "lease_time": 86400
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "DHCP message type, capitalised exactly like this: 'Discover', 'Request', 'Inform', 'Release', 'Decline'. Compare case-sensitively - it is 'Discover', not 'DISCOVER'".to_string(),
            required: true,
        },
        Parameter {
            name: "client_mac".to_string(),
            type_hint: "string".to_string(),
            description: "Client hardware address as lower-case hex with no separators, e.g. '001122334455' for the MAC written 00:11:22:33:44:55. Match on this exact form to give a known machine a fixed address".to_string(),
            required: true,
        },
        Parameter {
            name: "requested_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Address the client asked for in option 50, if it named one. Absent otherwise".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Address the client already holds (ciaddr), '0.0.0.0' when it has none yet. Non-zero in a renewal".to_string(),
            required: false,
        },
        Parameter {
            name: "xid".to_string(),
            type_hint: "number".to_string(),
            description: "Transaction id the client picked at random. The offer/ack/nak actions echo it automatically; you only need it if you build the reply with send_dhcp_response".to_string(),
            required: false,
        },
        Parameter {
            name: "gateway_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Relay agent address the request passed through (giaddr), '0.0.0.0' if the client is on this link. Echoed automatically in replies".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_dhcp_offer_action(),
        send_dhcp_ack_action(),
        send_dhcp_nak_action(),
        send_dhcp_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DHCP {message_type} from {client_mac}")
            .with_debug("DHCP {message_type}: MAC={client_mac}, requested_ip={requested_ip}")
            .with_trace("DHCP request: {json_pretty(.)}"),
    )
});

pub fn get_dhcp_event_types() -> Vec<EventType> {
    vec![DHCP_REQUEST_EVENT.clone()]
}
