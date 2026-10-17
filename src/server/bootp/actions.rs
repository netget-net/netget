//! BOOTP protocol actions implementation

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

pub struct BootpProtocol {
    request_context: std::sync::Arc<std::sync::Mutex<Option<BootpRequestContext>>>,
}

#[derive(Clone)]
pub struct BootpRequestContext {
    pub xid: u32,         // Transaction ID
    pub chaddr: Vec<u8>,  // Client MAC address
    pub op: v4::Opcode,   // Operation code (BootRequest/BootReply)
    pub ciaddr: Ipv4Addr, // Client IP address
    pub giaddr: Ipv4Addr, // Gateway IP address (for relay)
    pub sname: String,    // Server host name
    pub file: String,     // Boot file name
}

impl BootpProtocol {
    pub fn new() -> Self {
        Self {
            request_context: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn set_request_context(&self, context: BootpRequestContext) {
        *self
            .request_context
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(context);
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BootpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_bootp_reply_action(),
            send_bootp_response_action(),
            ignore_request_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "BOOTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_bootp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BOOTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bootp", "bootstrap"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            // Deliberately silent: BOOTP has no error reply: a BOOTREPLY is an offer of an
            // address and a claim to be the boot server.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(67))
            .well_known_udp_port(67)
            .implementation("dhcproto v0.12 for parsing (BOOTP format)")
            .llm_control("BOOTREQUEST→BOOTREPLY flow + boot file location")
            .e2e_testing("Manual BOOTP packet construction - 3 LLM calls")
            .notes("Bootstrap Protocol (RFC 951) - DHCP predecessor")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BOOTP server for diskless workstation boot configuration"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a BOOTP server on port 67"
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
                "base_stack": "bootp",
                "instruction": "BOOTP server for PXE boot, assign IPs from 192.168.1.100, boot file 'boot/pxeboot.n12'"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 67,
                "base_stack": "bootp",
                "event_handlers": [{
                    "event_pattern": "bootp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle BOOTP request\nif event.get('op_code') == 'BootRequest':\n    respond([{'type': 'send_bootp_reply', 'assigned_ip': '192.168.1.100', 'server_ip': '192.168.1.1', 'boot_file': 'boot/pxeboot.n12', 'server_hostname': 'bootserver.local'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 67,
                "base_stack": "bootp",
                "event_handlers": [{
                    "event_pattern": "bootp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_bootp_reply",
                            "assigned_ip": "192.168.1.100",
                            "server_ip": "192.168.1.1",
                            "boot_file": "boot/pxeboot.n12"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for BootpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::bootp::BootpServer;
            BootpServer::spawn_with_llm_actions(
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
            "send_bootp_reply" => self.execute_send_bootp_reply(action),
            "send_bootp_response" => self.execute_send_bootp_response(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown BOOTP action: {}", action_type)),
        }
    }
}

impl BootpProtocol {
    fn execute_send_bootp_reply(&self, action: serde_json::Value) -> Result<ActionResult> {
        let context = self
            .request_context
            .lock()
            .map_err(|_| anyhow!("BOOTP request context lock was poisoned"))?
            .clone();

        // Transaction ID: an explicit 'xid' in the action wins, otherwise echo the one
        // parsed from this request. A BOOTP client silently discards a reply whose xid
        // does not match the request it sent, so getting this wrong looks like a timeout.
        let xid = match action.get("xid") {
            Some(v) => parse_xid(v)?,
            None => context.as_ref().map(|c| c.xid).ok_or_else(|| {
                anyhow!(
                    "No BOOTP request context available and no 'xid' given: cannot build a reply \
                     the client will accept. Pass the 'xid' from the bootp_request event."
                )
            })?,
        };

        // Client hardware address, same rule: explicit wins, else echo the request's.
        let chaddr = match action.get("client_mac").and_then(|v| v.as_str()) {
            Some(mac) => parse_mac(mac)?,
            None => context.as_ref().map(|c| c.chaddr.clone()).ok_or_else(|| {
                anyhow!(
                    "No BOOTP request context available and no 'client_mac' given. Pass the \
                     'client_mac' from the bootp_request event."
                )
            })?,
        };

        // Extract parameters from action
        let assigned_ip = parse_ipv4(&action, "assigned_ip")?
            .ok_or_else(|| anyhow!("Missing 'assigned_ip' parameter"))?;

        let server_ip = parse_ipv4(&action, "server_ip")?.unwrap_or(Ipv4Addr::UNSPECIFIED);

        let boot_file = action
            .get("boot_file")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let server_hostname = action
            .get("server_hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // dhcproto asserts on over-long values, which would panic the request task.
        if boot_file.len() > 128 {
            return Err(anyhow!(
                "'boot_file' is {} bytes; the BOOTP file field holds at most 128",
                boot_file.len()
            ));
        }
        if server_hostname.len() > 64 {
            return Err(anyhow!(
                "'server_hostname' is {} bytes; the BOOTP sname field holds at most 64",
                server_hostname.len()
            ));
        }

        // Relay address: default to the giaddr the request arrived with, so a reply routed
        // through a relay agent still finds its way back.
        let gateway_ip = parse_ipv4(&action, "gateway_ip")?.unwrap_or_else(|| {
            context
                .as_ref()
                .map(|c| c.giaddr)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        });

        // Build BOOTP REPLY message
        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootReply)
            .set_xid(xid)
            .set_flags(v4::Flags::default())
            .set_yiaddr(assigned_ip)
            .set_siaddr(server_ip)
            .set_giaddr(gateway_ip)
            .set_chaddr(&chaddr);

        // Set boot file name if provided
        if !boot_file.is_empty() {
            msg.set_fname_str(boot_file);
        }

        // Set server hostname if provided
        if !server_hostname.is_empty() {
            msg.set_sname_str(server_hostname);
        }

        // Encode to bytes
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        msg.encode(&mut encoder)?;

        Ok(ActionResult::Output(buf))
    }

    fn execute_send_bootp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        let bytes = decode_hex_packet(data)?;

        if bytes.len() < 236 {
            return Err(anyhow!(
                "'data' decodes to {} bytes; a BOOTP packet is at least 236 bytes (300 with the \
                 options field). Prefer send_bootp_reply, which builds a well-formed packet for you.",
                bytes.len()
            ));
        }

        Ok(ActionResult::Output(bytes))
    }
}

/// Decode the `data` field of a raw-packet action.
///
/// The parameter is documented as hex, so it is decoded strictly as hex: an unparseable
/// value is an error rather than being silently put on the wire as ASCII, which would
/// produce a packet no BOOTP client can read. Whitespace and `:` separators are tolerated
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
            anyhow!("'xid' {n} does not fit in the 32-bit BOOTP transaction id field")
        });
    }
    if let Some(s) = value.as_str() {
        let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        return u32::from_str_radix(trimmed, 16).map_err(|e| {
            anyhow!("Invalid 'xid' {s:?}: {e}. Expected a number, or hex like \"0x6395a3e3\"")
        });
    }
    Err(anyhow!(
        "Invalid 'xid': expected the number from the bootp_request event, got {value}"
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

fn send_bootp_reply_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bootp_reply".to_string(),
        description:
            "Send a BOOTREPLY answering the client's BOOTREQUEST: assigns an IP address and points the client at its boot file. The server fills in the transaction id and the client's hardware address from the request it is answering, so you normally only supply the addresses and file names below."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "assigned_ip".to_string(),
                type_hint: "string".to_string(),
                description: "IPv4 address to give the client, dotted-quad, e.g. '192.168.1.100'. Goes in the yiaddr field"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "server_ip".to_string(),
                type_hint: "string".to_string(),
                description: "IPv4 address of the boot/TFTP server holding 'boot_file' (siaddr field). Default '0.0.0.0'".to_string(),
                required: false,
            },
            Parameter {
                name: "boot_file".to_string(),
                type_hint: "string".to_string(),
                description: "Path of the boot image on the TFTP server, e.g. 'boot/pxeboot.n12'. At most 128 characters".to_string(),
                required: false,
            },
            Parameter {
                name: "server_hostname".to_string(),
                type_hint: "string".to_string(),
                description: "Name of the boot server, e.g. 'bootserver.local'. At most 64 characters".to_string(),
                required: false,
            },
            Parameter {
                name: "gateway_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Relay agent address (giaddr). Defaults to the giaddr the request arrived with, which is what a relayed client needs - only set this if you are deliberately redirecting the reply".to_string(),
                required: false,
            },
            Parameter {
                name: "xid".to_string(),
                type_hint: "number".to_string(),
                description: "Transaction id to echo. Omit it: the server reuses the xid of the request being answered. Only set it (to the 'xid' from the bootp_request event) if you are constructing a reply out of band - a client discards any reply whose xid does not match its request".to_string(),
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
            "type": "send_bootp_reply",
            "assigned_ip": "192.168.1.100",
            "server_ip": "192.168.1.1",
            "boot_file": "boot/pxeboot.n12",
            "server_hostname": "bootserver.local"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BOOTP reply IP={assigned_ip}")
                .with_debug("BOOTP send_bootp_reply: ip={assigned_ip} server={server_ip} file={boot_file}"),
        ),
    }
}

fn send_bootp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bootp_response".to_string(),
        description: "Escape hatch: send a complete BOOTP packet you assembled yourself, byte for byte. Prefer send_bootp_reply, which fills in the transaction id, hardware address and header fields correctly; use this only for malformed or non-standard packets that send_bootp_reply cannot express. Nothing is echoed for you here - if the xid at bytes 4-7 does not match the request, the client ignores the packet.".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The whole packet as hex, two digits per byte (spaces and ':' are allowed and ignored). Decoded strictly as hex - it is never sent as text - and must be at least 236 bytes".to_string(),
            required: true,
        }],
        // A complete, decodable 236-byte BOOTREPLY: op=2 htype=1 hlen=6 hops=0,
        // xid=0x3903f326, yiaddr=192.168.1.100, siaddr=192.168.1.1,
        // chaddr=00:11:22:33:44:55, empty sname and file. Written out in full on
        // purpose - the shortest packet this action accepts is 236 bytes, so an
        // abbreviated example is one the executor rejects.
        example: json!({
            "type": "send_bootp_response",
            "data": "020106003903f3260000000000000000c0a80164c0a80101000000000011223344550000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     000000000000000000000000000000000000000000000000000000000000000000000000000000\
                     0000"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BOOTP raw response ({data_len}B)")
                .with_debug("BOOTP send_bootp_response: data_len={data_len}"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Ignore this BOOTP request without sending a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BOOTP ignored")
                .with_debug("BOOTP ignore_request"),
        ),
    }
}

// ============================================================================
// BOOTP Event Type Constants
// ============================================================================

pub static BOOTP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bootp_request",
        "BOOTP client sent a BOOTREQUEST (requesting IP and boot configuration)",
        json!({
            "type": "send_bootp_reply",
            "assigned_ip": "192.168.1.100",
            "server_ip": "192.168.1.1",
            "boot_file": "boot/pxeboot.n12"
        })
    )
    .with_parameters(vec![
        Parameter {
            name: "op_code".to_string(),
            type_hint: "string".to_string(),
            description: "Operation code of the packet received: 'BootRequest' for a client asking to boot, 'BootReply' if some other server's reply reached this port".to_string(),
            required: true,
        },
        Parameter {
            name: "client_mac".to_string(),
            type_hint: "string".to_string(),
            description: "Client hardware address as lower-case hex with no separators, e.g. '001122334455' for the MAC written 00:11:22:33:44:55. Match on this exact form to give a known machine a fixed address".to_string(),
            required: true,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Address the client already holds (ciaddr), '0.0.0.0' when it has none yet".to_string(),
            required: false,
        },
        Parameter {
            name: "xid".to_string(),
            type_hint: "number".to_string(),
            description: "Transaction id the client picked at random. send_bootp_reply echoes it automatically; you only need it if you build the reply with send_bootp_response".to_string(),
            required: false,
        },
        Parameter {
            name: "gateway_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Relay agent address the request passed through (giaddr), '0.0.0.0' if the client is on this link. Echoed automatically in the reply".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BOOTP {op_code} from {client_mac}")
            .with_debug("BOOTP {op_code} from MAC {client_mac}, IP {client_ip}")
            .with_trace("BOOTP: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_bootp_reply_action(),
        send_bootp_response_action(),
        ignore_request_action(),
    ])
});

pub fn get_bootp_event_types() -> Vec<EventType> {
    vec![BOOTP_REQUEST_EVENT.clone()]
}
