//! TURN protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub struct TurnProtocol;

impl TurnProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TurnProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TurnProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty. allocate_relay_address and revoke_allocation were
        // advertised here but execute_action had no arm for either, so calling
        // one only ever produced "Unknown TURN action".
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_turn_allocate_response_action(),
            send_turn_refresh_response_action(),
            send_turn_create_permission_response_action(),
            send_turn_channel_bind_response_action(),
            send_turn_error_response_action(),
            ignore_request_action(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "relay_ip".to_string(),
                type_hint: "string".to_string(),
                description:
                    "IP address advertised to clients in XOR-RELAYED-ADDRESS. Relay sockets \
                     are always bound to the server's own listen address; set this only when \
                     clients reach the relay at a different address (NAT, port forwarding). \
                     Default: the server's listen address."
                        .to_string(),
                required: false,
                example: json!("203.0.113.5"),
                default: None,
            },
            ParameterDefinition {
                name: "peer_scope".to_string(),
                type_hint: "string".to_string(),
                description: "Which peer addresses this relay may be pointed at. \"any\" \
                              (default) places no restriction — a client can be permitted to \
                              relay to 127.0.0.1 or to an RFC 1918 address, which is a UDP \
                              path into whatever the operator's host can reach. That is the \
                              right default for a honeypot and on loopback, and it is the \
                              wrong one anywhere else: set \"public\" to refuse loopback, \
                              private, link-local (including the 169.254.169.254 metadata \
                              address), multicast, broadcast and unspecified destinations."
                    .to_string(),
                required: false,
                example: json!("public"),
                default: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "TURN"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_turn_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>TURN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["turn"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: a STUN error response (508 when overloaded, 500 otherwise); no
            // allocation or permission is ever granted on that path.
            .answers_on_failure()
            .state(DevelopmentState::Experimental)
            .well_known_udp_port(3478)
            .implementation("Manual TURN protocol (RFC 8656) with a real UDP relay: every granted allocation binds its own socket and forwards traffic both ways")
            .llm_control("Whether to grant Allocate/Refresh/CreatePermission/ChannelBind, the lifetime, and which peers are permitted (policy, LLM). With no policy configured the server grants nothing with no LLM call. The data plane never calls the LLM")
            .e2e_testing("Mocked E2E relays a payload between two real UDP peers in both directions (tests/server/turn/e2e_test.rs)")
            .notes("THIS IS AN OPEN RELAY WHEN A POLICY GRANTS. Read the next three sentences before exposing it. (1) There is NO AUTHENTICATION: REALM, NONCE and MESSAGE-INTEGRITY are not implemented and no action can add them, so 'who may allocate' is entirely whatever answers turn_allocate_request — an instruction like 'grant allocations' means any host that can reach the port gets a relay, with no identity at all. (2) The DEFAULT DESTINATION SCOPE IS UNRESTRICTED (peer_scope=any): a permitted client can be relayed to 127.0.0.1, to RFC 1918 space or to 169.254.169.254, which is a UDP path from a stranger into whatever this host can reach, with the answers relayed back. That default is deliberate — this protocol exists to be pointed at by things under test, and a honeypot TURN server that refuses private destinations is not one — but set the peer_scope=public startup parameter anywhere it is not what you want, and it is NOT what you want on a reachable interface. (3) The only limits that do not depend on the model are a 256-allocation cap, a 3600s maximum lifetime and RFC 8656's fixed permission/channel lifetimes; there is no per-source rate limit and no cap on relayed bytes. With NO operator policy (no instruction, no handler) every control request is fail-closed — grant nothing, no LLM round-trip, no reply — which is why an unconfigured TURN server is safe and a configured one is exactly as safe as its policy. Mechanics: relays UDP only (no TCP allocations, no REQUESTED-ADDRESS-FAMILY, no reservation tokens or EVEN-PORT); Send indications and ChannelData go out the allocation's relay socket to permitted peers and peer traffic comes back as Data indications or ChannelData; the relay address is chosen by NetGet (the socket it actually bound), not by the model, and an action naming any other address is refused with 508. The ack-packet framing and the relay data plane are mechanical and never call the LLM")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "TURN relay server for NAT traversal"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a TURN relay server on port 3478 with 10 minute allocations"
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: grant every allocation and refresh, echoing the
        // server-reserved relay address and the client's transaction id, no LLM
        // call. One script handles both events.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
et = data["event_type_id"]
if et == "turn_allocate_request":
    actions = [{"type": "send_turn_allocate_response",
                "transaction_id": event.get("transaction_id"),
                "relay_address": event.get("relay_address"),
                "lifetime_seconds": 600}]
elif et == "turn_refresh_request":
    actions = [{"type": "send_turn_refresh_response",
                "transaction_id": event.get("transaction_id"),
                "lifetime_seconds": 600}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "turn",
                "instruction": "TURN relay server for NAT traversal. Allocate relay addresses on request. Grant 600 second lifetimes for allocations."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "turn",
                "event_handlers": [{
                    "event_pattern": "turn_allocate_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }, {
                    "event_pattern": "turn_refresh_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "turn",
                "event_handlers": [{
                    "event_pattern": "turn_allocate_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_turn_allocate_response",
                            "relay_address": "{{event.relay_address}}",
                            "client_address": "{{event.peer_addr}}",
                            "transaction_id": "{{event.transaction_id}}",
                            "lifetime_seconds": 600
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TurnProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let relay_ip = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("relay_ip"))
                .transpose()?
                .flatten();

            let peer_scope = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("peer_scope"))
                .transpose()?
                .flatten();
            let peer_scope = crate::server::turn::PeerScope::parse(peer_scope.as_deref())?;

            use crate::server::turn::TurnServer;
            TurnServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                relay_ip,
                peer_scope,
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
            "send_turn_allocate_response" => self.execute_send_allocate_response(action),
            "send_turn_refresh_response" => self.execute_send_refresh_response(action),
            "send_turn_create_permission_response" => self.execute_send_permission_response(action),
            "send_turn_channel_bind_response" => self.execute_send_channel_bind_response(action),
            "send_turn_error_response" => self.execute_send_error_response(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown TURN action: {}", action_type)),
        }
    }
}

impl TurnProtocol {
    /// Read and validate the `transaction_id` field shared by every response action.
    fn transaction_id_from(action: &serde_json::Value) -> Result<[u8; 12]> {
        let transaction_id = action
            .get("transaction_id")
            .and_then(|v| v.as_str())
            .context("Missing 'transaction_id' field")?;

        let bytes = hex::decode(transaction_id).context("Invalid transaction_id hex")?;

        let bytes: [u8; 12] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Transaction ID must be 12 bytes (24 hex characters)"))?;

        Ok(bytes)
    }

    /// Execute TURN allocate response
    fn execute_send_allocate_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let relay_address = action
            .get("relay_address")
            .and_then(|v| v.as_str())
            .context("Missing 'relay_address' field")?;

        let transaction_id = Self::transaction_id_from(&action)?;

        let lifetime_seconds = action
            .get("lifetime_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(600) as u32;

        // Parse relay address. The server loop checks this against the socket
        // it actually bound and refuses the allocation if they differ.
        let relay_addr: std::net::SocketAddr = relay_address
            .parse()
            .context("Invalid relay_address format")?;

        // Optional XOR-MAPPED-ADDRESS (RFC 8656 section 6.3): the client's own
        // reflexive address, echoed from the event's peer_addr.
        let client_addr = match action.get("client_address").and_then(|v| v.as_str()) {
            Some(addr) => Some(
                addr.parse::<std::net::SocketAddr>()
                    .context("Invalid client_address format")?,
            ),
            None => None,
        };

        // Note: allocation tracking is handled in the TURN server's main loop,
        // which owns the relay socket this response advertises.
        let packet = Self::build_allocate_response(
            &transaction_id,
            relay_addr,
            lifetime_seconds,
            client_addr,
        )?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute TURN refresh response
    fn execute_send_refresh_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = Self::transaction_id_from(&action)?;

        let lifetime_seconds = action
            .get("lifetime_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(600) as u32;

        let packet = Self::build_refresh_response(&transaction_id, lifetime_seconds)?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute TURN create permission response
    fn execute_send_permission_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = Self::transaction_id_from(&action)?;

        // The permitted peers themselves are applied by the server loop, which
        // owns the allocation table; this only builds the acknowledgement.
        let packet = Self::build_permission_response(&transaction_id)?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute TURN channel bind response
    fn execute_send_channel_bind_response(
        &self,
        action: serde_json::Value,
    ) -> Result<ActionResult> {
        let transaction_id = Self::transaction_id_from(&action)?;

        // Channel number and peer come from the request; the server loop binds
        // them when it sees this action.
        let packet = Self::build_success_response(&transaction_id, 9)?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute TURN error response
    fn execute_send_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Range-check before narrowing: `65536 as u16` is 0, which encodes an ERROR-CODE
        // attribute with class 0 - not an error at all. RFC 8489 section 14.8 encodes the
        // code as a class/number pair, so only 300-699 is representable.
        let error_code_raw = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(400);
        if !(300..700).contains(&error_code_raw) {
            return Err(anyhow::anyhow!(
                "error_code {error_code_raw} is outside the 300-699 range RFC 8489 section \
                 14.8 encodes as a class/number pair"
            ));
        }
        let error_code = error_code_raw as u16;

        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Bad Request");

        let transaction_id = Self::transaction_id_from(&action)?;

        // The error response must carry the same method as the request it
        // answers; hardcoding Allocate meant a Refresh or CreatePermission
        // failure came back as an Allocate error, which clients ignore.
        let method_name = action
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("allocate");
        let method = match method_name.to_ascii_lowercase().as_str() {
            "allocate" => 3,
            "refresh" => 4,
            "create_permission" | "createpermission" => 8,
            "channel_bind" | "channelbind" => 9,
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown 'method' value {other:?}. Valid values are \"allocate\", \
                     \"refresh\", \"create_permission\" and \"channel_bind\"."
                ))
            }
        };

        let packet = Self::build_error_response(&transaction_id, method, error_code, reason)?;

        Ok(ActionResult::Output(packet))
    }

    /// STUN message type for a (method, class) pair (RFC 8489 section 5).
    fn message_type(method: u16, class: u16) -> u16 {
        let class_bits = ((class & 0x2) << 7) | ((class & 0x1) << 4);
        (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | class_bits
    }

    /// Start a STUN message: type, placeholder length, magic cookie, transaction ID.
    fn start_message(message_type: u16, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(32);
        packet.extend_from_slice(&message_type.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        packet.extend_from_slice(&0x2112A442u32.to_be_bytes());
        packet.extend_from_slice(transaction_id);
        packet
    }

    /// Write the attribute length into the header once all attributes are added.
    fn finish_message(packet: &mut [u8]) {
        let attributes_length = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&attributes_length.to_be_bytes());
    }

    /// Build TURN allocate response packet
    fn build_allocate_response(
        transaction_id: &[u8; 12],
        relay_addr: std::net::SocketAddr,
        lifetime_seconds: u32,
        client_addr: Option<std::net::SocketAddr>,
    ) -> Result<Vec<u8>> {
        // 0x0103 = Allocate Success Response (class 2 = success)
        let mut packet = Self::start_message(Self::message_type(3, 2), transaction_id);

        // XOR-RELAYED-ADDRESS (0x0016)
        Self::add_xor_address_attribute(&mut packet, 0x0016, relay_addr, transaction_id)?;

        // XOR-MAPPED-ADDRESS (0x0020), when the caller echoed the client address
        if let Some(client_addr) = client_addr {
            Self::add_xor_address_attribute(&mut packet, 0x0020, client_addr, transaction_id)?;
        }

        Self::add_lifetime_attribute(&mut packet, lifetime_seconds)?;
        Self::add_software_attribute(&mut packet, "NetGet TURN/1.0")?;

        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Build TURN refresh response packet
    fn build_refresh_response(transaction_id: &[u8; 12], lifetime_seconds: u32) -> Result<Vec<u8>> {
        // 0x0104 = Refresh Success Response
        let mut packet = Self::start_message(Self::message_type(4, 2), transaction_id);
        Self::add_lifetime_attribute(&mut packet, lifetime_seconds)?;
        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Build TURN create permission response packet
    fn build_permission_response(transaction_id: &[u8; 12]) -> Result<Vec<u8>> {
        Self::build_success_response(transaction_id, 8)
    }

    /// Build a success response carrying no method-specific attributes.
    fn build_success_response(transaction_id: &[u8; 12], method: u16) -> Result<Vec<u8>> {
        let mut packet = Self::start_message(Self::message_type(method, 2), transaction_id);
        Self::add_software_attribute(&mut packet, "NetGet TURN/1.0")?;
        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Build a STUN Binding success response (XOR-MAPPED-ADDRESS of the client).
    pub(crate) fn build_binding_response(
        transaction_id: &[u8; 12],
        client_addr: std::net::SocketAddr,
    ) -> Result<Vec<u8>> {
        let mut packet = Self::start_message(Self::message_type(1, 2), transaction_id);
        Self::add_xor_address_attribute(&mut packet, 0x0020, client_addr, transaction_id)?;
        Self::add_software_attribute(&mut packet, "NetGet TURN/1.0")?;
        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Build a Data indication carrying relayed peer traffic to the client
    /// (RFC 8656 section 11.3). Sent by the relay task, not by an action: the
    /// data plane must not cost an LLM round-trip per packet.
    pub(crate) fn build_data_indication(
        peer_addr: std::net::SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        // Indications carry their own transaction ID; nothing correlates them.
        let transaction_id: [u8; 12] = rand::random();

        // 0x0017 = Data Indication (method 7, class 1 = indication)
        let mut packet = Self::start_message(Self::message_type(7, 1), &transaction_id);

        // XOR-PEER-ADDRESS (0x0012)
        Self::add_xor_address_attribute(&mut packet, 0x0012, peer_addr, &transaction_id)?;

        // DATA (0x0013)
        packet.extend_from_slice(&0x0013u16.to_be_bytes());
        let len = u16::try_from(payload.len())
            .map_err(|_| anyhow::anyhow!("Relayed payload too large for a DATA attribute"))?;
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);
        Self::add_padding(&mut packet);

        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Build a ChannelData frame (RFC 8656 section 12.4).
    pub(crate) fn build_channel_data(channel_number: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(4 + payload.len() + 3);
        packet.extend_from_slice(&channel_number.to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(payload);
        // ChannelData over UDP need not be padded, but padding is permitted and
        // keeps the framing identical over any transport.
        Self::add_padding(&mut packet);
        packet
    }

    /// Build TURN error response packet
    pub(crate) fn build_error_response(
        transaction_id: &[u8; 12],
        method: u16,
        error_code: u16,
        reason: &str,
    ) -> Result<Vec<u8>> {
        // Class = 3 (error response)
        let mut packet = Self::start_message(Self::message_type(method, 3), transaction_id);
        Self::add_error_code_attribute(&mut packet, error_code, reason)?;
        Self::finish_message(&mut packet);
        Ok(packet)
    }

    /// Add XOR-ed address attribute (XOR-RELAYED-ADDRESS, XOR-PEER-ADDRESS, etc.)
    fn add_xor_address_attribute(
        packet: &mut Vec<u8>,
        attr_type: u16,
        addr: std::net::SocketAddr,
        transaction_id: &[u8],
    ) -> Result<()> {
        packet.extend_from_slice(&attr_type.to_be_bytes());

        let attr_start = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder

        let value_start = packet.len();

        let magic_cookie = 0x2112A442u32;

        match addr {
            std::net::SocketAddr::V4(addr_v4) => {
                packet.push(0x00); // Reserved
                packet.push(0x01); // IPv4

                // XOR port
                let xor_port = addr_v4.port() ^ (magic_cookie >> 16) as u16;
                packet.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address
                let ip_bytes = addr_v4.ip().octets();
                let magic_bytes = magic_cookie.to_be_bytes();
                for i in 0..4 {
                    packet.push(ip_bytes[i] ^ magic_bytes[i]);
                }
            }
            std::net::SocketAddr::V6(addr_v6) => {
                packet.push(0x00); // Reserved
                packet.push(0x02); // IPv6

                let xor_port = addr_v6.port() ^ (magic_cookie >> 16) as u16;
                packet.extend_from_slice(&xor_port.to_be_bytes());

                let ip_bytes = addr_v6.ip().octets();
                let magic_bytes = magic_cookie.to_be_bytes();

                for i in 0..4 {
                    packet.push(ip_bytes[i] ^ magic_bytes[i]);
                }
                for i in 0..12 {
                    packet.push(ip_bytes[i + 4] ^ transaction_id[i]);
                }
            }
        }

        let value_length = (packet.len() - value_start) as u16;
        packet[attr_start..attr_start + 2].copy_from_slice(&value_length.to_be_bytes());

        Self::add_padding(packet);
        Ok(())
    }

    /// Add LIFETIME attribute
    fn add_lifetime_attribute(packet: &mut Vec<u8>, lifetime_seconds: u32) -> Result<()> {
        // Attribute Type: 0x000D (LIFETIME)
        packet.extend_from_slice(&0x000Du16.to_be_bytes());

        // Attribute Length: 4 bytes
        packet.extend_from_slice(&4u16.to_be_bytes());

        // Lifetime value
        packet.extend_from_slice(&lifetime_seconds.to_be_bytes());

        Ok(())
    }

    /// Add SOFTWARE attribute
    fn add_software_attribute(packet: &mut Vec<u8>, software: &str) -> Result<()> {
        packet.extend_from_slice(&0x8022u16.to_be_bytes());

        let software_bytes = software.as_bytes();
        let length = software_bytes.len() as u16;

        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(software_bytes);

        Self::add_padding(packet);
        Ok(())
    }

    /// Add ERROR-CODE attribute
    fn add_error_code_attribute(packet: &mut Vec<u8>, error_code: u16, reason: &str) -> Result<()> {
        packet.extend_from_slice(&0x0009u16.to_be_bytes());

        let attr_start = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes());

        let value_start = packet.len();

        packet.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        let class = (error_code / 100) as u8;
        let number = (error_code % 100) as u8;
        packet.push(class);
        packet.push(number);
        packet.extend_from_slice(reason.as_bytes());

        let value_length = (packet.len() - value_start) as u16;
        packet[attr_start..attr_start + 2].copy_from_slice(&value_length.to_be_bytes());

        Self::add_padding(packet);
        Ok(())
    }

    /// Add padding to align to 4-byte boundary
    fn add_padding(packet: &mut Vec<u8>) {
        let remainder = packet.len() % 4;
        if remainder != 0 {
            let padding = 4 - remainder;
            packet.extend_from_slice(&vec![0u8; padding]);
        }
    }
}

// Action definitions

fn send_turn_allocate_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_turn_allocate_response".to_string(),
        description: "Grant the allocation: NetGet starts relaying on the reserved relay socket \
                      and tells the client its address"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "relay_address".to_string(),
                type_hint: "string".to_string(),
                description: "MUST be exactly the event's relay_address (a static handler writes \
                              \"{{event.relay_address}}\"; the value in the example below is only \
                              a placeholder showing the host:port shape). NetGet has already \
                              bound this UDP socket; it is the only address peer traffic can \
                              arrive on. Any other value is refused with a 508 error, because a \
                              relay address nobody listens on silently breaks the client."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Transaction ID from the request: exactly 24 hex characters \
                              (12 bytes, RFC 8489). A static handler writes \
                              \"{{event.transaction_id}}\"; an LLM answer must carry the \
                              event's actual value, because the client discards a response \
                              whose transaction ID does not match."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "client_address".to_string(),
                type_hint: "string".to_string(),
                description: "Client's own address as seen by the server, i.e. \
                              \"{{event.peer_addr}}\". Sent back as XOR-MAPPED-ADDRESS."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "lifetime_seconds".to_string(),
                type_hint: "number".to_string(),
                description: "Allocation lifetime in seconds. Default: 600, capped at 3600. The \
                              relay socket is closed when it expires."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "allocation_id".to_string(),
                type_hint: "string".to_string(),
                description: "Unique allocation identifier. Defaults to transaction_id".to_string(),
                required: false,
            },
        ],
        // Concrete values, not "{{event.…}}" placeholders: that substitution only
        // happens for static event handlers, so a model that copies the template
        // literally puts the braces on the wire and the executor refuses them.
        // Both addresses must come from the event; the transaction ID is 12 bytes.
        example: json!({
            "type": "send_turn_allocate_response",
            "relay_address": "192.0.2.10:49160",
            "client_address": "198.51.100.20:54321",
            "transaction_id": "0123456789abcdef01234567",
            "lifetime_seconds": 600
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TURN allocate {relay_address}")
                .with_debug(
                    "TURN allocate_response: relay={relay_address}, lifetime={lifetime_seconds}s",
                ),
        ),
    }
}

fn send_turn_refresh_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_turn_refresh_response".to_string(),
        description: "Send TURN refresh response to extend allocation lifetime".to_string(),
        parameters: vec![
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Transaction ID from the request: exactly 24 hex characters \
                              (12 bytes, RFC 8489). A static handler writes \
                              \"{{event.transaction_id}}\"; an LLM answer must carry the \
                              event's actual value, because the client discards a response \
                              whose transaction ID does not match."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "lifetime_seconds".to_string(),
                type_hint: "number".to_string(),
                description: "New lifetime in seconds. Default: 600".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_turn_refresh_response",
            "transaction_id": "0123456789abcdef01234567",
            "lifetime_seconds": 600
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TURN refresh ({lifetime_seconds}s)")
                .with_debug("TURN refresh_response: lifetime={lifetime_seconds}s"),
        ),
    }
}

fn send_turn_create_permission_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_turn_create_permission_response".to_string(),
        description: "Permit peers to exchange relayed traffic with this client. Only permitted \
                      peers are relayed in either direction."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Transaction ID from the request: exactly 24 hex characters \
                              (12 bytes, RFC 8489). A static handler writes \
                              \"{{event.transaction_id}}\"; an LLM answer must carry the \
                              event's actual value, because the client discards a response \
                              whose transaction ID does not match."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "peer_addresses".to_string(),
                type_hint: "array".to_string(),
                description: "Subset of the request's peer_addresses to permit, e.g. \
                              [\"198.51.100.10:5000\"]. Omit to permit every peer the request \
                              named. Addresses the request did not name are ignored. Permissions \
                              match on IP address (RFC 8656) and last 5 minutes."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_turn_create_permission_response",
            "transaction_id": "0123456789abcdef01234567"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TURN permission created")
                .with_debug("TURN create_permission_response"),
        ),
    }
}

fn send_turn_channel_bind_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_turn_channel_bind_response".to_string(),
        description: "Bind the requested channel number to the requested peer. Traffic to and \
                      from that peer is then framed as ChannelData instead of Send/Data \
                      indications, and the peer is permitted."
            .to_string(),
        parameters: vec![Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "Transaction ID from the request: exactly 24 hex characters \
                          (12 bytes, RFC 8489). A static handler writes \
                          \"{{event.transaction_id}}\"; an LLM answer must carry the event's \
                          actual value, because the client discards a response whose \
                          transaction ID does not match."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_turn_channel_bind_response",
            "transaction_id": "0123456789abcdef01234567"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TURN channel bound")
                .with_debug("TURN channel_bind_response"),
        ),
    }
}

fn send_turn_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_turn_error_response".to_string(),
        description: "Send TURN error response".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "TURN error code (e.g., 400, 401, 403, 508)".to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Error reason phrase".to_string(),
                required: true,
            },
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Transaction ID from the request, hex-encoded (24 hex chars). Must match the request or the client will discard the response.".to_string(),
                required: true,
            },
            Parameter {
                name: "method".to_string(),
                type_hint: "string".to_string(),
                description: "Which request this error answers: \"allocate\" (default), \"refresh\", \"create_permission\" or \"channel_bind\". Must match the request's method or the client ignores the error.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_turn_error_response",
            "error_code": 508,
            "reason": "Insufficient Capacity",
            "transaction_id": "0123456789abcdef01234567",
            "method": "allocate"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TURN error {error_code}: {reason}")
                .with_debug("TURN error_response: {error_code} {reason}"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Silently ignore the TURN request (no response)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("TURN request ignored")
                .with_debug("TURN ignore_request"),
        ),
    }
}

// Event types

/// Fields every TURN event carries.
fn common_event_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "STUN/TURN transaction ID from the request, hex-encoded (24 hex chars = 12 bytes). MUST be copied into the response: clients discard any reply whose transaction ID differs from the request they sent.".to_string(),
            required: true,
        },
        Parameter {
            // The name says "peer" and the value is the *client*. Renaming it would break
            // every handler interpolating {{event.peer_addr}}, so the description has to carry
            // the whole warning - and it must, because on turn_create_permission_request this
            // field sits directly beside `peer_addresses`, which really is the peer list. A
            // model asked to permit "the peer" reads the singular, more obvious-looking name
            // and permits the client's own address instead of the one it was asked about.
            name: "peer_addr".to_string(),
            type_hint: "string".to_string(),
            description: "The CLIENT's IP:port as seen by the server - despite the name, this is never a peer to relay to. On a create-permission or channel-bind request, the peer the client is asking about is in `peer_addresses`, not here."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Server's listening IP:port".to_string(),
            required: true,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Decoded TURN message type, e.g. \"AllocateRequest\"".to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_received".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the received datagram in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "existing_allocations".to_string(),
            type_hint: "array".to_string(),
            description: "Allocations currently held by this client: allocation_id, relay_address, lifetime_seconds, expires_in_seconds, permitted_peers, channels".to_string(),
            required: true,
        },
    ]
}

fn with_extra(mut params: Vec<Parameter>, extra: Vec<Parameter>) -> Vec<Parameter> {
    params.extend(extra);
    params
}

pub static TURN_ALLOCATE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_allocate_request",
        "TURN allocate request received from client",
        // Concrete values, not "{{event.…}}" placeholders: that substitution only happens
        // for a static event handler, so a model that copies the template literally puts
        // the braces on the wire and the executor refuses them. The action examples in
        // this file were already corrected for exactly this reason; these event templates
        // were the other half of the same fix and were missed.
        json!({
            "type": "send_turn_allocate_response",
            "relay_address": "192.0.2.10:49160",
            "client_address": "198.51.100.20:54321",
            "transaction_id": "0123456789abcdef01234567",
            "lifetime_seconds": 600
        }),
    )
    .with_parameters(with_extra(
        common_event_parameters(),
        vec![
            Parameter {
                name: "relay_address".to_string(),
                type_hint: "string".to_string(),
                description: "IP:port of the UDP relay socket NetGet has already bound for this request. Copy it verbatim into send_turn_allocate_response: it is where peers will send traffic for this client, and no other address will work. The socket is closed again if the allocation is not granted.".to_string(),
                required: true,
            },
            Parameter {
                name: "requested_lifetime_seconds".to_string(),
                type_hint: "number".to_string(),
                description: "Lifetime the client asked for (LIFETIME attribute), or null if it did not ask. You are free to grant less.".to_string(),
                required: false,
            },
            Parameter {
                name: "requested_transport".to_string(),
                type_hint: "string".to_string(),
                description: "Transport the client asked to relay: \"udp\", \"tcp\", or null. Only UDP is relayed; TCP requests are refused with 442 before this event fires.".to_string(),
                required: false,
            },
        ],
    ))
    .with_actions(vec![
        send_turn_allocate_response_action(),
        send_turn_error_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("TURN allocate request")
            .with_debug("TURN allocate request")
            .with_trace("TURN allocate: {json_pretty(.)}"),
    )
});

pub static TURN_REFRESH_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_refresh_request",
        "TURN refresh request received from client",
        // Concrete values, not "{{event.…}}" placeholders: that substitution only happens
        // for a static event handler, so a model that copies the template literally puts
        // the braces on the wire and the executor refuses them. The action examples in
        // this file were already corrected for exactly this reason; these event templates
        // were the other half of the same fix and were missed.
        json!({
            "type": "send_turn_refresh_response",
            "transaction_id": "0123456789abcdef01234567",
            "lifetime_seconds": 600
        }),
    )
    .with_parameters(with_extra(
        common_event_parameters(),
        vec![Parameter {
            name: "requested_lifetime_seconds".to_string(),
            type_hint: "number".to_string(),
            description: "Lifetime the client asked for, or null. Zero means the client wants the allocation deleted; answering with lifetime_seconds 0 closes the relay socket.".to_string(),
            required: false,
        }],
    ))
    .with_actions(vec![
        send_turn_refresh_response_action(),
        send_turn_error_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("TURN refresh request")
            .with_debug("TURN refresh request")
            .with_trace("TURN refresh: {json_pretty(.)}"),
    )
});

pub static TURN_CREATE_PERMISSION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_create_permission_request",
        "TURN create permission request received from client",
        // Concrete values, not "{{event.…}}" placeholders: that substitution only happens
        // for a static event handler, so a model that copies the template literally puts
        // the braces on the wire and the executor refuses them. The action examples in
        // this file were already corrected for exactly this reason; these event templates
        // were the other half of the same fix and were missed.
        json!({
            "type": "send_turn_create_permission_response",
            "transaction_id": "0123456789abcdef01234567"
        }),
    )
    .with_parameters(with_extra(
        common_event_parameters(),
        vec![Parameter {
            name: "peer_addresses".to_string(),
            type_hint: "array".to_string(),
            description: "Peer IP:port values the client asks permission for - these, and not `peer_addr` (which is the client itself), are what the response must permit. Until a peer is permitted, nothing is relayed to or from it."
                .to_string(),
            required: true,
        }],
    ))
    .with_actions(vec![
        send_turn_create_permission_response_action(),
        send_turn_error_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("TURN create permission")
            .with_debug("TURN create permission")
            .with_trace("TURN create permission: {json_pretty(.)}"),
    )
});

pub static TURN_CHANNEL_BIND_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_channel_bind_request",
        "TURN channel bind request received from client",
        // Concrete values, not "{{event.…}}" placeholders: that substitution only happens
        // for a static event handler, so a model that copies the template literally puts
        // the braces on the wire and the executor refuses them. The action examples in
        // this file were already corrected for exactly this reason; these event templates
        // were the other half of the same fix and were missed.
        json!({
            "type": "send_turn_channel_bind_response",
            "transaction_id": "0123456789abcdef01234567"
        }),
    )
    .with_parameters(with_extra(
        common_event_parameters(),
        vec![
            Parameter {
                name: "channel_number".to_string(),
                type_hint: "number".to_string(),
                description: "Channel number the client wants bound (0x4000-0x7FFF). Out-of-range values are refused with 400 before this event fires.".to_string(),
                required: true,
            },
            Parameter {
                name: "peer_address".to_string(),
                type_hint: "string".to_string(),
                description: "Peer IP:port to bind the channel to. Granting the bind also permits that peer.".to_string(),
                required: true,
            },
        ],
    ))
    .with_actions(vec![
        send_turn_channel_bind_response_action(),
        send_turn_error_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("TURN channel bind request")
            .with_debug("TURN channel bind request")
            .with_trace("TURN channel bind: {json_pretty(.)}"),
    )
});

fn get_turn_event_types() -> Vec<EventType> {
    vec![
        TURN_ALLOCATE_REQUEST_EVENT.clone(),
        TURN_REFRESH_REQUEST_EVENT.clone(),
        TURN_CREATE_PERMISSION_REQUEST_EVENT.clone(),
        TURN_CHANNEL_BIND_REQUEST_EVENT.clone(),
    ]
}
