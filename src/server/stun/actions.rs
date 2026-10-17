//! STUN protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub struct StunProtocol;

impl StunProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl crate::llm::actions::protocol_trait::Protocol for StunProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new() // STUN server is purely reactive
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_stun_binding_response_action(),
            send_stun_error_response_action(),
            ignore_request_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "STUN"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_stun_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>STUN"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["stun"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure, with the real Binding Success Response. A STUN Binding response
            // asserts one thing - the reflexive transport address - and the server observed that
            // itself from the datagram; the model never supplies it on this path. So the static
            // answer is true whether or not the model was reachable, and it is logged
            // decision=static_fallback_llm_error, deliberately not fail_closed_*.
            .answers_on_failure()
            .state(DevelopmentState::Beta)
            .well_known_udp_port(3478)
            .implementation("Manual STUN protocol (RFC 8489)")
            .llm_control("Optional: Binding responses are static by default (mechanical), LLM only on opt-in")
            .e2e_testing(
                "REAL THIRD-PARTY CLIENT: stuntman 1.2.16's `stunclient` binary, in \
                 tests/server/stun/real_client_test.rs. NOT #[ignore]d and NOT skip-gated — the \
                 test FAILS, naming `brew install stuntman`, when the binary is absent. Not \
                 circular: this server is a hand-written RFC 8489 codec with no STUN library \
                 behind it, and the `stunclient` *crate* in Cargo.toml belongs to the STUN \
                 *client* (src/client/stun/), a different program that does not run in these \
                 tests. stuntman completes a full Binding transaction and must un-XOR our \
                 XOR-MAPPED-ADDRESS against the magic cookie and its own transaction ID to \
                 recover the address it prints; both tests assert the address it recovers is \
                 exactly the socket it sent from, which a wrong byte anywhere would break. Both \
                 encoders are covered: the STATIC path (empty instruction, zero LLM calls) and \
                 the ACTION path (send_stun_binding_response building the attribute from \
                 model-supplied strings). Also covered, without a third-party client: \
                 reflection_test.rs (only a Binding REQUEST is answered), static_default_test.rs \
                 (zero LLM calls on the mechanical path) and llm_failure_test.rs \
                 (decision=static_fallback_llm_error). NOT PROVEN: IPv6 XOR-MAPPED-ADDRESS \
                 against a real client (stunclient is driven over IPv4 loopback here, though the \
                 IPv6 encoder exists and is unit-covered); any authenticated exchange, since \
                 MESSAGE-INTEGRITY/USERNAME/REALM/NONCE/FINGERPRINT are not implemented and no \
                 action can add them, so no client can be made to authenticate; stuntman's NAT \
                 behaviour and filtering tests (-b/-f), which need the second address and port \
                 pair RFC 5780 wants and this server does not implement; and behaviour under \
                 any real NAT, everything here being loopback.",
            )
            .notes(
                "Stateless UDP; IPv4 and IPv6 XOR-MAPPED-ADDRESS are both encoded. A Binding \
                 response is fully determined by the request (reflect source into \
                 XOR-MAPPED-ADDRESS, echo the transaction ID), so it is answered STATICALLY with \
                 no LLM round-trip by default. The LLM is consulted only when the operator opts \
                 in with a server instruction or a per-event handler — the way to request \
                 non-standard behaviour such as lying about the mapped address. On LLM failure in \
                 opt-in mode the server falls back to the correct static response. REFLECTION: \
                 only a Binding REQUEST is answered; responses, indications and other methods are \
                 dropped silently, so this cannot be looped against another STUN server. It is \
                 still a ~2.4x amplifier for a spoofed source (20-byte request, 48-byte reply), \
                 which is inherent to STUN and no worse than a real STUN server, and there is NO \
                 per-source rate limit — put one in front of it on an untrusted network. No \
                 authentication: MESSAGE-INTEGRITY, USERNAME, REALM, NONCE and FINGERPRINT are \
                 not implemented and no action can add them.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "STUN server for NAT traversal"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a STUN server for NAT traversal on port 3478"
    }

    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: reflect the client's mapped address back for every
        // binding request, echoing its transaction id, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "stun_binding_request":
    actions = [{"type": "send_stun_binding_response",
                "transaction_id": event.get("transaction_id"),
                "mapped_address": event.get("peer_addr"),
                "xor_mapped_address": True}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all STUN responses
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "stun",
                "instruction": "STUN server for NAT traversal - respond with client's external IP"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "stun",
                "event_handlers": [{
                    "event_pattern": "stun_binding_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: no LLM call, but still echoes the client's own
            // transaction ID and address by interpolating the event fields. A
            // hardcoded transaction ID would never match the client's request,
            // and every STUN client discards a response whose transaction ID
            // differs from the one it sent.
            json!({
                "type": "open_server",
                "port": 3478,
                "base_stack": "stun",
                "event_handlers": [{
                    "event_pattern": "stun_binding_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_stun_binding_response",
                            "transaction_id": "{{event.transaction_id}}",
                            "mapped_address": "{{event.peer_addr}}",
                            "xor_mapped_address": true
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for StunProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::stun::StunServer;
            StunServer::spawn_with_llm_actions(
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
            "send_stun_binding_response" => self.execute_send_binding_response(action),
            "send_stun_error_response" => self.execute_send_error_response(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown STUN action: {}", action_type)),
        }
    }
}

impl StunProtocol {
    /// Execute STUN binding response action
    fn execute_send_binding_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract parameters
        let mapped_address = action
            .get("mapped_address")
            .and_then(|v| v.as_str())
            .context("Missing 'mapped_address' field")?;

        let transaction_id = action
            .get("transaction_id")
            .and_then(|v| v.as_str())
            .context("Missing 'transaction_id' field")?;

        // Optional parameters
        let xor_mapped_address = action
            .get("xor_mapped_address")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let software = action
            .get("software")
            .and_then(|v| v.as_str())
            .unwrap_or("NetGet/1.0");

        // Parse transaction ID from hex
        let transaction_id_bytes =
            hex::decode(transaction_id).context("Invalid transaction_id hex")?;

        if transaction_id_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Transaction ID must be 12 bytes"));
        }

        // Parse mapped address
        let addr: std::net::SocketAddr = mapped_address
            .parse()
            .context("Invalid mapped_address format")?;

        // Build STUN binding response
        let packet = Self::build_binding_response(
            &transaction_id_bytes,
            addr,
            xor_mapped_address,
            software,
        )?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute STUN error response action
    fn execute_send_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Both are declared `required: true`, so the executor enforces it rather
        // than substituting a default. Silently answering 400 Bad Request when
        // the model asked for 401 Unauthorized would put a different decision on
        // the wire from the one it made, and hide the malformed action.
        let error_code_raw = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .context("Missing or non-numeric 'error_code' field")?;

        // Range-check *before* narrowing. `65836 as u16` is 300, which passes the check below
        // and is then indistinguishable from a model that legitimately asked for 300 - the
        // wrap has to be caught while the original value is still visible.
        if !(300..700).contains(&error_code_raw) {
            return Err(anyhow::anyhow!(
                "error_code {error_code_raw} is outside the 300-699 range RFC 8489 section \
                 14.8 encodes as a class/number pair"
            ));
        }
        let error_code = error_code_raw as u16;

        if !(300..700).contains(&error_code) {
            return Err(anyhow::anyhow!(
                "error_code {error_code} is outside the 300-699 range RFC 8489 section 14.8 \
                 encodes as a class/number pair"
            ));
        }

        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .context("Missing 'reason' field")?;

        let transaction_id = action
            .get("transaction_id")
            .and_then(|v| v.as_str())
            .context("Missing 'transaction_id' field")?;

        // Parse transaction ID from hex
        let transaction_id_bytes =
            hex::decode(transaction_id).context("Invalid transaction_id hex")?;

        if transaction_id_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Transaction ID must be 12 bytes"));
        }

        // Build STUN error response
        let packet = Self::build_error_response(&transaction_id_bytes, error_code, reason)?;

        Ok(ActionResult::Output(packet))
    }

    /// Build STUN binding response packet
    ///
    /// There is deliberately no MESSAGE-INTEGRITY here, and no parameter asking
    /// for one. The action used to advertise `message_integrity` and the executor
    /// took the boolean and threw it away, so a model that set it got exactly the
    /// unauthenticated response it got with the flag off, while the parameter's
    /// own description said "Include MESSAGE-INTEGRITY attribute". RFC 8489
    /// section 14.6 computes that attribute over a key derived from a
    /// username/realm/password the server does not have and has no way to obtain,
    /// so the knob could never have been honoured. Removing it is the honest fix.
    fn build_binding_response(
        transaction_id: &[u8],
        mapped_addr: std::net::SocketAddr,
        use_xor: bool,
        software: &str,
    ) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Message Type: 0x0101 (Binding Success Response)
        packet.extend_from_slice(&0x0101u16.to_be_bytes());

        // Message Length (will be updated later)
        let length_pos = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie: 0x2112A442
        packet.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID (12 bytes)
        packet.extend_from_slice(transaction_id);

        let attributes_start = packet.len();

        // Add MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute
        if use_xor {
            Self::add_xor_mapped_address_attribute(&mut packet, mapped_addr, transaction_id)?;
        } else {
            Self::add_mapped_address_attribute(&mut packet, mapped_addr)?;
        }

        // Add SOFTWARE attribute
        Self::add_software_attribute(&mut packet, software)?;

        // Update message length (attributes length, excluding 20-byte header)
        let attributes_length = (packet.len() - attributes_start) as u16;
        packet[length_pos..length_pos + 2].copy_from_slice(&attributes_length.to_be_bytes());

        Ok(packet)
    }

    /// Build STUN error response packet (RFC 8489 §6.3.4).
    ///
    /// Reached only through `send_stun_error_response`, i.e. when a handler or
    /// the model deliberately refuses a request. The server's *own* LLM-failure
    /// path does not come here: it falls back to the mechanical Binding Success
    /// Response, because for STUN the correct answer is a fact about the
    /// requester's source address rather than anything the backend contributes.
    /// This doc comment used to claim the opposite, and the `pub(crate)` it
    /// justified is what is left of that.
    pub(crate) fn build_error_response(
        transaction_id: &[u8],
        error_code: u16,
        reason: &str,
    ) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Message Type: 0x0111 (Binding Error Response)
        packet.extend_from_slice(&0x0111u16.to_be_bytes());

        // Message Length (will be updated later)
        let length_pos = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie: 0x2112A442
        packet.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID (12 bytes)
        packet.extend_from_slice(transaction_id);

        let attributes_start = packet.len();

        // Add ERROR-CODE attribute
        Self::add_error_code_attribute(&mut packet, error_code, reason)?;

        // Update message length
        let attributes_length = (packet.len() - attributes_start) as u16;
        packet[length_pos..length_pos + 2].copy_from_slice(&attributes_length.to_be_bytes());

        Ok(packet)
    }

    /// Add MAPPED-ADDRESS attribute
    fn add_mapped_address_attribute(
        packet: &mut Vec<u8>,
        addr: std::net::SocketAddr,
    ) -> Result<()> {
        // Attribute Type: 0x0001 (MAPPED-ADDRESS)
        packet.extend_from_slice(&0x0001u16.to_be_bytes());

        // Attribute Length
        let attr_start = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder

        let value_start = packet.len();

        // Reserved byte + family
        match addr {
            std::net::SocketAddr::V4(addr_v4) => {
                packet.push(0x00); // Reserved
                packet.push(0x01); // IPv4
                packet.extend_from_slice(&addr_v4.port().to_be_bytes());
                packet.extend_from_slice(&addr_v4.ip().octets());
            }
            std::net::SocketAddr::V6(addr_v6) => {
                packet.push(0x00); // Reserved
                packet.push(0x02); // IPv6
                packet.extend_from_slice(&addr_v6.port().to_be_bytes());
                packet.extend_from_slice(&addr_v6.ip().octets());
            }
        }

        let value_length = (packet.len() - value_start) as u16;
        packet[attr_start..attr_start + 2].copy_from_slice(&value_length.to_be_bytes());

        // Add padding to align to 4-byte boundary
        Self::add_padding(packet);

        Ok(())
    }

    /// Add XOR-MAPPED-ADDRESS attribute
    fn add_xor_mapped_address_attribute(
        packet: &mut Vec<u8>,
        addr: std::net::SocketAddr,
        transaction_id: &[u8],
    ) -> Result<()> {
        // Attribute Type: 0x0020 (XOR-MAPPED-ADDRESS)
        packet.extend_from_slice(&0x0020u16.to_be_bytes());

        // Attribute Length
        let attr_start = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder

        let value_start = packet.len();

        // Magic cookie for XOR operations
        let magic_cookie = 0x2112A442u32;

        match addr {
            std::net::SocketAddr::V4(addr_v4) => {
                packet.push(0x00); // Reserved
                packet.push(0x01); // IPv4

                // XOR port with upper 16 bits of magic cookie
                let xor_port = addr_v4.port() ^ (magic_cookie >> 16) as u16;
                packet.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie
                let ip_bytes = addr_v4.ip().octets();
                let magic_bytes = magic_cookie.to_be_bytes();
                for i in 0..4 {
                    packet.push(ip_bytes[i] ^ magic_bytes[i]);
                }
            }
            std::net::SocketAddr::V6(addr_v6) => {
                packet.push(0x00); // Reserved
                packet.push(0x02); // IPv6

                // XOR port with upper 16 bits of magic cookie
                let xor_port = addr_v6.port() ^ (magic_cookie >> 16) as u16;
                packet.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie + transaction ID
                let ip_bytes = addr_v6.ip().octets();
                let magic_bytes = magic_cookie.to_be_bytes();

                // First 4 bytes XORed with magic cookie
                for i in 0..4 {
                    packet.push(ip_bytes[i] ^ magic_bytes[i]);
                }

                // Remaining 12 bytes XORed with transaction ID
                for i in 0..12 {
                    packet.push(ip_bytes[i + 4] ^ transaction_id[i]);
                }
            }
        }

        let value_length = (packet.len() - value_start) as u16;
        packet[attr_start..attr_start + 2].copy_from_slice(&value_length.to_be_bytes());

        // Add padding to align to 4-byte boundary
        Self::add_padding(packet);

        Ok(())
    }

    /// Add SOFTWARE attribute
    fn add_software_attribute(packet: &mut Vec<u8>, software: &str) -> Result<()> {
        // Attribute Type: 0x8022 (SOFTWARE)
        packet.extend_from_slice(&0x8022u16.to_be_bytes());

        let software_bytes = software.as_bytes();
        let length = software_bytes.len() as u16;

        // Attribute Length
        packet.extend_from_slice(&length.to_be_bytes());

        // Attribute Value
        packet.extend_from_slice(software_bytes);

        // Add padding to align to 4-byte boundary
        Self::add_padding(packet);

        Ok(())
    }

    /// Add ERROR-CODE attribute
    fn add_error_code_attribute(packet: &mut Vec<u8>, error_code: u16, reason: &str) -> Result<()> {
        // Attribute Type: 0x0009 (ERROR-CODE)
        packet.extend_from_slice(&0x0009u16.to_be_bytes());

        // Attribute Length
        let attr_start = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder

        let value_start = packet.len();

        // Reserved (2 bytes) + Class (1 byte) + Number (1 byte)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        let class = (error_code / 100) as u8;
        let number = (error_code % 100) as u8;
        packet.push(class);
        packet.push(number);

        // Reason phrase
        packet.extend_from_slice(reason.as_bytes());

        let value_length = (packet.len() - value_start) as u16;
        packet[attr_start..attr_start + 2].copy_from_slice(&value_length.to_be_bytes());

        // Add padding to align to 4-byte boundary
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

fn send_stun_binding_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stun_binding_response".to_string(),
        description: "Send STUN binding response with mapped address".to_string(),
        parameters: vec![
            Parameter {
                name: "mapped_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Client's public IP:port as seen by server (e.g., \"203.0.113.45:54321\")"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Transaction ID from the request, hex-encoded (exactly 24 hex chars = 12 bytes). MUST be copied from the event's transaction_id: a STUN client silently discards any response whose transaction ID does not match the request it sent.".to_string(),
                required: true,
            },
            Parameter {
                name: "xor_mapped_address".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Use XOR-MAPPED-ADDRESS (true) or MAPPED-ADDRESS (false). Default: true"
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "software".to_string(),
                type_hint: "string".to_string(),
                description: "Software version string. Default: \"NetGet/1.0\"".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stun_binding_response",
            "mapped_address": "203.0.113.45:54321",
            "transaction_id": "0123456789abcdef01234567",
            "xor_mapped_address": true,
            "software": "NetGet STUN/1.0"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STUN binding response {mapped_address}")
                .with_debug("STUN binding_response: {mapped_address}"),
        ),
    }
}

fn send_stun_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stun_error_response".to_string(),
        description: "Send STUN error response".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "STUN error code (e.g., 400, 401, 420, 438, 500)".to_string(),
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
                description: "Transaction ID from request (hex string)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_stun_error_response",
            "error_code": 401,
            "reason": "Unauthorized",
            "transaction_id": "0123456789abcdef01234567"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STUN error {error_code}: {reason}")
                .with_debug("STUN error_response: {error_code} {reason}"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Silently ignore the STUN request (no response)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("STUN request ignored")
                .with_debug("STUN ignore_request"),
        ),
    }
}

// Event types

pub static STUN_BINDING_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stun_binding_request",
        "STUN binding request received from client",
        // Concrete values, not "{{event.…}}" placeholders. This is the template for the
        // *model's own reply*, and nothing substitutes into that — the braces only mean
        // something in a static event handler. A model copying the placeholder puts the
        // literal string on the wire and the executor refuses it. Both values must come from
        // the event; the transaction ID is 12 bytes, hex-encoded.
        json!({
            "type": "send_stun_binding_response",
            "mapped_address": "198.51.100.20:54321",
            "transaction_id": "0123456789abcdef01234567"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Client's IP:port address (public address as seen by server)".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Server's listening IP:port address".to_string(),
            required: true,
        },
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "STUN transaction ID (hex-encoded, 12 bytes = 24 hex chars)".to_string(),
            required: true,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "STUN message type. Always \"BindingRequest\": the server drops every \
                          other class and method before raising this event, so nothing else \
                          reaches you here."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_received".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes in the STUN request".to_string(),
            required: true,
        },
    ])
    // Without this the event advertised no actions at all, so every action the
    // model produced was rejected as "Unknown Action" and the request went
    // unanswered. Only static/script handlers, which skip that validation, could
    // reply.
    .with_actions(vec![
        send_stun_binding_response_action(),
        send_stun_error_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("STUN {client_ip} binding request")
            .with_debug("STUN binding request from {client_ip}:{client_port}")
            .with_trace("STUN: {json_pretty(.)}"),
    )
});

fn get_stun_event_types() -> Vec<EventType> {
    vec![STUN_BINDING_REQUEST_EVENT.clone()]
}
