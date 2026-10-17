//! TFTP protocol actions implementation

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

pub struct TftpProtocol;

impl TftpProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// Read a `block_number` and check it fits the wire field.
///
/// The field is 16 bits. This used to be `as_u64()? as u16`, which silently wraps: a model
/// answering with block 65536 put block 0 on the wire, and block 70000 put 4464 — a
/// mid-transfer block number the client had already acknowledged, so the transfer either
/// stalled or duplicated a block with no error anywhere. The declared range is 1-65535 and
/// the executor now enforces it.
fn parse_block_number(action: &serde_json::Value, action_name: &str) -> Result<u16> {
    let raw = action
        .get("block_number")
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Missing 'block_number' in {action_name} action"))?;

    u16::try_from(raw).map_err(|_| {
        anyhow::anyhow!(
            "Invalid TFTP block_number {raw} in {action_name}: the field is 16 bits, so it must \
             be 0-65535 (0 is only valid as the ACK that accepts a write request)."
        )
    })
}

// Event type constants
pub static TFTP_READ_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_read_request",
        "A client asked to download a file (RRQ). You are the filesystem: nothing is read from \
         disk. Answer with send_tftp_data carrying block 1 of the file you invent, or refuse \
         with send_tftp_error (code 1 = file not found).",
        json!({
            "type": "send_tftp_data",
            "block_number": 1,
            "data_hex": "48656c6c6f20544654502100"
        }),
    )
    // Per-event narrowing: an RRQ is answered with data or an error, never with an ACK (the
    // client acknowledges, the server does not). `call_llm` builds the model's tool list from
    // the event type rather than from get_sync_actions(), so without these lists TFTP offered
    // the model nothing it could reply with.
    .with_actions(vec![send_tftp_data_action(), send_tftp_error_action()])
    .with_parameters(vec![
        Parameter {
            name: "filename".to_string(),
            type_hint: "string".to_string(),
            description: "Name of file being requested".to_string(),
            required: true,
        },
        Parameter {
            name: "mode".to_string(),
            type_hint: "string".to_string(),
            description: "Transfer mode (netascii, octet, mail)".to_string(),
            required: true,
        },
        Parameter {
            name: "client_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Client socket address".to_string(),
            required: true,
        },
    ])
});

pub static TFTP_WRITE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_write_request",
        "A client asked to upload a file (WRQ). Accept it with send_tftp_ack for block 0, which \
         is what tells the client to start sending, or refuse it with send_tftp_error (code 2 = \
         access violation).",
        json!({"type": "send_tftp_ack", "block_number": 0}),
    )
    .with_actions(vec![send_tftp_ack_action(), send_tftp_error_action()])
    .with_parameters(vec![
        Parameter {
            name: "filename".to_string(),
            type_hint: "string".to_string(),
            description: "Name of file to write".to_string(),
            required: true,
        },
        Parameter {
            name: "mode".to_string(),
            type_hint: "string".to_string(),
            description: "Transfer mode (netascii, octet, mail)".to_string(),
            required: true,
        },
        Parameter {
            name: "client_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Client socket address".to_string(),
            required: true,
        },
    ])
});

pub static TFTP_DATA_BLOCK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_data_block",
        "A block of an upload arrived. Acknowledge it with send_tftp_ack for the same \
         block_number, or abort the transfer with send_tftp_error.",
        json!({"type": "send_tftp_ack", "block_number": 1}),
    )
    .with_actions(vec![send_tftp_ack_action(), send_tftp_error_action()])
    .with_parameters(vec![
        Parameter {
            name: "block_number".to_string(),
            type_hint: "number".to_string(),
            description: "Block number (1-65535)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Block data as hex string".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes in this block".to_string(),
            required: true,
        },
        Parameter {
            name: "is_final".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if this is the final block (< 512 bytes)".to_string(),
            required: true,
        },
    ])
});

pub static TFTP_ACK_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_ack_received",
        "The client acknowledged a block of a download. Send the next block with send_tftp_data \
         (a block shorter than 512 bytes is what ends the transfer, per RFC 1350 - so send a \
         short or empty final block), or abort with send_tftp_error. Returning no action ends \
         the transfer.",
        json!({
            "type": "send_tftp_data",
            "block_number": 2,
            "data_hex": ""
        }),
    )
    .with_actions(vec![send_tftp_data_action(), send_tftp_error_action()])
    .with_parameters(vec![Parameter {
        name: "block_number".to_string(),
        type_hint: "number".to_string(),
        description: "Block number acknowledged".to_string(),
        required: true,
    }])
});

fn get_tftp_event_types() -> Vec<EventType> {
    vec![
        TFTP_READ_REQUEST_EVENT.clone(),
        TFTP_WRITE_REQUEST_EVENT.clone(),
        TFTP_DATA_BLOCK_EVENT.clone(),
        TFTP_ACK_RECEIVED_EVENT.clone(),
    ]
}

// Implement Protocol trait (common functionality)
impl Protocol for TftpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_tftp_data_action(),
            send_tftp_ack_action(),
            send_tftp_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "TFTP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_tftp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>TFTP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // No bare "file" or "transfer": both are too generic to own. "file" swallowed NFS's
        // "file server" and "transfer" swallowed FTP's "file transfer", so a request for
        // either resolved to TFTP.
        vec!["tftp", "pxe", "boot"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        // Deliberately NOT `.connectionless()`. TFTP is UDP, but unlike the other UDP
        // servers its "connections" are real per-transfer sessions with an explicit
        // lifecycle: every exit path — final ACK, timeout, ERROR, socket error — calls
        // `close_connection_on_server`, so nothing leaks and the idle sweep has no work to
        // do. Declaring it connectionless made `cleanup_old_connections` evict a live
        // transfer whenever the handler took more than ten seconds to answer, which one LLM
        // round-trip routinely does; the transfer then finished on the wire while its
        // connection entry, its block counter and its close all targeted a record that was
        // already gone.
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(69))
            .well_known_udp_port(69)
            .implementation("Custom TFTP packet parsing and state machine")
            .llm_control("File read/write operations via memory (no disk storage)")
            .e2e_testing("Mock-based tests with RRQ/WRQ flows")
            .notes("LLM provides all file content from memory/instruction")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Trivial File Transfer Protocol server for network booting and simple file transfers"
    }

    fn example_prompt(&self) -> &'static str {
        "listen on port 69 via tftp. Serve pxelinux.0 boot file with hex data 4d5a9000..."
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: serve a single-block virtual file ("Hello\n") for every
        // read request, no LLM call. data_hex is the file bytes, hex-encoded.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "tftp_read_request":
    actions = [{"type": "send_tftp_data", "block_number": 1,
                "data_hex": "48656c6c6f0a"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all TFTP responses intelligently
            json!({
                "type": "open_server",
                "port": 69,
                "base_stack": "tftp",
                "instruction": "TFTP file transfer server for network booting"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 69,
                "base_stack": "tftp",
                "event_handlers": [{
                    "event_pattern": "tftp_read_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 69,
                "base_stack": "tftp",
                "event_handlers": [{
                    "event_pattern": "tftp_read_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_tftp_error",
                            "error_code": 1,
                            "error_message": "File not found"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TftpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::tftp::TftpServer;
            TftpServer::spawn_with_llm_actions(
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
            "send_tftp_data" => self.execute_send_tftp_data(action),
            "send_tftp_ack" => self.execute_send_tftp_ack(action),
            "send_tftp_error" => self.execute_send_tftp_error(action),
            _ => Err(anyhow::anyhow!("Unknown TFTP action: {}", action_type)),
        }
    }
}

impl TftpProtocol {
    fn execute_send_tftp_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let block_number = parse_block_number(&action, "send_tftp_data")?;

        let data_hex = action
            .get("data_hex")
            .and_then(|v| v.as_str())
            .context("Missing 'data_hex' in send_tftp_data action")?;

        let data =
            hex::decode(data_hex).context("Failed to decode hex data in send_tftp_data action")?;

        if data.len() > 512 {
            return Err(anyhow::anyhow!(
                "TFTP data block cannot exceed 512 bytes, got {}",
                data.len()
            ));
        }

        // Build TFTP DATA packet
        // Opcode (2 bytes) = 3 (DATA)
        // Block number (2 bytes)
        // Data (0-512 bytes)
        let mut packet = Vec::with_capacity(4 + data.len());
        packet.extend_from_slice(&3u16.to_be_bytes()); // Opcode DATA
        packet.extend_from_slice(&block_number.to_be_bytes());
        packet.extend_from_slice(&data);

        Ok(ActionResult::Output(packet))
    }

    fn execute_send_tftp_ack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let block_number = parse_block_number(&action, "send_tftp_ack")?;

        // Build TFTP ACK packet
        // Opcode (2 bytes) = 4 (ACK)
        // Block number (2 bytes)
        let mut packet = Vec::with_capacity(4);
        packet.extend_from_slice(&4u16.to_be_bytes()); // Opcode ACK
        packet.extend_from_slice(&block_number.to_be_bytes());

        Ok(ActionResult::Output(packet))
    }

    fn execute_send_tftp_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Both fields are declared `required: true`. They used to be silently defaulted to
        // 0 and "Error", so an action the model got wrong produced a plausible-looking
        // ERROR packet rather than a visible failure — and the declaration was a lie.
        let error_code = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .context("Missing 'error_code' in send_tftp_error action (RFC 1350 defines 0-7)")?;
        if error_code > 7 {
            return Err(anyhow::anyhow!(
                "Invalid TFTP error_code {error_code}: RFC 1350 defines 0-7 (0=not defined, \
                 1=file not found, 2=access violation, 3=disk full, 4=illegal operation, \
                 5=unknown transfer ID, 6=file exists, 7=no such user)."
            ));
        }
        let error_code = error_code as u16;

        let error_message = action
            .get("error_message")
            .and_then(|v| v.as_str())
            .context("Missing 'error_message' in send_tftp_error action")?;

        // The message is NUL-terminated on the wire, so an embedded NUL would truncate it
        // and leave the remainder as trailing garbage the client reads as part of the packet.
        if error_message.contains('\0') {
            return Err(anyhow::anyhow!(
                "TFTP 'error_message' must not contain a NUL byte: the field is NUL-terminated \
                 on the wire, so an embedded NUL truncates the message."
            ));
        }

        // Build TFTP ERROR packet
        // Opcode (2 bytes) = 5 (ERROR)
        // Error code (2 bytes)
        // Error message (string)
        // Null terminator (1 byte)
        let mut packet = Vec::with_capacity(4 + error_message.len() + 1);
        packet.extend_from_slice(&5u16.to_be_bytes()); // Opcode ERROR
        packet.extend_from_slice(&error_code.to_be_bytes());
        packet.extend_from_slice(error_message.as_bytes());
        packet.push(0); // Null terminator

        Ok(ActionResult::Output(packet))
    }
}

// Action definitions

fn send_tftp_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_tftp_data".to_string(),
        description: "Send a data block to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "block_number".to_string(),
                type_hint: "number".to_string(),
                description: "Block number (1-65535)".to_string(),
                required: true,
            },
            Parameter {
                name: "data_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Data as hex string, max 512 bytes. The length is what ends the \
                    transfer: exactly 512 means more blocks follow, anything shorter (including \
                    empty) is the final block, per RFC 1350. Send an empty final block when the \
                    file is an exact multiple of 512 bytes."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_tftp_data",
            "block_number": 1,
            "data_hex": "48656c6c6f20544654502100"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TFTP DATA #{block_number}")
                .with_debug("TFTP send_tftp_data: block={block_number} bytes={data_hex}"),
        ),
    }
}

fn send_tftp_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_tftp_ack".to_string(),
        description: "Acknowledge received data block".to_string(),
        parameters: vec![Parameter {
            name: "block_number".to_string(),
            type_hint: "number".to_string(),
            description: "Block number to acknowledge".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_tftp_ack",
            "block_number": 5
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TFTP ACK #{block_number}")
                .with_debug("TFTP send_tftp_ack: block={block_number}"),
        ),
    }
}

fn send_tftp_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_tftp_error".to_string(),
        description: "Send error and terminate transfer".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "Error code (0=not defined, 1=file not found, 2=access violation, 3=disk full, 4=illegal operation, 5=unknown TID, 6=file exists, 7=no such user)".to_string(),
                required: true,
            },
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_tftp_error",
            "error_code": 1,
            "error_message": "File not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TFTP ERROR #{error_code}: {error_message}")
                .with_debug("TFTP send_tftp_error: code={error_code} msg={error_message}"),
        ),
    }
}
