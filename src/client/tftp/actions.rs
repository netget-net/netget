//! TFTP client protocol actions

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

pub struct TftpClientProtocol;

impl Default for TftpClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl TftpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

// Event type constants
pub static TFTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_connected",
        "TFTP client socket bound; choose a transfer to start",
        json!({"type": "tftp_read_file", "filename": "pxelinux.0", "mode": "octet"}),
    )
    .with_parameters(vec![
        param("server_addr", "string", "Server socket address", true),
        param(
            "local_addr",
            "string",
            "Local socket address (client TID)",
            true,
        ),
    ])
    .with_actions(vec![
        tftp_read_file_action(),
        tftp_write_file_action(),
        disconnect_action(),
    ])
});

pub static TFTP_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_data_received",
        "Received data block from server",
        json!({"type": "send_ack", "block_number": 1}),
    )
    .with_parameters(vec![
        param("block_number", "number", "Block number received", true),
        param("data_hex", "string", "Block data, hex-encoded", true),
        param("data_length", "number", "Number of bytes in block", true),
        param(
            "is_final",
            "boolean",
            "True if final block (< 512 bytes)",
            true,
        ),
        param("total_bytes", "number", "Total bytes received so far", true),
    ])
    .with_actions(vec![send_ack_action(), disconnect_action()])
});

pub static TFTP_CLIENT_ACK_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_ack_received",
        "Server acknowledged a block; send the next one",
        json!({"type": "send_data_block", "block_number": 1, "data_hex": "48656c6c6f"}),
    )
    .with_parameters(vec![param(
        "block_number",
        "number",
        "Block number acknowledged",
        true,
    )])
    .with_actions(vec![send_data_block_action(), disconnect_action()])
});

pub static TFTP_CLIENT_TRANSFER_COMPLETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_transfer_complete",
        "File transfer completed",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![
        param("total_bytes", "number", "Total bytes transferred", true),
        param("total_blocks", "number", "Total blocks transferred", true),
    ])
    .with_actions(vec![disconnect_action()])
});

pub static TFTP_CLIENT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tftp_error",
        "TFTP error received from server",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![
        param("error_code", "number", "TFTP error code", true),
        param("error_message", "string", "Error message from server", true),
    ])
    .with_actions(vec![disconnect_action()])
});

// Implement Protocol trait (common functionality)
impl crate::llm::actions::protocol_trait::Protocol for TftpClientProtocol {
    /// What a caller can ask for at any time: start a read, start a write, or give up.
    ///
    /// The mid-transfer actions (`send_ack`, `send_data_block`) are deliberately **not**
    /// repeated here — they belong to `get_sync_actions()` and to the events that need them.
    /// This list carried them for a while as a workaround: `call_llm_for_client` used to build
    /// the model's tool list from `get_async_actions()` alone, never `get_sync_actions()` and
    /// never `event.event_type.actions`, so `send_ack` was advertised nowhere and every DATA
    /// block came back "Unknown Action" with the transfer stalled at block 1
    /// (`tests/client/tftp/e2e_test.rs::reads_a_two_block_file` catches exactly that).
    ///
    /// That is fixed centrally now — `client_llm_action_set` advertises the union of async,
    /// sync and the firing event's own actions — so the honest declaration is back, and the
    /// TFTP e2e test passing with `send_ack` sync-only is the proof the central fix works.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            tftp_read_file_action(),
            tftp_write_file_action(),
            disconnect_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_ack_action(),
            send_data_block_action(),
            disconnect_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "TFTP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TFTP_CLIENT_CONNECTED_EVENT.clone(),
            TFTP_CLIENT_DATA_RECEIVED_EVENT.clone(),
            TFTP_CLIENT_ACK_RECEIVED_EVENT.clone(),
            TFTP_CLIENT_TRANSFER_COMPLETE_EVENT.clone(),
            TFTP_CLIENT_ERROR_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>TFTP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["tftp", "tftp client", "trivial file transfer"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Hand-rolled RFC 1350 packet encode/decode over tokio UdpSocket. \
                 Learns the server TID from the first reply. No RFC 2347 option \
                 negotiation, no retransmission (5s timeout aborts).",
            )
            .llm_control(
                "Model picks read vs write, acknowledges each DATA block, and supplies \
                 every outbound DATA block. NetGet invents no request on its own.",
            )
            .e2e_testing(
                "Validated against NetGet's own TFTP server (tests/client/tftp) — \
                 a same-project peer, which is weaker evidence than an independent \
                 implementation. Packet encode/decode is additionally checked against \
                 RFC 1350 literal bytes.",
            )
            .notes(
                "Re-enabled 2026-08; had been commented out of the registry since \
                 2025-11 pending the call_llm_for_client signature change. Write \
                 transfers are LLM-driven block by block, so a large upload costs one \
                 LLM call per 512 bytes.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "TFTP client for file transfers"
    }

    fn example_prompt(&self) -> &'static str {
        "connect to 192.168.1.1:69 via tftp. Read file pxelinux.0"
    }

    fn group_name(&self) -> &'static str {
        "Clients"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        Vec::new()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:69",
                "base_stack": "tftp",
                "instruction": "Read the file pxelinux.0 in octet mode and report its size"
            }),
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:69",
                "base_stack": "tftp",
                "event_handlers": [{
                    "event_pattern": "tftp_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<tftp_client_handler>"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:69",
                "base_stack": "tftp",
                "event_handlers": [
                    {
                        "event_pattern": "tftp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "tftp_read_file",
                                "filename": "pxelinux.0",
                                "mode": "octet"
                            }]
                        }
                    },
                    {
                        "event_pattern": "tftp_transfer_complete",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "disconnect"}]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for TftpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            crate::client::tftp::TftpClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "tftp_read_file" | "tftp_write_file" => {
                let filename = action
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .with_context(|| format!("Missing 'filename' in {}", action_type))?;
                let mode = action
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("octet");
                if mode != "octet" && mode != "netascii" {
                    return Err(anyhow::anyhow!(
                        "TFTP mode must be 'octet' or 'netascii', got '{}'",
                        mode
                    ));
                }
                Ok(ClientActionResult::Custom {
                    name: action_type.to_string(),
                    data: json!({ "filename": filename, "mode": mode }),
                })
            }
            "send_ack" => {
                let block_number = action
                    .get("block_number")
                    .and_then(|v| v.as_u64())
                    .context("Missing 'block_number' in send_ack")?;
                let block_number =
                    u16::try_from(block_number).context("TFTP block_number must fit in 16 bits")?;

                // ACK packet: opcode(2) + block_number(2)
                let mut packet = Vec::with_capacity(4);
                packet.extend_from_slice(&crate::client::tftp::OP_ACK.to_be_bytes());
                packet.extend_from_slice(&block_number.to_be_bytes());

                Ok(ClientActionResult::SendData(packet))
            }
            "send_data_block" => {
                let block_number = action
                    .get("block_number")
                    .and_then(|v| v.as_u64())
                    .context("Missing 'block_number' in send_data_block")?;
                let block_number =
                    u16::try_from(block_number).context("TFTP block_number must fit in 16 bits")?;

                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data_hex' in send_data_block")?;

                let data =
                    hex::decode(data_hex).context("Failed to decode hex in send_data_block")?;

                if data.len() > crate::client::tftp::TFTP_BLOCK_SIZE {
                    return Err(anyhow::anyhow!(
                        "TFTP data block cannot exceed {} bytes, got {}",
                        crate::client::tftp::TFTP_BLOCK_SIZE,
                        data.len()
                    ));
                }

                // DATA packet: opcode(2) + block_number(2) + data
                let mut packet = Vec::with_capacity(4 + data.len());
                packet.extend_from_slice(&crate::client::tftp::OP_DATA.to_be_bytes());
                packet.extend_from_slice(&block_number.to_be_bytes());
                packet.extend_from_slice(&data);

                Ok(ClientActionResult::SendData(packet))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown TFTP client action: {}",
                action_type
            )),
        }
    }
}

// Action definitions

fn tftp_read_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "tftp_read_file".to_string(),
        description: "Request a file from the TFTP server (sends RRQ)".to_string(),
        parameters: vec![
            param("filename", "string", "Name of file to read", true),
            param(
                "mode",
                "string",
                "Transfer mode: 'octet' or 'netascii' (default: octet)",
                false,
            ),
        ],
        example: json!({
            "type": "tftp_read_file",
            "filename": "pxelinux.0",
            "mode": "octet"
        }),
        log_template: None,
    }
}

fn tftp_write_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "tftp_write_file".to_string(),
        description: "Offer a file to the TFTP server (sends WRQ). The file content is not \
                      supplied here: the server answers with ACK block 0, and you send each \
                      512-byte block with send_data_block. A block shorter than 512 bytes \
                      ends the transfer."
            .to_string(),
        parameters: vec![
            param("filename", "string", "Name of file to write", true),
            param(
                "mode",
                "string",
                "Transfer mode: 'octet' or 'netascii' (default: octet)",
                false,
            ),
        ],
        example: json!({
            "type": "tftp_write_file",
            "filename": "config.txt",
            "mode": "octet"
        }),
        log_template: None,
    }
}

fn send_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ack".to_string(),
        description: "Acknowledge a received DATA block".to_string(),
        parameters: vec![param(
            "block_number",
            "number",
            "Block number to acknowledge (echo the one from the event)",
            true,
        )],
        example: json!({
            "type": "send_ack",
            "block_number": 5
        }),
        log_template: None,
    }
}

fn send_data_block_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_data_block".to_string(),
        description: "Send one DATA block to the server. A block shorter than 512 bytes is \
                      the last one and ends the transfer."
            .to_string(),
        parameters: vec![
            param(
                "block_number",
                "number",
                "Block number (one more than the block just acknowledged)",
                true,
            ),
            param(
                "data_hex",
                "string",
                "Block payload, hex-encoded, at most 512 bytes decoded",
                true,
            ),
        ],
        example: json!({
            "type": "send_data_block",
            "block_number": 1,
            "data_hex": "48656c6c6f"
        }),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Abandon the transfer and close the client".to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: None,
    }
}
