//! BitTorrent Peer Wire Protocol client actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Peer handshake event
pub static PEER_HANDSHAKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_handshake",
        "Received handshake from BitTorrent peer",
        // Not `{"type": "placeholder", ...}`, which `execute_action` refuses outright as
        // `Unknown Peer client action: placeholder` — the single example the model was shown
        // was one it would be rejected for copying. Declaring interest is the realistic
        // answer to a completed handshake.
        json!({"type": "peer_interested"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "info_hash".to_string(),
            type_hint: "string".to_string(),
            description: "Info hash (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Peer ID (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "reserved".to_string(),
            type_hint: "string".to_string(),
            description: "Reserved bytes (hex)".to_string(),
            required: false,
        },
    ])
});

/// Peer message event
pub static PEER_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_message",
        "Received message from BitTorrent peer",
        // Not a placeholder — see PEER_HANDSHAKE_EVENT above. Requesting a block is the
        // realistic answer to a peer that has just unchoked or advertised a piece.
        json!({"type": "peer_request_piece", "index": 0, "begin": 0, "length": 16384}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "number".to_string(),
            description: "Message type (0=choke, 1=unchoke, 2=interested, 3=not_interested, 4=have, 5=bitfield, 6=request, 7=piece, 8=cancel, 9=port)".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_len".to_string(),
            type_hint: "number".to_string(),
            description: "Payload length".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Payload data (hex)".to_string(),
            required: false,
        },
    ])
});

/// BitTorrent Peer Wire Protocol client protocol action handler
pub struct TorrentPeerClientProtocol;

impl TorrentPeerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentPeerClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "peer_handshake".to_string(),
                description: "Send handshake to peer".to_string(),
                parameters: vec![
                    Parameter {
                        name: "info_hash".to_string(),
                        type_hint: "string".to_string(),
                        description: "Info hash (40 char hex)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "peer_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our peer ID (40 char hex)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "peer_handshake",
                    "info_hash": "0123456789abcdef0123456789abcdef01234567",
                    "peer_id": "abcdef0123456789abcdef0123456789abcdef01"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "peer_interested".to_string(),
                description: "Send interested message".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "peer_interested"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "peer_not_interested".to_string(),
                description: "Send not interested message".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "peer_not_interested"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "peer_request_piece".to_string(),
                description: "Request a piece from peer".to_string(),
                parameters: vec![
                    Parameter {
                        name: "index".to_string(),
                        type_hint: "number".to_string(),
                        description: "Piece index".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "begin".to_string(),
                        type_hint: "number".to_string(),
                        description: "Byte offset within piece".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "length".to_string(),
                        type_hint: "number".to_string(),
                        description: "Block length to request".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "peer_request_piece",
                    "index": 0,
                    "begin": 0,
                    "length": 16384
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "peer_send_piece".to_string(),
                description: "Send a piece to peer".to_string(),
                parameters: vec![
                    Parameter {
                        name: "index".to_string(),
                        type_hint: "number".to_string(),
                        description: "Piece index".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "begin".to_string(),
                        type_hint: "number".to_string(),
                        description: "Byte offset within piece".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "block".to_string(),
                        type_hint: "string".to_string(),
                        description: "Block data (hex)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "peer_send_piece",
                    "index": 0,
                    "begin": 0,
                    "block": "abcdef0123"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from peer".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn protocol_name(&self) -> &'static str {
        "BitTorrent Peer Wire"
    }
    /// Clone the statics the client actually emits, rather than rebuilding them.
    ///
    /// This used to construct a second, parameterless pair. `get_event_types()` is the copy
    /// the model is shown — the statics are used only at the emit site — so every field
    /// `with_parameters` declares was invisible to it. Two definitions of one event drift;
    /// one cannot.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![PEER_HANDSHAKE_EVENT.clone(), PEER_MESSAGE_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BitTorrent-PeerWire"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bittorrent", "peer", "peer wire", "torrent peer"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .implementation("TCP-based peer wire protocol with handshake and message framing")
                .llm_control("Full control over peer messages (choke, unchoke, interested, request, piece, etc.)")
                .e2e_testing("Mock peer server")
                .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent Peer Wire Protocol client for peer-to-peer data transfer"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to peer at 192.168.1.100:6881 and exchange pieces for info_hash xyz"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles peer wire protocol
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:6881",
                "base_stack": "torrent-peer",
                "instruction": "Connect to peer and exchange pieces for a torrent"
            }),
            // Script mode: Code-based peer handling
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:6881",
                "base_stack": "torrent-peer",
                "event_handlers": [{
                    "event_pattern": "peer_handshake",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<peer_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed peer action
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:6881",
                "base_stack": "torrent-peer",
                "event_handlers": [{
                    "event_pattern": "peer_message",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "disconnect"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for TorrentPeerClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::torrent_peer::TorrentPeerClient;
            TorrentPeerClient::connect_with_llm_actions(
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
        fn u32_field(action: &serde_json::Value, name: &str) -> Result<u32> {
            let raw = action
                .get(name)
                .and_then(|v| v.as_u64())
                .with_context(|| format!("missing or non-numeric '{}'", name))?;
            u32::try_from(raw).with_context(|| format!("'{}' does not fit in u32", name))
        }

        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        // `peer_interested`, `peer_not_interested`, `peer_request_piece` and `peer_send_piece`
        // are advertised by `get_async_actions()` but used to be rejected here as unknown:
        // only `peer_message` was accepted, and that name was declared nowhere. Each of the
        // four is a fixed BEP 3 message id with a payload derived from its own parameters, so
        // build that payload here rather than making the model hand-assemble the hex it was
        // shown in a contradictory example.
        let framed = match action_type {
            // interested (2) and not-interested (3) carry no payload.
            "peer_interested" => Some((2u8, String::new())),
            "peer_not_interested" => Some((3u8, String::new())),
            // request (6): <index><begin><length>, three big-endian u32.
            "peer_request_piece" => {
                let index = u32_field(&action, "index")?;
                let begin = u32_field(&action, "begin")?;
                let length = u32_field(&action, "length")?;
                let mut payload = Vec::with_capacity(12);
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(&length.to_be_bytes());
                Some((6u8, hex::encode(payload)))
            }
            // piece (7): <index><begin><block>, two big-endian u32 then the raw block.
            "peer_send_piece" => {
                let index = u32_field(&action, "index")?;
                let begin = u32_field(&action, "begin")?;
                let block_hex = action
                    .get("block")
                    .and_then(|v| v.as_str())
                    .context("peer_send_piece requires 'block' (hex-encoded block data)")?;
                let block = hex::decode(block_hex)
                    .context("peer_send_piece 'block' must be hex-encoded")?;
                let mut payload = Vec::with_capacity(8 + block.len());
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(&block);
                Some((7u8, hex::encode(payload)))
            }
            _ => None,
        };

        if let Some((message_type, payload)) = framed {
            return Ok(ClientActionResult::Custom {
                name: "peer_message".to_string(),
                data: serde_json::json!({
                    "type": "peer_message",
                    "message_type": message_type,
                    "payload": payload,
                }),
            });
        }

        match action_type {
            "peer_handshake" => Ok(ClientActionResult::Custom {
                name: "peer_handshake".to_string(),
                data: action,
            }),
            // Kept so a caller that learned the raw shape still works; it is the escape hatch
            // for message ids the four named actions above do not cover (have, bitfield, …).
            "peer_message" => Ok(ClientActionResult::Custom {
                name: "peer_message".to_string(),
                data: action,
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Peer client action: {}",
                action_type
            )),
        }
    }
}
