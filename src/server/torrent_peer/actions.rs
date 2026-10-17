//! BitTorrent Peer Wire Protocol actions implementation

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

pub struct TorrentPeerProtocol;

impl TorrentPeerProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentPeerProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // The two read deadlines, and nothing else. BEP 3 has no negotiable listener options,
        // but who is on the other end decides both of these and only the operator knows that:
        // the defaults serve NetGet's own peer client, which waits for our handshake before
        // sending its own, while a listener on a public swarm wants the first one much lower.
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no handshake before the server \
                              closes it. Default 300, matching the window a `manual` rule \
                              gives a human to answer one event. The peer is often NetGet's \
                              own torrent_peer client, whose read loop blocks on the other \
                              side's 68-byte handshake and only sends its own when the \
                              send_handshake action says to - so both ends wait, and a short \
                              bound makes this end give up first. Lower it (30 was the old \
                              value) for a listener on a public swarm."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::HANDSHAKE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a handshaked peer may go without a further message \
                              before the server closes it. Default 180: the peer wire \
                              protocol's keep-alive runs about every two minutes, so this \
                              gives a conforming peer a full missed keep-alive of slack."
                    .to_string(),
                required: false,
                example: json!(180),
                default: Some(serde_json::json!(
                    super::IDLE_AFTER_HANDSHAKE_TIMEOUT.as_secs()
                )),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            SEND_HANDSHAKE_ACTION.clone(),
            SEND_CHOKE_ACTION.clone(),
            SEND_UNCHOKE_ACTION.clone(),
            SEND_INTERESTED_ACTION.clone(),
            SEND_NOT_INTERESTED_ACTION.clone(),
            SEND_BITFIELD_ACTION.clone(),
            SEND_HAVE_ACTION.clone(),
            SEND_PIECE_ACTION.clone(),
            SEND_KEEPALIVE_ACTION.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Torrent-Peer"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            PEER_HANDSHAKE_EVENT.clone(),
            PEER_CHOKE_MESSAGE_EVENT.clone(),
            PEER_REQUEST_MESSAGE_EVENT.clone(),
            PEER_BITFIELD_MESSAGE_EVENT.clone(),
            PEER_MESSAGE_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BitTorrent-Peer"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["torrent-peer", "peer", "seeder"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(6881)
            .implementation("TCP peer wire protocol with binary encoding")
            .llm_control("Piece transfer, choke/unchoke, bitfield")
            .e2e_testing("tests/server/torrent_peer/{e2e_test,peer_inject_test,llm_failure_test}.rs, 7 LLM calls, none #[ignore]d. NO third-party BitTorrent client is involved: the peer is a raw TcpStream with hand-built 68-byte handshakes and length-prefixed frames, which is an independent *reading* of BEP 3 rather than an independent implementation. This field claimed 'Real BitTorrent clients' and no such client appears anywhere in the tree. Covered: handshake + bitfield, a request/piece exchange, the dashboard's injected peer message and disconnect, and the LLM-failure reply (a choke frame, then half-close for the non-transient category). Not tested: any real client, a full piece transfer, cancel/have handling, the extension protocol.")
            .notes("Binary protocol, peer-to-peer data transfer. Stores nothing - no pieces, no bitfield state; the model answers every request, so it decides what this peer claims to have.")
            .max_inbound_bytes(crate::server::torrent_peer::MAX_PENDING)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent Peer Wire Protocol for peer-to-peer file sharing"
    }
    fn example_prompt(&self) -> &'static str {
        "start a bittorrent peer on port 51413"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: complete the BitTorrent handshake by echoing the info
        // hash, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "peer_handshake":
    actions = [{"type": "send_handshake",
                "info_hash": event.get("info_hash", "")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles BitTorrent peer wire protocol
            json!({
                "type": "open_server",
                "port": 51413,
                "base_stack": "torrent-peer",
                "instruction": "Act as BitTorrent seeder. Respond to handshakes, send bitfield, and serve piece requests"
            }),
            // Script mode: Code-based peer handling
            json!({
                "type": "open_server",
                "port": 51413,
                "base_stack": "torrent-peer",
                "event_handlers": [{
                    "event_pattern": "peer_handshake",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed peer responses
            json!({
                "type": "open_server",
                "port": 51413,
                "base_stack": "torrent-peer",
                "event_handlers": [
                    {
                        "event_pattern": "peer_handshake",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "send_handshake",
                                    "info_hash": "{{event.info_hash}}",
                                    "peer_id": "-NT0001-xxxxxxxxxxxx"
                                },
                                {
                                    "type": "send_bitfield",
                                    "bitfield": "ff"
                                },
                                {
                                    "type": "send_unchoke"
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TorrentPeerProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::torrent_peer::TorrentPeerServer;
            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            TorrentPeerServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field")?;

        match action_type {
            "send_handshake" => self.execute_send_handshake(action),
            "send_choke" => Ok(ActionResult::Output(vec![0, 0, 0, 1, 0])),
            "send_unchoke" => Ok(ActionResult::Output(vec![0, 0, 0, 1, 1])),
            "send_interested" => Ok(ActionResult::Output(vec![0, 0, 0, 1, 2])),
            "send_not_interested" => Ok(ActionResult::Output(vec![0, 0, 0, 1, 3])),
            "send_have" => self.execute_send_have(action),
            "send_bitfield" => self.execute_send_bitfield(action),
            "send_piece" => self.execute_send_piece(action),
            "send_keepalive" => Ok(ActionResult::Output(vec![0, 0, 0, 0])),
            // Not offered to the model (a peer answers messages, it does not hang up on its
            // own), but the dashboard's "disconnect this peer" injects it through the peer
            // command task, which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Peer action: {}", action_type)),
        }
    }
}

impl TorrentPeerProtocol {
    fn execute_send_handshake(&self, action: serde_json::Value) -> Result<ActionResult> {
        let info_hash = hex::decode(
            action
                .get("info_hash")
                .and_then(|v| v.as_str())
                .context("Missing info_hash")?,
        )?;
        // A peer ID is 20 arbitrary bytes. `peer_id` covers the ASCII case models
        // actually produce; `peer_id_hex` covers the rest and wins when both are given.
        let peer_id_bytes = match action.get("peer_id_hex").and_then(|v| v.as_str()) {
            Some(hex_str) => hex::decode(hex_str).context("peer_id_hex is not valid hex")?,
            None => action
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-NT0001-xxxxxxxxxxxx")
                .as_bytes()
                .to_vec(),
        };

        if info_hash.len() != 20 {
            return Err(anyhow::anyhow!(
                "info_hash must be 20 bytes (40 hex chars), got {}",
                info_hash.len()
            ));
        }
        if peer_id_bytes.len() != 20 {
            return Err(anyhow::anyhow!(
                "peer_id must be 20 bytes, got {}",
                peer_id_bytes.len()
            ));
        }

        let mut handshake = Vec::new();
        handshake.push(19u8);
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0u8; 8]);
        handshake.extend_from_slice(&info_hash);
        handshake.extend_from_slice(&peer_id_bytes);

        Ok(ActionResult::Output(handshake))
    }

    fn execute_send_have(&self, action: serde_json::Value) -> Result<ActionResult> {
        let piece_index = action
            .get("piece_index")
            .and_then(|v| v.as_u64())
            .context("Missing piece_index")? as u32;

        let mut message = Vec::new();
        message.extend_from_slice(&5u32.to_be_bytes());
        message.push(4);
        message.extend_from_slice(&piece_index.to_be_bytes());

        Ok(ActionResult::Output(message))
    }

    fn execute_send_bitfield(&self, action: serde_json::Value) -> Result<ActionResult> {
        let bitfield_hex = action
            .get("bitfield")
            .and_then(|v| v.as_str())
            .context("Missing bitfield")?;
        let bitfield = hex::decode(bitfield_hex)?;

        let length = (1 + bitfield.len()) as u32;
        let mut message = Vec::new();
        message.extend_from_slice(&length.to_be_bytes());
        message.push(5);
        message.extend_from_slice(&bitfield);

        Ok(ActionResult::Output(message))
    }

    fn execute_send_piece(&self, action: serde_json::Value) -> Result<ActionResult> {
        let index = action
            .get("index")
            .and_then(|v| v.as_u64())
            .context("Missing index")? as u32;
        let begin = action
            .get("begin")
            .and_then(|v| v.as_u64())
            .context("Missing begin")? as u32;
        let block_hex = action
            .get("block_hex")
            .and_then(|v| v.as_str())
            .context("Missing block_hex")?;
        let block = hex::decode(block_hex)?;

        let length = (9 + block.len()) as u32;
        let mut message = Vec::new();
        message.extend_from_slice(&length.to_be_bytes());
        message.push(7);
        message.extend_from_slice(&index.to_be_bytes());
        message.extend_from_slice(&begin.to_be_bytes());
        message.extend_from_slice(&block);

        Ok(ActionResult::Output(message))
    }
}

/// Every action a peer-wire event can answer with.
///
/// The peer wire protocol has no correlation id and no request/response pairing beyond
/// the handshake: any message is legal at any point after it, so narrowing per event
/// would only hide legitimate replies. The one thing an event must not do is advertise
/// nothing, which is what all four of these used to do.
fn all_peer_actions() -> Vec<ActionDefinition> {
    vec![
        SEND_HANDSHAKE_ACTION.clone(),
        SEND_CHOKE_ACTION.clone(),
        SEND_UNCHOKE_ACTION.clone(),
        SEND_INTERESTED_ACTION.clone(),
        SEND_NOT_INTERESTED_ACTION.clone(),
        SEND_BITFIELD_ACTION.clone(),
        SEND_HAVE_ACTION.clone(),
        SEND_PIECE_ACTION.clone(),
        SEND_KEEPALIVE_ACTION.clone(),
    ]
}

pub static PEER_HANDSHAKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_handshake",
        "BitTorrent peer opened a connection and sent its handshake. Reply with a \
         handshake echoing the same info_hash, then usually a bitfield and an unchoke.",
        json!({
            "type": "send_handshake",
            "info_hash": "0123456789abcdef0123456789abcdef01234567",
            "peer_id": "-NG0001-netgetserver"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "info_hash".to_string(),
            type_hint: "string".to_string(),
            description: "Torrent the peer wants, hex-encoded (40 chars). The handshake \
                          reply must echo it or the peer disconnects; use \
                          \"{{event.info_hash}}\"."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Remote peer's ID rendered as lossy UTF-8. Informational only — \
                          the trailing bytes are usually random, so this may contain \
                          replacement characters."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_id_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Remote peer's 20-byte ID, hex-encoded (40 chars). Faithful form."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(all_peer_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT peer handshake ({duration_ms}ms)")
            .with_debug("BT peer handshake from {client_ip}: info_hash={info_hash}")
            .with_trace("BT handshake: {json_pretty(.)}"),
    )
});

pub static PEER_CHOKE_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_choke_message",
        "Peer sent a payload-free state message: choke, unchoke, interested or \
         not_interested. Check `message_type` to see which.",
        json!({"type": "send_unchoke"}),
    )
    .with_parameters(vec![Parameter {
        name: "message_type".to_string(),
        type_hint: "string".to_string(),
        description: "\"choke\", \"unchoke\", \"interested\" or \"not_interested\"".to_string(),
        required: true,
    }])
    .with_actions(all_peer_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT {message_type}")
            .with_debug("BT peer {message_type} from {client_ip}"),
    )
});

pub static PEER_REQUEST_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_request_message",
        "Peer requested a block of a piece. Answer with send_piece, or with send_choke to \
         refuse.",
        // Concrete numbers, not `"{{event.index}}"`. `execute_send_piece` reads both with
        // `.as_u64()`, so the quoted placeholder fails as `Missing index` — and this is a
        // `response_example`, which is shown to the *model*, where `{{...}}` is not
        // interpolated at all (only static handlers get that). `SEND_HANDSHAKE_ACTION`'s
        // own comment records dodging exactly this trap by using real hex in its example;
        // this event reintroduced it. Copy the event's own numeric `index` and `begin`.
        json!({
            "type": "send_piece",
            "index": 0,
            "begin": 0,
            "block_hex": "48656c6c6f20576f726c64"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Always \"request\"".to_string(),
            required: true,
        },
        Parameter {
            name: "index".to_string(),
            type_hint: "number".to_string(),
            description: "Piece index. Echo it in send_piece or the peer discards the block."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "begin".to_string(),
            type_hint: "number".to_string(),
            description: "Byte offset within the piece. Echo it in send_piece.".to_string(),
            required: true,
        },
        Parameter {
            name: "length".to_string(),
            type_hint: "number".to_string(),
            description: "Bytes requested, typically 16384. send_piece should return \
                          exactly this many bytes."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(all_peer_actions())
    .with_alternative_example(json!({"type": "send_choke"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT request piece {index}")
            .with_debug("BT peer request: piece={index}, begin={begin}, length={length}"),
    )
});

pub static PEER_BITFIELD_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_bitfield_message",
        "Peer announced which pieces it holds",
        json!({"type": "send_interested"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Always \"bitfield\"".to_string(),
            required: true,
        },
        Parameter {
            name: "bitfield".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded bitfield, one bit per piece, most significant bit \
                          first. \"ff\" means the peer has pieces 0-7."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(all_peer_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT bitfield")
            .with_debug("BT peer bitfield from {client_ip}")
            .with_trace("BT bitfield: {bitfield}"),
    )
});

pub static PEER_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "peer_message",
        "Peer sent a have, piece, cancel or keep-alive message, or a message id this \
         server does not decode. Check `message_type`.",
        json!({"type": "send_keepalive"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"have\", \"piece\", \"cancel\", \"keepalive\" or \"unknown\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "piece_index".to_string(),
            type_hint: "number".to_string(),
            description: "Piece the peer now has (message_type \"have\" only)".to_string(),
            required: false,
        },
        Parameter {
            name: "index".to_string(),
            type_hint: "number".to_string(),
            description: "Piece index (message_type \"piece\" or \"cancel\")".to_string(),
            required: false,
        },
        Parameter {
            name: "begin".to_string(),
            type_hint: "number".to_string(),
            description: "Byte offset (message_type \"piece\" or \"cancel\")".to_string(),
            required: false,
        },
        Parameter {
            name: "block_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded block the peer sent (message_type \"piece\")".to_string(),
            required: false,
        },
        Parameter {
            name: "id".to_string(),
            type_hint: "number".to_string(),
            description: "Raw message id (message_type \"unknown\")".to_string(),
            required: false,
        },
        Parameter {
            name: "payload_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded undecoded payload (message_type \"unknown\")".to_string(),
            required: false,
        },
    ])
    .with_actions(all_peer_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT {message_type}")
            .with_debug("BT peer {message_type} from {client_ip}")
            .with_trace("BT message: {json_pretty(.)}"),
    )
});

pub static SEND_HANDSHAKE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_handshake".to_string(),
    description: "Send the 68-byte BitTorrent handshake. The info_hash must match the one \
                  the peer sent or it will drop the connection."
        .to_string(),
    parameters: vec![
        Parameter {
            name: "info_hash".to_string(),
            type_hint: "string".to_string(),
            description: "Torrent info hash, hex-encoded (exactly 40 hex chars = 20 bytes), \
                          echoing the event's info_hash. A static handler writes the literal \
                          \"{{event.info_hash}}\", which is substituted before the action \
                          runs; an LLM answer must carry the real hex."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Our peer ID as exactly 20 ASCII bytes (default \
                          \"-NT0001-xxxxxxxxxxxx\"). For a non-ASCII ID use peer_id_hex \
                          instead."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "peer_id_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Our peer ID as 40 hex chars. Takes precedence over peer_id.".to_string(),
            required: false,
        },
    ],
    // A real 40-hex-char info_hash, not "{{event.info_hash}}": that substitution
    // only happens for static event handlers, so a model copying the template
    // hands the executor a value that is neither valid hex nor 20 bytes.
    example: json!({"type": "send_handshake", "info_hash": "0123456789abcdef0123456789abcdef01234567", "peer_id": "-NT0001-xxxxxxxxxxxx"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> BT handshake")
            .with_debug("BT send handshake: peer_id={peer_id}"),
    ),
});

pub static SEND_INTERESTED_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "send_interested".to_string(),
        description: "Tell the peer we want pieces it holds".to_string(),
        parameters: vec![],
        example: json!({"type": "send_interested"}),
        log_template: Some(LogTemplate::new().with_info("-> BT interested")),
    });

pub static SEND_NOT_INTERESTED_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "send_not_interested".to_string(),
        description: "Tell the peer we want nothing it holds".to_string(),
        parameters: vec![],
        example: json!({"type": "send_not_interested"}),
        log_template: Some(LogTemplate::new().with_info("-> BT not_interested")),
    });

pub static SEND_KEEPALIVE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_keepalive".to_string(),
    description: "Send a zero-length keep-alive so the peer does not time the connection out"
        .to_string(),
    parameters: vec![],
    example: json!({"type": "send_keepalive"}),
    log_template: Some(LogTemplate::new().with_info("-> BT keepalive")),
});

pub static SEND_CHOKE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_choke".to_string(),
    description: "Send choke message".to_string(),
    parameters: vec![],
    example: json!({"type": "send_choke"}),
    log_template: Some(LogTemplate::new().with_info("-> BT choke")),
});

pub static SEND_UNCHOKE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_unchoke".to_string(),
    description: "Send unchoke message".to_string(),
    parameters: vec![],
    example: json!({"type": "send_unchoke"}),
    log_template: Some(LogTemplate::new().with_info("-> BT unchoke")),
});

pub static SEND_BITFIELD_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_bitfield".to_string(),
    description: "Send bitfield message".to_string(),
    parameters: vec![Parameter {
        name: "bitfield".to_string(),
        type_hint: "string".to_string(),
        description: "Bitfield (hex)".to_string(),
        required: true,
    }],
    example: json!({"type": "send_bitfield", "bitfield": "ff"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> BT bitfield")
            .with_debug("BT send bitfield: {bitfield}"),
    ),
});

pub static SEND_HAVE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_have".to_string(),
    description: "Send have message".to_string(),
    parameters: vec![Parameter {
        name: "piece_index".to_string(),
        type_hint: "number".to_string(),
        description: "Piece index".to_string(),
        required: true,
    }],
    example: json!({"type": "send_have", "piece_index": 0}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> BT have piece {piece_index}")
            .with_debug("BT send have: piece_index={piece_index}"),
    ),
});

pub static SEND_PIECE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_piece".to_string(),
    description: "Send piece data".to_string(),
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
            description: "Byte offset".to_string(),
            required: true,
        },
        Parameter {
            name: "block_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Block data (hex)".to_string(),
            required: true,
        },
    ],
    example: json!({"type": "send_piece", "index": 0, "begin": 0, "block_hex": "00112233"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> BT piece {index} @{begin}")
            .with_debug("BT send piece: index={index}, begin={begin}, block_len={block_hex_len}"),
    ),
});
