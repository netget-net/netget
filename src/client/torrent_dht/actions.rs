//! BitTorrent DHT client protocol actions implementation

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

/// DHT response event
pub static DHT_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dht_response",
        "Received response from DHT node",
        // Not a placeholder. `{"type": "placeholder", ...}` is what this carried, and
        // `execute_action` rejects it outright as `Unknown DHT client action: placeholder` --
        // so a model copying the one example it was shown got a hard error. A follow-up query
        // is the realistic answer to a response; `wait_for_more` and `disconnect` are the
        // other two.
        json!({
            "type": "dht_find_node",
            "node_id": "0123456789abcdef0123456789abcdef01234567",
            "target": "fedcba9876543210fedcba9876543210fedcba98"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Message type: q (query), r (response), e (error)".to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "Query type: ping, find_node, get_peers, announce_peer".to_string(),
            required: false,
        },
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "Response data from node".to_string(),
            required: false,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Error information if any".to_string(),
            required: false,
        },
        Parameter {
            name: "peer".to_string(),
            type_hint: "string".to_string(),
            description: "Address of responding peer".to_string(),
            required: false,
        },
    ])
});

/// BitTorrent DHT client protocol action handler
pub struct TorrentDhtClientProtocol;

impl TorrentDhtClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentDhtClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "dht_ping".to_string(),
                description: "Ping a DHT node".to_string(),
                parameters: vec![
                    Parameter {
                        name: "node_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our node ID: exactly 40 hex characters (20 bytes). Not text -- \"abcdefghij0123456789\" is rejected.".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "transaction_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Transaction ID, hex-encoded (KRPC uses 2 bytes, so 4 hex characters). Omit it and a fresh one is generated; the reply echoes it back.".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "dht_ping",
                    "node_id": "0123456789abcdef0123456789abcdef01234567",
                    "transaction_id": "0001"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "dht_find_node".to_string(),
                description: "Find nodes close to a target ID".to_string(),
                parameters: vec![
                    Parameter {
                        name: "node_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our node ID: exactly 40 hex characters (20 bytes). Not text -- \"abcdefghij0123456789\" is rejected.".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target node ID to find: exactly 40 hex characters (20 bytes).".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "transaction_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Transaction ID, hex-encoded (KRPC uses 2 bytes, so 4 hex characters). Omit it and a fresh one is generated; the reply echoes it back.".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "dht_find_node",
                    "node_id": "0123456789abcdef0123456789abcdef01234567",
                    "target": "fedcba9876543210fedcba9876543210fedcba98",
                    "transaction_id": "0002"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "dht_get_peers".to_string(),
                description: "Get peers for an info_hash".to_string(),
                parameters: vec![
                    Parameter {
                        name: "node_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our node ID: exactly 40 hex characters (20 bytes). Not text -- \"abcdefghij0123456789\" is rejected.".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "info_hash".to_string(),
                        type_hint: "string".to_string(),
                        description: "Info hash to query: exactly 40 hex characters (20 bytes).".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "transaction_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Transaction ID, hex-encoded (KRPC uses 2 bytes, so 4 hex characters). Omit it and a fresh one is generated; the reply echoes it back.".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "dht_get_peers",
                    "node_id": "0123456789abcdef0123456789abcdef01234567",
                    "info_hash": "1111111111111111111111111111111111111111",
                    "transaction_id": "0003"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "dht_announce_peer".to_string(),
                description: "Announce that we have a torrent".to_string(),
                parameters: vec![
                    Parameter {
                        name: "node_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our node ID: exactly 40 hex characters (20 bytes). Not text -- \"abcdefghij0123456789\" is rejected.".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "info_hash".to_string(),
                        type_hint: "string".to_string(),
                        description: "Info hash to announce: exactly 40 hex characters (20 bytes).".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "transaction_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Transaction ID, hex-encoded (KRPC uses 2 bytes, so 4 hex characters). Omit it and a fresh one is generated; the reply echoes it back.".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "dht_announce_peer",
                    "node_id": "0123456789abcdef0123456789abcdef01234567",
                    "info_hash": "1111111111111111111111111111111111111111",
                    "transaction_id": "0004"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from DHT".to_string(),
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
        "BitTorrent DHT"
    }
    /// Clone the static the client actually emits, rather than rebuilding it.
    ///
    /// This used to construct a second, parameterless `dht_response` with a `"placeholder"`
    /// example. That is the copy the model is shown -- `DHT_RESPONSE_EVENT` is only ever used
    /// at the emit site -- so every field the event carries was invisible to it and the single
    /// example it was given is one `execute_action` refuses. Two definitions of one event
    /// drift; one cannot.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DHT_RESPONSE_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BitTorrent-DHT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bittorrent", "dht", "kademlia", "distributed hash table"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("UDP-based Kademlia DHT with bencode messages")
            .llm_control(
                "Full control over DHT queries (ping, find_node, get_peers, announce_peer)",
            )
            .e2e_testing("Mock DHT node")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent DHT client for distributed peer discovery"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to DHT node at router.bittorrent.com:6881 and find peers for info_hash xyz"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles DHT queries
            json!({
                "type": "open_client",
                "remote_addr": "router.bittorrent.com:6881",
                "base_stack": "torrent-dht",
                "instruction": "Query the DHT for peers with a specific info_hash"
            }),
            // Script mode: Code-based DHT handling
            json!({
                "type": "open_client",
                "remote_addr": "router.bittorrent.com:6881",
                "base_stack": "torrent-dht",
                "event_handlers": [{
                    "event_pattern": "dht_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dht_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DHT action
            json!({
                "type": "open_client",
                "remote_addr": "router.bittorrent.com:6881",
                "base_stack": "torrent-dht",
                "event_handlers": [{
                    "event_pattern": "dht_response",
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
impl Client for TorrentDhtClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::torrent_dht::TorrentDhtClient;
            TorrentDhtClient::connect_with_llm_actions(
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

        // The four query actions are what `get_async_actions()` advertises, but this match
        // used to accept only `dht_query` — a name declared nowhere. So a model that used a
        // tool name (`dht_ping`) was rejected as an unknown action, and only a model that
        // copied the *example* verbatim, which contradicted the action's own name by saying
        // `{"type": "dht_query", "query_type": "ping"}`, happened to work. Translate the
        // advertised name into the wire query type here; `dht_query` stays accepted so a
        // caller that learned the old shape still works.
        let query_type = match action_type {
            "dht_ping" => Some("ping"),
            "dht_find_node" => Some("find_node"),
            "dht_get_peers" => Some("get_peers"),
            "dht_announce_peer" => Some("announce_peer"),
            _ => None,
        };

        if let Some(query_type) = query_type {
            let mut data = action;
            let obj = data
                .as_object_mut()
                .context("DHT action must be a JSON object")?;
            // An explicit query_type is honoured, so `dht_query` semantics are unchanged.
            obj.entry("query_type")
                .or_insert_with(|| serde_json::Value::String(query_type.to_string()));
            return Ok(ClientActionResult::Custom {
                name: "dht_query".to_string(),
                data,
            });
        }

        match action_type {
            "dht_query" => Ok(ClientActionResult::Custom {
                name: "dht_query".to_string(),
                data: action,
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown DHT client action: {}",
                action_type
            )),
        }
    }
}
