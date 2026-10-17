//! BitTorrent Tracker client protocol actions implementation

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

/// Tracker announce response event
pub static TRACKER_ANNOUNCE_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tracker_announce_response",
        "Received announce response from BitTorrent tracker",
        json!({
            "type": "disconnect"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "interval".to_string(),
            type_hint: "number".to_string(),
            description: "Time in seconds to wait before next announce".to_string(),
            required: false,
        },
        Parameter {
            name: "complete".to_string(),
            type_hint: "number".to_string(),
            description: "Number of seeders".to_string(),
            required: false,
        },
        Parameter {
            name: "incomplete".to_string(),
            type_hint: "number".to_string(),
            description: "Number of leechers".to_string(),
            required: false,
        },
        Parameter {
            name: "peers".to_string(),
            type_hint: "string".to_string(),
            description: "Peer list from tracker".to_string(),
            required: false,
        },
    ])
});

/// Tracker scrape response event
pub static TRACKER_SCRAPE_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tracker_scrape_response",
        "Received scrape response from BitTorrent tracker",
        json!({
            "type": "disconnect"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "files".to_string(),
        type_hint: "string".to_string(),
        description: "File statistics from tracker".to_string(),
        required: false,
    }])
});

/// BitTorrent Tracker client protocol action handler
pub struct TorrentTrackerClientProtocol;

impl TorrentTrackerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentTrackerClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "tracker_announce".to_string(),
                description: "Announce to the BitTorrent tracker".to_string(),
                parameters: vec![
                    Parameter {
                        name: "info_hash".to_string(),
                        type_hint: "string".to_string(),
                        description: "The torrent's 20-byte info_hash. Percent-encoding is \
                                      applied for you, so send it however you have it \
                                      (40 hex characters is the usual form); a value that \
                                      is already percent-encoded is also accepted."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "peer_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our 20-byte peer id, e.g. \"-NG0001-abcdefghijkl\". \
                                      Percent-encoding is applied for you."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "port".to_string(),
                        type_hint: "number".to_string(),
                        description: "Port number for peer connections".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "uploaded".to_string(),
                        type_hint: "number".to_string(),
                        description: "Bytes uploaded".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "downloaded".to_string(),
                        type_hint: "number".to_string(),
                        description: "Bytes downloaded".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "left".to_string(),
                        type_hint: "number".to_string(),
                        description: "Bytes still to download. BEP 3 reads 0 as \"I have the \
                                      complete torrent\", which is what makes a tracker \
                                      treat us as a seeder -- so send a real figure. Omit \
                                      it and no completeness is claimed."
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "event".to_string(),
                        type_hint: "string".to_string(),
                        description: "Event type: started, completed, stopped".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "tracker_announce",
                    "info_hash": "%12%34%56%78%90%AB%CD%EF%12%34%56%78%90%AB%CD%EF%12%34%56%78",
                    "peer_id": "-TR2940-abcdefghijkl",
                    "port": 6881,
                    "uploaded": 0,
                    "downloaded": 0,
                    "left": 1024000,
                    "event": "started"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "tracker_scrape".to_string(),
                description: "Scrape statistics from the BitTorrent tracker".to_string(),
                parameters: vec![Parameter {
                    name: "info_hash".to_string(),
                    type_hint: "string".to_string(),
                    description: "The torrent's 20-byte info_hash to scrape. \
                                  Percent-encoding is applied for you."
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "tracker_scrape",
                    "info_hash": "%12%34%56%78%90%AB%CD%EF%12%34%56%78%90%AB%CD%EF%12%34%56%78"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the tracker".to_string(),
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
        "BitTorrent Tracker"
    }
    /// Clones of the statics the client actually emits, so the declaration cannot drift from
    /// what is raised.
    ///
    /// These used to be rebuilt by hand here, and the two copies had already diverged: the
    /// rebuilt pair carried no `with_parameters`, so the model was never told an announce
    /// response contains `interval`, `complete`, `incomplete` and `peers` — the entire content
    /// of the event it was being asked about — and their example action was a literal
    /// `{"type": "placeholder"}`, which is not a verb this protocol can execute.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TRACKER_ANNOUNCE_RESPONSE_EVENT.clone(),
            TRACKER_SCRAPE_RESPONSE_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>BitTorrent-Tracker"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bittorrent",
            "tracker",
            "torrent tracker",
            "announce",
            "scrape",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("HTTP GET with bencode response parsing")
            .llm_control("Full control over tracker announces and scrapes")
            .e2e_testing("Mock tracker server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent tracker client for peer discovery"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to tracker at http://tracker.example.com:6969/announce and announce with info_hash xyz"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles tracker communication
            json!({
                "type": "open_client",
                "remote_addr": "tracker.example.com:6969",
                "base_stack": "torrent-tracker",
                "instruction": "Announce to the tracker with info_hash and get peer list"
            }),
            // Script mode: Code-based tracker handling
            json!({
                "type": "open_client",
                "remote_addr": "tracker.example.com:6969",
                "base_stack": "torrent-tracker",
                "event_handlers": [{
                    "event_pattern": "tracker_announce_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<tracker_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed tracker action
            json!({
                "type": "open_client",
                "remote_addr": "tracker.example.com:6969",
                "base_stack": "torrent-tracker",
                "event_handlers": [{
                    "event_pattern": "tracker_announce_response",
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
impl Client for TorrentTrackerClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::torrent_tracker::TorrentTrackerClient;
            TorrentTrackerClient::connect_with_llm_actions(
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
            "tracker_announce" => Ok(ClientActionResult::Custom {
                name: "tracker_announce".to_string(),
                data: action,
            }),
            "tracker_scrape" => Ok(ClientActionResult::Custom {
                name: "tracker_scrape".to_string(),
                data: action,
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Tracker client action: {}",
                action_type
            )),
        }
    }
}
