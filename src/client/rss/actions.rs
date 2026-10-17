//! RSS client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

/// RSS client connected event
pub static RSS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rss_connected",
        "RSS client initialized and ready to fetch feeds",
        json!({
            "type": "fetch_rss_feed",
            "url": "/tech-news.xml"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "base_url".to_string(),
        type_hint: "string".to_string(),
        description: "Base URL for RSS feeds".to_string(),
        required: true,
    }])
    .with_actions(vec![fetch_rss_feed_action(), disconnect_action()])
});

/// RSS client feed fetched event
pub static RSS_CLIENT_FEED_FETCHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rss_feed_fetched",
        "RSS feed fetched and parsed",
        json!({"type": "disconnect"}),
    )
    .with_actions(vec![
        fetch_rss_feed_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "url".to_string(),
            type_hint: "string".to_string(),
            description: "Feed URL".to_string(),
            required: true,
        },
        Parameter {
            name: "feed_title".to_string(),
            type_hint: "string".to_string(),
            description: "Feed title".to_string(),
            required: true,
        },
        Parameter {
            name: "feed_link".to_string(),
            type_hint: "string".to_string(),
            description: "Feed link (website URL)".to_string(),
            required: true,
        },
        Parameter {
            name: "feed_description".to_string(),
            type_hint: "string".to_string(),
            description: "Feed description".to_string(),
            required: true,
        },
        Parameter {
            name: "item_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of items in feed".to_string(),
            required: true,
        },
        Parameter {
            name: "items".to_string(),
            type_hint: "array".to_string(),
            description: "Array of feed items".to_string(),
            required: true,
        },
    ])
});

/// RSS client protocol action handler
pub struct RssClientProtocol;

impl Default for RssClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl RssClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// Fetch a feed. `url` may be absolute (`http://host/feed.xml`) or a path relative to the
/// address the client was opened on (`/feed.xml`).
fn fetch_rss_feed_action() -> ActionDefinition {
    ActionDefinition {
        name: "fetch_rss_feed".to_string(),
        description: "Fetch and parse an RSS 2.0 feed. The url may be absolute or a path \
                      relative to the address this client was opened on."
            .to_string(),
        parameters: vec![Parameter {
            name: "url".to_string(),
            type_hint: "string".to_string(),
            description: "Feed URL or path (e.g. '/news.xml' or 'http://example.com/feed.xml')"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "fetch_rss_feed",
            "url": "/tech-news.xml"
        }),
        log_template: None,
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Do nothing further with this feed and wait for more input".to_string(),
        parameters: vec![],
        example: json!({ "type": "wait_for_more" }),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Stop the RSS client".to_string(),
        parameters: vec![],
        example: json!({ "type": "disconnect" }),
        log_template: None,
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for RssClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        Vec::new()
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![fetch_rss_feed_action(), disconnect_action()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            fetch_rss_feed_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "RSS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            RSS_CLIENT_CONNECTED_EVENT.clone(),
            RSS_CLIENT_FEED_FETCHED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RSS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["rss", "rss client", "feed reader", "syndication"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "reqwest HTTP GET + the `rss` crate for RSS 2.0 parsing. Items are handed \
                 to the model as structured JSON, never raw XML. No conditional requests \
                 (no ETag / If-Modified-Since), no Atom, no autodiscovery.",
            )
            .llm_control("Feed selection, item filtering, content interpretation")
            .e2e_testing(
                "Validated against a plain in-test HTTP listener serving RSS 2.0 XML, and \
                 against feed bytes produced independently of the `rss` crate. Not yet run \
                 against a third-party feed server.",
            )
            .notes(
                "Re-enabled 2026-08; had been commented out of the registry since 2025-11 \
                 pending the call_llm_for_client signature change. Chained fetches are \
                 capped at 16 per client.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "RSS feed client for reading web syndication feeds"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to localhost:8080 via rss and fetch /tech-news.xml, show me the latest 5 items"
    }

    fn group_name(&self) -> &'static str {
        "Web"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls RSS feed fetching
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "rss",
                "instruction": "Fetch the RSS feed at /news.xml and summarize recent articles"
            }),
            // Script mode: Code-based feed processing
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "rss",
                "event_handlers": [{
                    "event_pattern": "rss_feed_fetched",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<rss_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed feed fetch
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "rss",
                "event_handlers": [
                    {
                        "event_pattern": "rss_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "fetch_rss_feed",
                                "url": "http://example.com/news.xml"
                            }]
                        }
                    },
                    {
                        "event_pattern": "rss_feed_fetched",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for RssClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            crate::client::rss::RssClient::connect_with_llm_actions(
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
            "fetch_rss_feed" => {
                let url = action
                    .get("url")
                    .and_then(|v| v.as_str())
                    .context("Missing 'url' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "fetch_rss_feed".to_string(),
                    data: json!({ "url": url }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!("Unknown RSS client action: {action_type}")),
        }
    }
}
