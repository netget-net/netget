//! RSS protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::pin::Pin;
use std::sync::LazyLock;

/// RSS feed requested event - fired when a client requests a feed
pub static RSS_FEED_REQUESTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rss_feed_requested",
        "A client requested an RSS feed. Answer with generate_rss_feed; the server renders the \
         XML from the fields you supply.",
        json!({
            "type": "generate_rss_feed",
            "title": "NetGet News",
            "link": "http://localhost/news.xml",
            "description": "Latest headlines",
            "items": [{
                "title": "First post",
                "link": "http://localhost/1",
                "description": "Hello world"
            }]
        }),
    )
    // The protocol's only sync action, and its only event. `call_llm` advertises the event's
    // action list rather than get_sync_actions(), so leaving this empty meant every
    // generate_rss_feed the model produced was rejected as an unknown action.
    .with_actions(vec![generate_rss_feed_action()])
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Feed path (e.g., /news.xml)".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "HTTP request headers".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("RSS request")
            .with_debug("RSS feed request")
            .with_trace("RSS: {json_pretty(.)}"),
    )
});

/// RSS protocol action handler
pub struct RssProtocol;

impl RssProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for RssProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        Vec::new()
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // RSS has no async actions - feeds are generated on request
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![generate_rss_feed_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "RSS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![RSS_FEED_REQUESTED_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RSS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["rss", "rss server", "feed", "syndication", "via rss"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("rss crate for RSS 2.0 XML generation, served over HTTP")
            .llm_control("Feed content generation (title, items, categories)")
            .e2e_testing(
                "feed-rs 2 is the independent reader: it parses the served feed, identifies it \
                 as FeedType::RSS2, and the test asserts channel title, description and \
                 language, three entries, the first entry's title and link, that its RFC 2822 \
                 pub_date parsed into a real timestamp, and its categories \
                 (tests/server/rss/e2e_test.rs, not #[ignore]d). The parser matters more than \
                 usual here: this server builds its XML with the `rss` crate, so parsing it \
                 back with the `rss` crate — which is what this test used to do — proved only \
                 that one crate round-trips through itself. RSS has no session, so \
                 fetch-and-parse is the whole protocol; reqwest does the GET, feed-rs is the \
                 evidence. Not proven: conditional GET / If-Modified-Since, feed \
                 autodiscovery, Atom.",
            )
            .request_only(
                "RSS is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "RSS feed server for web syndication"
    }

    fn example_prompt(&self) -> &'static str {
        "Create an RSS feed server on port 8080 serving tech news at /tech.xml with categories"
    }

    fn group_name(&self) -> &'static str {
        "Web"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: serve a fixed (empty) RSS feed for every request, no
        // LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "rss_feed_requested":
    actions = [{"type": "generate_rss_feed", "title": "NetGet Feed",
                "link": "http://localhost:8080", "description": "NetGet RSS feed",
                "items": []}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all RSS feed requests intelligently
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "rss",
                "instruction": "RSS feed server generating dynamic feeds"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "rss",
                "event_handlers": [{
                    "event_pattern": "rss_feed_requested",
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
                "port": 8080,
                "base_stack": "rss",
                "event_handlers": [{
                    "event_pattern": "rss_feed_requested",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "generate_rss_feed",
                            "title": "Default Feed",
                            "link": "http://localhost:8080",
                            "description": "Default RSS feed",
                            "items": []
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for RssProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>> {
        Box::pin(async move {
            use crate::server::rss::RssServer;

            RssServer::spawn_with_llm_actions(
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
            "generate_rss_feed" => self.execute_generate_feed(action),
            _ => Err(anyhow::anyhow!("Unknown RSS action: {action_type}")),
        }
    }
}

impl RssProtocol {
    /// Execute generate_rss_feed sync action
    fn execute_generate_feed(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Validate here rather than in the server: a failure at this point lands in
        // `ExecutionResult::failures`, which is what the model is shown and what the repair
        // loop reads. `build_rss_from_llm_data` calls the same function as a last gate.
        validate_feed_data(&action)?;

        // Return custom result with feed data
        Ok(ActionResult::Custom {
            name: "generate_rss_feed".to_string(),
            data: action,
        })
    }
}

/// Check the fields `generate_rss_feed` declares `required: true`.
///
/// The server used to substitute `"Untitled Feed"`, `"http://localhost"` and
/// `"No description"` for a missing title, link and description, so an answer naming none of
/// the three produced a complete-looking feed and nothing recorded that the model had not
/// actually supplied one. A required field whose default asserts a result is the shape
/// CLAUDE.md calls the most dangerous pattern here; refuse and say which field, so the
/// message the repair loop reads names the fix.
///
/// `items` is required but may be empty: a feed with no entries is a legitimate answer
/// ("nothing new"), whereas a feed with no title is not a feed.
pub fn validate_feed_data(action: &serde_json::Value) -> Result<()> {
    for field in ["title", "link", "description"] {
        match action.get(field) {
            None | Some(serde_json::Value::Null) => {
                anyhow::bail!(
                    "generate_rss_feed requires '{field}'. RSS 2.0 makes title, link and \
                     description mandatory on the channel, and netget will not invent them."
                );
            }
            Some(serde_json::Value::String(s)) if s.trim().is_empty() => {
                anyhow::bail!("generate_rss_feed '{field}' must not be empty");
            }
            Some(serde_json::Value::String(_)) => {}
            Some(other) => {
                anyhow::bail!(
                    "generate_rss_feed '{field}' must be a string, got {}",
                    match other {
                        serde_json::Value::Bool(_) => "a boolean",
                        serde_json::Value::Number(_) => "a number",
                        serde_json::Value::Array(_) => "an array",
                        serde_json::Value::Object(_) => "an object",
                        _ => "something else",
                    }
                );
            }
        }
    }

    match action.get("items") {
        None | Some(serde_json::Value::Null) => anyhow::bail!(
            "generate_rss_feed requires 'items'. Use an empty array for a feed with no entries."
        ),
        Some(serde_json::Value::Array(_)) => {}
        Some(_) => anyhow::bail!("generate_rss_feed 'items' must be an array"),
    }

    Ok(())
}

/// Action definition for generate_rss_feed (sync)
fn generate_rss_feed_action() -> ActionDefinition {
    ActionDefinition {
        name: "generate_rss_feed".to_string(),
        description: "Generate RSS feed XML for the current request".to_string(),
        parameters: vec![
            Parameter {
                name: "title".to_string(),
                type_hint: "string".to_string(),
                description: "Feed title".to_string(),
                required: true,
            },
            Parameter {
                name: "link".to_string(),
                type_hint: "string".to_string(),
                description: "Feed link (website URL)".to_string(),
                required: true,
            },
            Parameter {
                name: "description".to_string(),
                type_hint: "string".to_string(),
                description: "Feed description".to_string(),
                required: true,
            },
            Parameter {
                name: "language".to_string(),
                type_hint: "string".to_string(),
                description: "Feed language (e.g., 'en-us')".to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "string".to_string(),
                description: "Time to live in minutes".to_string(),
                required: false,
            },
            Parameter {
                name: "last_build_date".to_string(),
                type_hint: "string".to_string(),
                description: "Last build date (RFC 2822)".to_string(),
                required: false,
            },
            Parameter {
                name: "items".to_string(),
                type_hint: "array".to_string(),
                description: "Array of feed items".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "generate_rss_feed",
            "title": "Tech News Feed",
            "link": "https://example.com",
            "description": "Latest technology news",
            "language": "en-us",
            "ttl": "60",
            "last_build_date": "Mon, 09 Nov 2025 12:00:00 GMT",
            "items": [
                {
                    "title": "New AI Model Released",
                    "link": "https://example.com/ai-news",
                    "description": "Company X released a new AI model",
                    "author": "john@example.com (John Doe)",
                    "pub_date": "Mon, 09 Nov 2025 10:00:00 GMT",
                    "guid": "https://example.com/ai-news",
                    "categories": [
                        "AI",
                        "Technology",
                        {"name": "Machine Learning", "domain": "tech.example.com"}
                    ]
                },
                {
                    "title": "Cloud Computing Trends",
                    "link": "https://example.com/cloud-trends",
                    "description": "Latest trends in cloud computing",
                    "pub_date": "Mon, 09 Nov 2025 09:00:00 GMT",
                    "categories": ["Cloud", "Infrastructure"]
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RSS feed: {title}")
                .with_debug("RSS generate_rss_feed: title={title} items={items_len}"),
        ),
    }
}
