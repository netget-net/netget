//! WHOIS client protocol actions.
//!
//! **The two `EventType` statics below are the ones `mod.rs` emits, and `get_event_types()`
//! must return exactly them.** It used to build two *different* `EventType`s inline, with the
//! same ids but no parameters, no actions, and `{"type": "placeholder"}` as the example
//! action. Three things followed from that, and none of them fails loudly:
//!
//! * The model was shown `placeholder` as the thing to answer a `whois_connected` with. The
//!   WHOIS *server* had the identical bug and fixed it, with a comment in `actions.rs` saying
//!   the example is rendered verbatim into the documentation and so has to be executable.
//! * The parameters the client actually puts on each event — `remote_addr`, `response`,
//!   `query`, `truncated` — were documented nowhere the model could read them.
//! * `event_handlers` validation (`events::handler::action_catalog_for_pattern`) built its
//!   catalog from `get_sync_actions()` **plus the matching event's own actions**, and read
//!   `get_async_actions()` not at all. With no `.with_actions(…)` anywhere and an empty sync
//!   list, the catalog for a whois-client event was the common actions alone — so
//!   `{"type": "query_whois"}` in a static handler was rejected as an unknown action, and a
//!   whois client could not be routed deterministically at all. **That was a defect in the
//!   shared code and is fixed there**: a client's catalog is now async ∪ sync ∪ the matching
//!   events' actions, the same union the model is shown
//!   (`llm::actions::client_trait::client_action_names_for_pattern`). Attaching the two verbs
//!   to the events below is still right — the event's own list is what a reader of the docs
//!   sees as the answer to *that* event — but it is no longer what makes them nameable.
//!
//! The actions are therefore defined once, below, and attached to both events.

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

/// Put a query on the wire. The client's only outbound verb.
fn query_whois_action() -> ActionDefinition {
    ActionDefinition {
        name: "query_whois".to_string(),
        description: "Query WHOIS information for a domain or IP address. RFC 3912 is one \
                      query per connection - the server answers and closes - so a follow-up \
                      (the referral chase from a registry to the registrar) opens a fresh \
                      connection of its own; issuing another query_whois is all that is needed"
            .to_string(),
        parameters: vec![Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "Domain name or IP address to query (e.g., 'example.com' or '8.8.8.8')"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "query_whois",
            "query": "example.com"
        }),
        log_template: None,
    }
}

/// Half-close, which is how a WHOIS client says it is finished.
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Disconnect from the WHOIS server".to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: None,
    }
}

/// WHOIS client connected event
pub static WHOIS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "whois_connected",
        "WHOIS client successfully connected to server. Nothing has been asked yet - send a \
         query_whois.",
        // Rendered verbatim into the documentation the model reads, so it must be an action
        // the executor accepts. This was `{}`.
        json!({
            "type": "query_whois",
            "query": "example.com"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "WHOIS server address".to_string(),
        required: true,
    }])
    .with_actions(vec![query_whois_action(), disconnect_action()])
});

/// WHOIS client response received event
pub static WHOIS_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "whois_response_received",
        "Response received from WHOIS server. RFC 3912 is one query per connection, so a \
         follow-up - chasing the referral from a registry to the registrar, which is most of \
         what WHOIS is used for - opens its own connection; issue it as a query_whois and the \
         client handles that.",
        // Rendered verbatim into the docs the model reads, so it has to be an action the
        // executor accepts. The previous `{}` taught the model nothing and modelled nothing.
        json!({
            "type": "query_whois",
            "query": "example.com"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "The WHOIS response text".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The original query (domain or IP)".to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the server sent more than the client will hold (1 MB) and \
                          only the head of the record is in 'response'. A WHOIS reply carries \
                          no length, so how much arrives is the server's choice; treat a \
                          truncated record as incomplete rather than as the whole answer"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![query_whois_action(), disconnect_action()])
});

/// WHOIS client protocol action handler
pub struct WhoisClientProtocol;

impl Default for WhoisClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl WhoisClientProtocol {
    pub fn new() -> Self {
        Self::default()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WhoisClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![query_whois_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // The same two verbs. A client has one LLM entry point, so async/sync cannot express a
        // narrowing, and the two readers that matter union the lists anyway:
        // `client_llm_action_set` for the model and `client_action_names_for_pattern` for
        // `event_handlers` validation, which no longer reads the sync list alone.
        //
        // The copy stays because a third reader still does: `cli::tasks`'s
        // `execute_single_task` builds a client-scoped scheduled task's action list from
        // `get_sync_actions()` and nothing else, and `ConversationHandler` rejects anything
        // outside it. Drop this list and a scheduled task on a WHOIS client can no longer
        // issue a query. Union there too and this can go.
        vec![query_whois_action(), disconnect_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "WHOIS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        // The statics `mod.rs` actually emits. This used to build two different `EventType`s
        // inline with the same ids, no parameters and a `placeholder` example — see the
        // module note.
        vec![
            WHOIS_CLIENT_CONNECTED_EVENT.clone(),
            WHOIS_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>WHOIS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["whois", "whois client", "domain lookup", "ip lookup"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Direct TCP to port 43 with text protocol")
            .llm_control("Full control over WHOIS queries and response parsing")
            .e2e_testing("Public WHOIS servers (whois.iana.org, etc.)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "WHOIS client for domain and IP address lookups"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to WHOIS at whois.iana.org:43 and query 'example.com'"
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls WHOIS queries
            json!({
                "type": "open_client",
                "remote_addr": "whois.verisign-grs.com:43",
                "base_stack": "whois",
                "instruction": "Query example.com and extract the registrar, creation date, and expiration date"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "whois.iana.org:43",
                "base_stack": "whois",
                "event_handlers": [{
                    "event_pattern": "whois_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<whois_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed WHOIS query on connect
            json!({
                "type": "open_client",
                "remote_addr": "whois.verisign-grs.com:43",
                "base_stack": "whois",
                "event_handlers": [
                    {
                        "event_pattern": "whois_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "query_whois",
                                "query": "example.com"
                            }]
                        }
                    },
                    {
                        "event_pattern": "whois_response_received",
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
impl Client for WhoisClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::whois::WhoisClient;
            WhoisClient::connect_with_llm_actions(
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
            "query_whois" => {
                let query = action
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "whois_query".to_string(),
                    data: json!({
                        "query": query,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown WHOIS client action: {}",
                action_type
            )),
        }
    }
}
