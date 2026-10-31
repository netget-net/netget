//! Ident (RFC 1413) **client** actions, events and metadata.
//!
//! The querying half of RFC 1413. NetGet asks another host "which account owns the TCP
//! connection between these two ports?" and reads back one line. The vocabulary is
//! deliberately tiny — there is exactly one thing a client may say on the wire — and the
//! interesting work is in `mod.rs`, which owns the parse and the port-pair check.
//!
//! ## Nothing here consults the local system
//!
//! The server half's rule ("NetGet invents every userid, it never reads `/etc/passwd`") has a
//! mirror image on this side: NetGet is the *querier*, so it learns about somebody else's
//! accounts. The port pair the model asks about is the model's own choice — it is never
//! derived from a local socket table, `getpwuid`, or any other host state — and the userid
//! that comes back is reported once, in the event, and nowhere else. It is not written into
//! memory automatically, not echoed into a status line, and not used to name anything.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Raised once, immediately after the TCP connection to the ident server is up.
///
/// This is the model's cue to choose a port pair and answer with `send_ident_query`. Nothing
/// goes on the wire until it does: an ident client speaks first, and NetGet does not invent
/// the question.
pub static IDENT_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ident_connected",
        "Connected to an ident (RFC 1413) server. Answer with send_ident_query naming the \
         port pair to ask about; nothing is sent until you do.",
        json!({}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "The ident server actually connected to, host:port".to_string(),
        required: true,
    }])
    .with_actions(client_action_set())
});

/// A well-formed `USERID` reply **whose port pair matches the query it answers**.
///
/// A reply carrying a different pair never reaches this event — see
/// [`IDENT_CLIENT_REPLY_MISMATCH_EVENT`].
pub static IDENT_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ident_response_received",
        "The ident server named an account: '<server_port> , <client_port> : USERID : \
         <opsys>[,<charset>] : <userid>'. The port pair has already been checked against the \
         query, so this really is the answer to what was asked.",
        json!({}),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Server-side port of the pair that was asked about".to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Client-side port of the pair that was asked about".to_string(),
            required: true,
        },
        Parameter {
            name: "userid".to_string(),
            type_hint: "string".to_string(),
            description: "The account the remote host claims owns that connection. It is an \
                          unverified assertion by a stranger's host; treat it as a hint, never \
                          as authentication"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "opsys".to_string(),
            type_hint: "string".to_string(),
            description: "Operating-system token the server reported, e.g. UNIX, WIN32, OTHER"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "charset".to_string(),
            type_hint: "string".to_string(),
            description: "Character set the server appended to opsys after a comma, e.g. \
                          US-ASCII. Absent when the server did not send one"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(client_action_set())
});

/// A well-formed `ERROR` reply whose port pair matches the query it answers.
pub static IDENT_CLIENT_ERROR_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ident_error_received",
        "The ident server refused: '<server_port> , <client_port> : ERROR : <token>'. \
         NO-USER means no connection matches the pair, HIDDEN-USER means it matches but the \
         owner declined to be named, INVALID-PORT means a port was rejected, UNKNOWN-ERROR is \
         everything else. This is a normal answer, not a failure.",
        json!({}),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Server-side port of the pair that was asked about".to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Client-side port of the pair that was asked about".to_string(),
            required: true,
        },
        Parameter {
            name: "error_token".to_string(),
            type_hint: "string".to_string(),
            description: "NO-USER, INVALID-PORT, HIDDEN-USER, UNKNOWN-ERROR, or an X-prefixed \
                          implementation-defined token"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_action_set())
});

/// Something came back that is **not an answer to the question that was asked**.
///
/// RFC 1413 §3 has the client match a reply to its query by the port pair, and this is the one
/// correctness property an ident client really has. A reply carrying a different pair is not
/// "slightly wrong" — it is an answer about a different connection, and accepting it would
/// attribute a stranger's account to the wrong socket. The same event covers a reply that
/// cannot be parsed at all, one that overflows the line cap, and one that arrives before any
/// query was sent: in every case the honest report is "this is not my answer", never a
/// loosely-parsed result.
pub static IDENT_CLIENT_REPLY_MISMATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ident_reply_mismatch",
        "The server sent something that is not an answer to the query: a different port pair, \
         an unparseable line, an oversized line, or a reply with no query outstanding. It has \
         been rejected rather than parsed loosely.",
        json!({}),
    )
    .with_parameters(vec![
        Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why it was rejected: port_pair_mismatch, unsolicited, oversized, or \
                          one of the parse verdicts (port_pair, response_type, userid_fields, \
                          error_token, …)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "queried_server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Server-side port this client asked about. Absent when no query was \
                          outstanding"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "queried_client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Client-side port this client asked about. Absent when no query was \
                          outstanding"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "reply_server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Server-side port the reply carried. Absent when the reply had no \
                          parseable pair"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "reply_client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Client-side port the reply carried. Absent when the reply had no \
                          parseable pair"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "reply_line".to_string(),
            type_hint: "string".to_string(),
            description: "The offending line as text, control characters stripped and \
                          truncated. Diagnostic only — it has already been rejected"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_action_set())
});

/// The client's entire vocabulary, defined **once**.
///
/// It is returned by `get_async_actions()` and attached to every event type, so each event's
/// own description names the verbs that answer it. Both consumers of a client's vocabulary
/// take the union, so neither depends on the attachment:
///
/// * `client_llm_action_set` (`src/llm/actions/client_trait.rs`) unions async ∪ sync ∪ the
///   firing event's actions and deduplicates by name, so the model sees each verb once. A
///   client has one LLM entry point and therefore cannot express a narrowing, which is why
///   `get_sync_actions()` is empty here rather than a second copy.
/// * `validate_static_action_names` (`src/events/handler.rs`) checks a client handler against
///   `client_action_names_for_pattern`, the same union plus the matching events' actions, so a
///   `{"type": "static", "actions": [{"type": "send_ident_query", …}]}` routing rule is
///   accepted at creation.
fn client_action_set() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "send_ident_query".to_string(),
            description: "Ask the ident server who owns the TCP connection between two ports: \
                          sends '<server_port> , <client_port>'. server_port is the port on \
                          the machine being queried; client_port is the port on the far end \
                          of that connection. The reply must echo this exact pair or NetGet \
                          rejects it. RFC 1413 allows one query per connection, so asking \
                          again opens a fresh one."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "server_port".to_string(),
                    type_hint: "integer".to_string(),
                    description: "Port on the queried host, 1-65535".to_string(),
                    required: true,
                },
                Parameter {
                    name: "client_port".to_string(),
                    type_hint: "integer".to_string(),
                    description: "Port on the other end of that connection, 1-65535".to_string(),
                    required: true,
                },
            ],
            example: json!({
                "type": "send_ident_query",
                "server_port": 6193,
                "client_port": 23
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Say nothing and keep reading. Rarely right here: an ident server \
                          sends exactly one line and closes."
                .to_string(),
            parameters: vec![],
            example: json!({"type": "wait_for_more"}),
            log_template: None,
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Close the connection to the ident server.".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: None,
        },
    ]
}

/// Ident client protocol handler.
pub struct IdentClientProtocol;

impl Default for IdentClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl IdentClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// Read a port out of an action parameter.
///
/// Accepts an integer or a decimal string, because models produce both, and insists on
/// `1..=65535` — an ident query names two real TCP ports and nothing else is answerable.
///
/// The error text deliberately avoids the words "unknown"/"unsupported": those are how
/// `tests/event_action_declarations_test.rs` recognises an *action name* the executor cannot
/// run, and a missing-parameter complaint must not be mistaken for one.
fn port_field(action: &serde_json::Value, key: &str) -> Result<u16> {
    let raw = action
        .get(key)
        .with_context(|| format!("send_ident_query requires '{key}' (a TCP port, 1-65535)"))?;

    let value = match raw {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    };

    match value {
        Some(v) if (1..=65535).contains(&v) => Ok(v as u16),
        _ => Err(anyhow::anyhow!(
            "send_ident_query needs '{key}' to be a TCP port in 1-65535, got {raw}"
        )),
    }
}

impl Protocol for IdentClientProtocol {
    /// Both parameters are read in `mod.rs`: `ident_port` by `resolve_target`, and
    /// `response_timeout_secs` by the reply read.
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "ident_port".to_string(),
                type_hint: "integer".to_string(),
                description: "TCP port of the ident server. Defaults to 113, which is the only \
                              port RFC 1413 defines and the only one a real identd listens on \
                              — override it for a test harness or a non-standard deployment, \
                              not in the field. Wins over any port written into remote_addr."
                    .to_string(),
                required: false,
                example: json!(113),
                default: None,
            },
            ParameterDefinition {
                name: "response_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "How long to wait for the single reply line before giving up \
                              (default 30). An ident server that never answers is common; the \
                              connection is closed rather than held open."
                    .to_string(),
                required: false,
                example: json!(30),
                default: None,
            },
        ]
    }

    /// One wire verb plus the two lifecycle verbs.
    ///
    /// `get_sync_actions()` is deliberately empty rather than a copy of this list:
    /// `client_llm_action_set` unions async, sync and the firing event's own actions, so a
    /// client cannot express a narrowing and duplicating the list buys nothing. See
    /// `src/llm/actions/client_trait.rs`.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        client_action_set()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }

    fn protocol_name(&self) -> &'static str {
        "Ident"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            IDENT_CLIENT_CONNECTED_EVENT.clone(),
            IDENT_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
            IDENT_CLIENT_ERROR_RECEIVED_EVENT.clone(),
            IDENT_CLIENT_REPLY_MISMATCH_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Ident"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ident",
            "identd",
            "rfc1413",
            "auth",
            "ident client",
            "ident lookup",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Connecting *out* to port 113 needs nothing; only listening on it would.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-rolled tokio TCP: one line out, one line in, close. No library exists — \
                 there is no RFC 1413 crate on crates.io. The reply's port pair is checked \
                 against the query and a mismatch is rejected, never parsed as a result.",
            )
            .llm_control(
                "Which port pair to ask about, and what to do with the answer — including \
                 asking again on a fresh connection, up to a depth bound.",
            )
            .e2e_testing(
                "Driven against NetGet's own ident server and against hand-written loopback \
                 peers that reply with a wrong port pair, a malformed line and an oversized \
                 line.",
            )
            .notes(
                "Experimental, and hard to move: no third-party ident client or server binary \
                 with a configurable port exists (see src/server/ident/CLAUDE.md for the \
                 search), because RFC 1413 has no notion of one. Same-project evidence only.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Ident (RFC 1413) client: asks a host which account owns a given TCP connection"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the ident server at 127.0.0.1:113 and ask who owns the connection between \
         port 6667 and port 49152"
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:113",
                "base_stack": "ident",
                "instruction": "Ask who owns the connection between server port 6667 and \
                                client port 49152, and report the userid."
            }),
            // Script mode: the connect event chooses the pair, the reply is handled in code.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:113",
                "base_stack": "ident",
                "event_handlers": [{
                    "event_pattern": "ident_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ident_client_handler>"
                    }
                }]
            }),
            // Static mode: a fixed query on connect, then hang up on the answer. A static
            // handler cannot read the event, which is fine here because the query's port pair
            // is chosen by us rather than echoed from anything.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:113",
                "base_stack": "ident",
                "event_handlers": [
                    {
                        "event_pattern": "ident_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_ident_query",
                                "server_port": 6667,
                                "client_port": 49152
                            }]
                        }
                    },
                    {
                        "event_pattern": "ident_response_received",
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

impl Client for IdentClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::ident::IdentClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.startup_params,
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
            "send_ident_query" => {
                let server_port = port_field(&action, "server_port")?;
                let client_port = port_field(&action, "client_port")?;
                // Custom rather than SendData: the connection loop has to remember which pair
                // was asked about in order to check the reply against it, and bytes alone
                // cannot carry that.
                Ok(ClientActionResult::Custom {
                    name: "ident_query".to_string(),
                    data: json!({
                        "server_port": server_port,
                        "client_port": client_port,
                    }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Ident client action: {}",
                action_type
            )),
        }
    }
}
