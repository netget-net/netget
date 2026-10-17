//! Finger (RFC 1288) client protocol actions.
//!
//! The client's whole vocabulary is one query and two ways of ending the session. Finger's
//! answer is **free text by design** — RFC 1288 specifies no format for it at all — so nothing
//! here parses it. The text goes to the model verbatim and the model decides what it means;
//! that is the entire point of NetGet. The one concession is a small `best_effort` block on the
//! response event, and it is named that way because it is a guess: half the world's finger
//! daemons print something a `Login:`/`Name:` reader would get wrong.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// TCP port assigned to finger (`/etc/services`: `finger 79/tcp`).
///
/// Used only when `remote_addr` carries no port of its own; see the `port` startup parameter.
pub const DEFAULT_FINGER_PORT: u16 = 79;

/// Default for the `allow_forwarding` startup parameter.
///
/// RFC 1288 §3.2.1 names `user@host` forwarding a security risk. Asking a finger server to
/// relay on your behalf is the client half of that risk, so it is refused unless the operator
/// turns it on by name.
pub const DEFAULT_ALLOW_FORWARDING: bool = false;

/// Default for the `response_timeout_secs` startup parameter.
pub const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Cap on one response.
///
/// A finger answer is a few hundred bytes; RFC 1288 sets no limit and a hostile server can
/// stream forever, so the read stops here and the event says `truncated`.
pub const MAX_RESPONSE_BYTES: usize = 65_536;

/// How many times the model may answer a response with another query.
///
/// Every follow-up needs its own TCP connection (RFC 1288 is one query per connection), and
/// each one raises `finger_response_received` again — which is exactly the self-referential
/// shape that has run away in this repo before. The bound is the answer, not silence.
pub const MAX_FOLLOWUP_DEPTH: usize = 4;

/// Drop ASCII/Unicode control characters.
///
/// Applied to every value that reaches the wire and to every single-line value that reaches
/// the event. In a line-oriented protocol a stray CR or LF **forges a line** — outbound it
/// would forge a second query, inbound it would forge a record — and ESC would put terminal
/// escapes on the operator's dashboard.
pub fn strip_controls(s: &str) -> String {
    crate::utils::sanitize::strip_controls(s)
}

/// Same, but keeping newlines and tabs: for the response text, which is inherently multi-line.
///
/// Line endings are normalised to LF first so a lone CR does not survive as a control
/// character, and every other control — ESC included — is dropped.
pub fn sanitize_response(s: &str) -> String {
    crate::utils::sanitize::multiline(&s.replace("\r\n", "\n").replace('\r', "\n"))
}

/// One `{Q1}`/`{Q2}` query this client will put on the wire.
///
/// RFC 1288 §2.3:
///
/// ```text
/// {Q1} ::= [{W}|{W}{S}{U}] {C}          -- local query
/// {Q2} ::= [{W}{S}][{U}]{H}{C}          -- forwarding query
/// {W}  ::= "/W"                         -- long format
/// {U}  ::= username
/// {H}  ::= @hostname
/// {C}  ::= CRLF
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FingerQuerySpec {
    /// Login to ask about, or `None` for the empty "list everyone" query.
    pub username: Option<String>,
    /// Send `/W`, asking the server for the long format.
    pub verbose: bool,
    /// `@host`: ask the server to **relay** the query. Refused unless `allow_forwarding`.
    pub forward_host: Option<String>,
}

impl FingerQuerySpec {
    /// Validate one `send_finger_query` action into a spec.
    ///
    /// The validation is the security boundary, not decoration. A username carrying `@` would
    /// make a forwarding query *implicitly*, slipping past the `allow_forwarding` gate
    /// entirely; one carrying whitespace or a leading `/` could forge the `/W` token or a
    /// second field. Each is refused by name so the model is told to use `forward_host`
    /// rather than silently getting something else than it asked for.
    pub fn from_action(action: &serde_json::Value) -> Result<Self> {
        let username = match action.get("username").and_then(|v| v.as_str()) {
            Some(raw) => {
                let cleaned = strip_controls(raw).trim().to_string();
                if cleaned.is_empty() {
                    None
                } else {
                    if cleaned.contains('@') {
                        bail!(
                            "'username' must not contain '@' ({cleaned:?}). A 'user@host' query \
                             asks the server to relay on your behalf, which RFC 1288 section \
                             3.2.1 calls a security risk; put the host in the separate \
                             'forward_host' parameter, which is refused unless the client was \
                             started with allow_forwarding=true."
                        );
                    }
                    if cleaned.starts_with('/') || cleaned.chars().any(|c| c.is_whitespace()) {
                        bail!(
                            "'username' must not contain whitespace or start with '/' \
                             ({cleaned:?}): the query is a single line and either would forge \
                             an extra field, such as the '/W' verbose token. Use the 'verbose' \
                             parameter to ask for the long format."
                        );
                    }
                    Some(cleaned)
                }
            }
            None => None,
        };

        let forward_host = match action.get("forward_host").and_then(|v| v.as_str()) {
            Some(raw) => {
                let cleaned = strip_controls(raw)
                    .trim()
                    .trim_start_matches('@')
                    .to_string();
                if cleaned.is_empty() {
                    None
                } else {
                    if cleaned.chars().any(|c| c.is_whitespace()) {
                        bail!(
                            "'forward_host' must not contain whitespace ({cleaned:?}): the \
                             query is a single line and whitespace would forge an extra field."
                        );
                    }
                    Some(cleaned)
                }
            }
            None => None,
        };

        let verbose = action
            .get("verbose")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            username,
            verbose,
            forward_host,
        })
    }

    /// Round-trip form carried by [`ClientActionResult::Custom`] and by the response event.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "username": self.username,
            "verbose": self.verbose,
            "forward_host": self.forward_host,
        })
    }

    /// Rebuild a spec produced by [`Self::to_json`]. Values are re-cleaned rather than
    /// trusted, so the wire encoding has exactly one place that decides what is legal.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        Self::from_action(value)
    }

    /// The query line **without** its CRLF: what the response event reports as `query`.
    pub fn query_text(&self) -> String {
        let mut line = String::new();
        if self.verbose {
            line.push_str("/W");
        }
        let mut who = String::new();
        if let Some(user) = &self.username {
            who.push_str(user);
        }
        if let Some(host) = &self.forward_host {
            who.push('@');
            who.push_str(host);
        }
        if !who.is_empty() {
            if self.verbose {
                line.push(' ');
            }
            line.push_str(&who);
        }
        line
    }

    /// The bytes that go on the wire. RFC 1288 terminates every query with CRLF.
    pub fn to_wire_line(&self) -> String {
        format!("{}\r\n", self.query_text())
    }

    /// True when this query asks the server to relay to another host.
    pub fn is_forwarding(&self) -> bool {
        self.forward_host.is_some()
    }
}

/// Best-effort structure over a response that has none.
///
/// **This is a guess and is named so.** `Login:` at the start of a line is the one convention
/// BSD `fingerd` and its descendants share; plenty of daemons print a table, a `.plan` and
/// nothing else, or a localised header. Whatever this returns, `response` carries the text the
/// server actually sent and is the only authoritative field.
pub fn best_effort_fields(text: &str) -> serde_json::Value {
    let mut logins: Vec<String> = Vec::new();
    for line in text.lines() {
        if logins.len() >= 32 {
            break;
        }
        if let Some(rest) = line.strip_prefix("Login:") {
            if let Some(first) = rest.split_whitespace().next() {
                if !logins.iter().any(|l| l == first) {
                    logins.push(first.to_string());
                }
            }
        }
    }
    json!({
        "logins": logins,
        "line_count": text.lines().count(),
        "note": "GUESS ONLY. RFC 1288 defines no response format; 'logins' is scraped from \
                 lines beginning 'Login:' and is wrong against any daemon that prints \
                 something else. Read 'response' - it is the text the server actually sent.",
    })
}

/// Raised once, when the TCP connection to the finger server is up and nothing has been sent.
pub static FINGER_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "finger_connected",
        "Finger client connected; the server is waiting for one query line",
        json!({
            "type": "send_finger_query",
            "username": "alice"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "The finger server this client is connected to, host:port".to_string(),
            required: true,
        },
        Parameter {
            name: "allow_forwarding".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether this client will put a 'user@host' forwarding query on the \
                          wire. False by default; a send_finger_query carrying forward_host is \
                          refused and never sent when this is false."
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("FINGER client connected to {remote_addr}")
            .with_debug(
                "FINGER client connected to {remote_addr} allow_forwarding={allow_forwarding}",
            ),
    )
    .with_actions(finger_client_actions())
    .with_alternative_example(json!({
        "type": "send_finger_query",
        "verbose": true
    }))
});

/// Raised once per query, when the server has answered and closed (or the read was cut short).
pub static FINGER_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "finger_response_received",
        "The finger server answered and closed the connection",
        json!({
            "type": "disconnect"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "The server's answer, verbatim apart from control characters being \
                          stripped and line endings normalised to LF. RFC 1288 defines no \
                          format for it - read it as prose. This field is authoritative."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The query line that produced this response, without its CRLF"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string|null".to_string(),
            description: "The login that was asked about, or null for the empty list-all query"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "verbose".to_string(),
            type_hint: "boolean".to_string(),
            description: "'/W' was sent with the query".to_string(),
            required: true,
        },
        Parameter {
            name: "forward_host".to_string(),
            type_hint: "string|null".to_string(),
            description: "The '@host' of the query, or null. Only ever non-null when the \
                          client was started with allow_forwarding=true."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "bytes".to_string(),
            type_hint: "number".to_string(),
            description: "How many bytes were read from the server".to_string(),
            required: true,
        },
        Parameter {
            name: "eof".to_string(),
            type_hint: "boolean".to_string(),
            description: "The server closed the connection, so the answer is complete. False \
                          means the read stopped first - see 'truncated' and the log."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "The response hit the client's size cap and the rest was discarded"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "best_effort".to_string(),
            type_hint: "object".to_string(),
            description: "A GUESS at structure, nothing more: 'logins' scraped from lines \
                          beginning 'Login:', plus 'line_count'. Wrong against any daemon that \
                          prints a different layout. Always prefer 'response'."
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("FINGER client got {bytes}B for query {query}")
            .with_debug("FINGER client response: query={query} bytes={bytes} eof={eof} truncated={truncated}")
            .with_trace("FINGER client: {json_pretty(.)}"),
    )
    .with_actions(finger_client_actions())
    .with_alternative_example(json!({
        "type": "send_finger_query",
        "username": "bob",
        "verbose": true
    }))
});

fn send_finger_query_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_finger_query".to_string(),
        description: "Ask the finger server about a user. Omit 'username' to send the empty \
                      query, which RFC 1288 defines as 'list everyone'. The server answers with \
                      free text and closes, so exactly one query fits on one connection - \
                      sending this again in reply to finger_response_received opens a fresh \
                      connection to the same server (bounded, so a chain cannot run away). \
                      'username' must not contain '@': a 'user@host' query asks the server to \
                      relay, which is refused unless the client was started with \
                      allow_forwarding=true, and it must be requested through 'forward_host' so \
                      it can never happen by accident."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "Login to ask about, e.g. 'alice'. Omit for the empty query, which \
                              asks for every user. No '@', no whitespace, no leading '/'."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "verbose".to_string(),
                type_hint: "boolean".to_string(),
                description: "Send RFC 1288's '/W' token, asking for the long format. Servers \
                              are free to ignore it. Default false."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "forward_host".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the server to RELAY this query to another host ('user@host'). \
                              RFC 1288 section 3.2.1 calls forwarding a security risk. Refused \
                              and never sent unless the client was started with \
                              allow_forwarding=true; leave it out for a normal query."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_finger_query",
            "username": "alice",
            "verbose": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FINGER query {username}")
                .with_debug("FINGER send_finger_query: username={username} verbose={verbose} forward_host={forward_host}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and keep waiting. On finger_connected this leaves the \
                      connection open with no query on it, which is useful only when a query is \
                      going to be injected from the dashboard. On finger_response_received the \
                      server has already closed, so this simply ends the session."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("FINGER client waiting")
                .with_debug("FINGER wait_for_more"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close the connection to the finger server. A finger server closes on its \
                      own once it has answered (RFC 1288), so this is mainly for hanging up \
                      before sending any query."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("FINGER client disconnecting")
                .with_debug("FINGER disconnect"),
        ),
    }
}

/// The client's entire vocabulary, declared once.
///
/// Clients **union** async ∪ sync ∪ the firing event's actions
/// ([`crate::llm::actions::client_trait::client_llm_action_set`]), so this list is declared as
/// async actions and attached to the event types, and deliberately not duplicated into
/// `get_sync_actions()`.
pub fn finger_client_actions() -> Vec<ActionDefinition> {
    vec![
        send_finger_query_action(),
        wait_for_more_action(),
        disconnect_action(),
    ]
}

/// Finger (RFC 1288) client protocol.
pub struct FingerClientProtocol;

impl Default for FingerClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl FingerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for FingerClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        finger_client_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Deliberately empty. A client has one LLM entry point, so async/sync carries no
        // meaning here and duplicating the list into both would just be noise -- see
        // `client_llm_action_set`, which unions them.
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "Finger"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            FINGER_CLIENT_CONNECTED_EVENT.clone(),
            FINGER_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FINGER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["finger", "finger client", "rfc1288", "user lookup"]
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "TCP port to connect to when 'remote_addr' carries no port of its own \
                     (default {DEFAULT_FINGER_PORT}, the assigned finger port). An explicit \
                     port in remote_addr always wins. This exists because the real finger(1) \
                     has no port option at all and is locked to 79, so a test server on a high \
                     port is only reachable through NetGet."
                ),
                required: false,
                example: json!(79),
                default: None,
            },
            ParameterDefinition {
                name: "allow_forwarding".to_string(),
                type_hint: "boolean".to_string(),
                description: "Allow this client to send 'user@host' forwarding queries, asking \
                              the server to relay on our behalf (default false). RFC 1288 \
                              section 3.2.1 calls forwarding a security risk. While false, a \
                              send_finger_query carrying 'forward_host' is refused and no bytes \
                              reach the wire; the refusal is logged as decision=forward_refused."
                    .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "response_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "How long to wait for the server's answer before giving up on the read \
                     (default {DEFAULT_RESPONSE_TIMEOUT_SECS}). A finger client reads until the \
                     server closes, so without this a server that never closes would park the \
                     connection task forever. 0 means wait indefinitely."
                ),
                required: false,
                example: json!(30),
                default: None,
            },
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Hand-rolled tokio TCP client; the RFC 1288 {Q1}/{Q2} query line is built in \
                 FingerQuerySpec::to_wire_line and the answer is read to EOF. No library, no \
                 dependency. Connecting out needs no privilege even on port 79.",
            )
            .llm_control(
                "The whole query (username, the /W verbose token, and - only when the operator \
                 enabled it - the @host forwarding target), and what to do with the free-text \
                 answer, including asking a follow-up question on a fresh connection.",
            )
            .e2e_testing(
                "tests/client/finger/e2e_test.rs, 10 LLM calls. The round trip runs against \
                 NetGet's own Finger server; the exact query bytes are asserted against a raw \
                 TcpListener.",
            )
            .notes(
                "EXPERIMENTAL, and specifically NOT validated against an independent finger \
                 implementation. The peer in the round-trip test is NetGet's own Finger server, \
                 so it is same-project evidence: it shows the two halves agree, not that either \
                 matches RFC 1288. No fingerd exists on macOS (Apple ships finger(1) only) and \
                 Homebrew has no formula for one, so no third-party daemon was available here. \
                 Promoting this to Beta needs one run against a real finger daemon on loopback - \
                 which, unlike the server's mirror-image problem, is achievable, because a \
                 daemon is inetd-driven and can be told to listen on a high port even though \
                 finger(1) cannot be told to connect to one. \
                 Forwarding (user@host) is refused unless allow_forwarding=true, and the refusal \
                 happens before anything is written. The response is delivered to the model as \
                 text and is deliberately not parsed; the 'best_effort' block is a guess and \
                 says so.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Finger (RFC 1288) client for looking up user information on a remote host"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the finger server at 127.0.0.1:79 and ask about 'alice'"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model chooses the query and reads the answer.
            json!({
                "type": "open_client",
                "protocol": "finger",
                "remote_addr": "127.0.0.1:79",
                "instruction": "Ask the finger server about 'alice'. Read the free-text answer and report her real name, terminal and plan if the server gave them; say so plainly if it did not."
            }),
            // Script mode: deterministic, no model round-trip per event.
            json!({
                "type": "open_client",
                "protocol": "finger",
                "remote_addr": "127.0.0.1:79",
                "instruction": "Finger alice",
                "event_handlers": [{
                    "event_pattern": "finger_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_finger_query', 'username': 'alice'}])"
                    }
                }]
            }),
            // Static mode: a fixed query on connect, then hang up on the answer.
            json!({
                "type": "open_client",
                "protocol": "finger",
                "remote_addr": "127.0.0.1:79",
                "instruction": "Finger alice",
                "event_handlers": [
                    {
                        "event_pattern": "finger_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_finger_query", "username": "alice"}]
                        }
                    },
                    {
                        "event_pattern": "finger_response_received",
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

impl Client for FingerClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::finger::{FingerClient, FingerClientConfig};

            // `?`, never unwrap: these values come from the model or an MCP client, and a
            // panic here kills the request task before it can report anything.
            let params = ctx.startup_params.as_ref();

            let port = params
                .map(|p| p.get_optional_u32("port"))
                .transpose()?
                .flatten();
            let port = match port {
                Some(p) if p == 0 || p > u16::MAX as u32 => {
                    bail!("'port' must be between 1 and 65535, got {p}")
                }
                Some(p) => Some(p as u16),
                None => None,
            };

            let allow_forwarding = params
                .map(|p| p.get_optional_bool("allow_forwarding"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_ALLOW_FORWARDING);

            let response_timeout_secs = params
                .map(|p| p.get_optional_u64("response_timeout_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_RESPONSE_TIMEOUT_SECS);

            let config = FingerClientConfig {
                default_port: port.unwrap_or(DEFAULT_FINGER_PORT),
                allow_forwarding,
                response_timeout_secs,
            };

            FingerClient::connect_with_llm_actions(
                ctx.remote_addr,
                config,
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
            "send_finger_query" => {
                // Validated here so the injected path and the LLM path share exactly one
                // definition of a legal query; the *forwarding policy* is applied by the
                // connection loop, which is where the startup parameter lives.
                let spec = FingerQuerySpec::from_action(&action)?;
                Ok(ClientActionResult::Custom {
                    name: "finger_query".to_string(),
                    data: spec.to_json(),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Finger client action: {}",
                action_type
            )),
        }
    }
}
