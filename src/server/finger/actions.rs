//! Finger (RFC 1288) protocol actions.
//!
//! The wire format is free text, so every action here is a *formatter*: the model supplies
//! structured fields and this file turns them into the conventional block a finger client
//! prints verbatim. Nothing is read from the host — no `passwd`, no `utmp`, no `.plan` file.
//! A real finger daemon leaks real accounts; this one invents every user.

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

/// Default for the `answer_forward_queries` startup parameter.
///
/// RFC 1288 §3.2.1 names forwarding (`user@host`) as a security risk and recommends against
/// supporting it. NetGet refuses by default and, at *any* setting, never opens an outbound
/// connection to the named host — see [`FingerProtocol::get_startup_parameters`].
pub const DEFAULT_ANSWER_FORWARD_QUERIES: bool = false;

/// Maximum bytes accepted for one query line before the connection is refused.
///
/// RFC 1288 sets no limit; an unbounded accumulator is a memory sink for anything that
/// connects and never sends a newline.
pub const MAX_QUERY_BYTES: usize = 1024;

pub struct FingerProtocol;

impl FingerProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FingerProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// One parsed `{Q1}` / `{Q2}` query.
///
/// RFC 1288 §2.3:
///
/// ```text
/// {Q1} ::= [{W}|{W}{S}{U}] {C}
/// {Q2} ::= [{W}{S}][{U}]{H}{C}
/// {W}  ::= "/W"
/// {U}  ::= username
/// {H}  ::= @hostname | @hostname{H}
/// {C}  ::= CRLF
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FingerQuery {
    /// The requested login name, or `None` for the empty ("list everyone") query.
    pub username: Option<String>,
    /// The `/W` token was present: the client asked for the long/verbose format.
    pub verbose: bool,
    /// The `@host` part of a forwarding query, host chain included, or `None`.
    pub forward_host: Option<String>,
    /// No username was given, so the query is for every user on the host.
    pub list_all: bool,
}

/// Drop control characters.
///
/// Applied to everything parsed off the wire before it reaches the event, and to every
/// single-line field the model fills in before it reaches the wire. In a line-oriented free
/// text protocol a stray CR or LF forges a line, and the peer cannot tell a forged line from
/// a real one.
fn strip_controls(s: &str) -> String {
    crate::utils::sanitize::strip_controls(s)
}

/// Same, but keeping newlines and tabs: for the genuinely multi-line fields (`plan`, `project`).
///
/// Line endings are normalised first so a lone CR becomes the line break the model meant —
/// `to_crlf` below would have done that afterwards, and `utils::sanitize::multiline` drops a
/// bare CR rather than letting it overwrite a line a reader has already seen.
fn strip_controls_multiline(s: &str) -> String {
    crate::utils::sanitize::multiline(&s.replace("\r\n", "\n").replace('\r', "\n"))
}

/// Normalise arbitrary line endings to CRLF and guarantee a trailing one.
fn to_crlf(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    let normalised = s.replace("\r\n", "\n").replace('\r', "\n");
    for (i, line) in normalised.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out
}

impl FingerQuery {
    /// Parse one query line (terminator already removed).
    ///
    /// Lenient in the two ways that cost nothing: `/W` is matched case-insensitively, and
    /// surrounding whitespace is ignored. Strict where it matters — an `@` anywhere makes the
    /// query a forwarding query, whatever else is on the line.
    pub fn parse(line: &str) -> Self {
        let line = strip_controls(line);
        let mut rest = line.trim();

        let verbose = rest.len() >= 2 && rest[..2].eq_ignore_ascii_case("/W");
        if verbose {
            rest = rest[2..].trim();
        }

        let (user_part, forward_host) = match rest.find('@') {
            Some(idx) => {
                let host = rest[idx + 1..].trim();
                (
                    rest[..idx].trim(),
                    if host.is_empty() {
                        None
                    } else {
                        Some(host.to_string())
                    },
                )
            }
            None => (rest, None),
        };

        let username = if user_part.is_empty() {
            None
        } else {
            Some(user_part.to_string())
        };

        Self {
            list_all: username.is_none(),
            username,
            verbose,
            forward_host,
        }
    }

    /// The JSON the `finger_query` event carries.
    pub fn to_event_data(&self) -> serde_json::Value {
        json!({
            "username": self.username,
            "verbose": self.verbose,
            "forward_host": self.forward_host,
            "list_all": self.list_all,
        })
    }
}

impl Protocol for FingerProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Finger is purely reactive: the server says nothing until the client asks.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        finger_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "FINGER"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_finger_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FINGER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["finger", "rfc1288"]
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "answer_forward_queries".to_string(),
            type_hint: "boolean".to_string(),
            description: "Answer 'user@host' forwarding queries locally with invented \
                          information instead of refusing them (default: false). NetGet never \
                          connects to the named host at any setting - there is no outbound \
                          code path - so 'true' means only that the query reaches the model as \
                          a finger_query event carrying forward_host. RFC 1288 section 3.2.1 \
                          calls forwarding a security risk and recommends refusing it, which \
                          is why the default is false."
                .to_string(),
            required: false,
            example: json!(false),
            default: None,
        }]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(79))
            .well_known_port(79)
            .implementation(
                "Hand-rolled tokio TCP loop; RFC 1288 {Q1}/{Q2} query grammar parsed in \
                 FingerQuery::parse. No library, no dependency.",
            )
            .llm_control(
                "Every byte of the answer: the user block (login, name, tty, idle, login time, \
                 office, shell, plan, project), free text, and the error line.",
            )
            .e2e_testing(
                "tests/server/finger/e2e_test.rs, 6 LLM calls, all against a raw TCP socket.",
            )
            .notes(
                "EXPERIMENTAL, and specifically NOT validated against a real client. The real \
                 client is finger(1), which exists on macOS/BSD and Linux - but its usage is \
                 `finger [-46gklmpsho] [user ...] [user@host ...]` with no port option, and \
                 `user@host:port` is rejected as a hostname, so it resolves the 'finger' \
                 service and always connects to TCP 79. Validating against it therefore needs \
                 a privileged run binding port 79, which no test here does. The e2e suite uses \
                 a raw socket, which proves the bytes but not that a real client accepts them. \
                 An #[ignore]d root test would not change this rating. \
                 Forwarding (user@host) is refused by default per RFC 1288 section 3.2.1 and \
                 is never proxied at any setting. The server answers exactly one query and \
                 then closes, which is what RFC 1288 specifies and what finger(1) expects, so \
                 close_connection is an early exit rather than a requirement. Nothing local is \
                 read: no passwd, no utmp, no .plan.",
            )
            .max_inbound_bytes(crate::server::finger::actions::MAX_QUERY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Finger (RFC 1288) user information server"
    }

    fn example_prompt(&self) -> &'static str {
        "Finger server on port 79 - invent a plausible user record for any login that is asked for"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 79,
                "base_stack": "finger",
                "instruction": "Finger server. Invent a plausible record for whatever login is asked for, and answer the empty query with a short list of two users."
            }),
            json!({
                "type": "open_server",
                "port": 79,
                "base_stack": "finger",
                "event_handlers": [{
                    "event_pattern": "finger_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "user = event.get('username')\nif not user:\n    respond([{'type': 'send_finger_response', 'text': 'Login     Name          Tty  Idle  Login Time\\nalice     Alice Smith   *    2     Mon 09:12\\nbob       Bob Jones     con  -     Mon 08:40'}])\nelse:\n    respond([{'type': 'send_finger_user', 'login': user, 'name': 'Test User', 'tty': 'ttys002', 'idle': '5 minutes', 'login_time': 'Mon Sep  1 09:12', 'office': 'Room 101', 'office_phone': 'x1234', 'shell': '/bin/sh', 'plan': 'No plan.'}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 79,
                "base_stack": "finger",
                "event_handlers": [{
                    "event_pattern": "finger_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_finger_user",
                            "login": "alice",
                            "name": "Alice Smith",
                            "tty": "ttys002",
                            "idle": "5 minutes",
                            "login_time": "Mon Sep  1 09:12",
                            "office": "Room 101",
                            "office_phone": "x1234",
                            "shell": "/bin/sh",
                            "project": "Networking",
                            "plan": "Ship the finger server."
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for FingerProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::finger::FingerServer;

            // `?`, never unwrap: these values come from the model or an MCP client, and a
            // panic here kills the request task before it can report anything.
            let answer_forward_queries = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("answer_forward_queries"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_ANSWER_FORWARD_QUERIES);

            FingerServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                answer_forward_queries,
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
            "send_finger_user" => self.execute_send_finger_user(action),
            "send_finger_response" => self.execute_send_finger_response(action),
            "send_finger_error" => self.execute_send_finger_error(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown FINGER action: {}", action_type)),
        }
    }
}

impl FingerProtocol {
    /// Format the conventional finger user block.
    ///
    /// Every field except `login` is optional and a missing field omits its line entirely,
    /// rather than printing a placeholder — an invented "Never logged in." would be a
    /// positive assertion the model never made.
    fn execute_send_finger_user(&self, action: serde_json::Value) -> Result<ActionResult> {
        let field = |key: &str| -> Option<String> {
            action
                .get(key)
                .and_then(|v| v.as_str())
                .map(strip_controls)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let multiline = |key: &str| -> Option<String> {
            action
                .get(key)
                .and_then(|v| v.as_str())
                .map(strip_controls_multiline)
                .map(|s| s.trim_end().to_string())
                .filter(|s| !s.is_empty())
        };

        let login = action
            .get("login")
            .and_then(|v| v.as_str())
            .map(strip_controls)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .context("Missing 'login' parameter")?;

        let mut out = String::new();

        // `Login: x` padded to column 40 then `Name: y`, which is what BSD fingerd emits and
        // what a human reading raw finger output expects to see.
        let mut first = format!("Login: {}", login);
        if let Some(name) = field("name") {
            while first.len() < 40 {
                first.push(' ');
            }
            first.push_str(&format!("Name: {}", name));
        }
        out.push_str(&first);
        out.push_str("\r\n");

        if let Some(shell) = field("shell") {
            out.push_str(&format!("Shell: {}\r\n", shell));
        }

        match (field("office"), field("office_phone")) {
            (Some(o), Some(p)) => out.push_str(&format!("Office: {}, {}\r\n", o, p)),
            (Some(o), None) => out.push_str(&format!("Office: {}\r\n", o)),
            (None, Some(p)) => out.push_str(&format!("Office Phone: {}\r\n", p)),
            (None, None) => {}
        }

        // Presence line, assembled only from the parts that were supplied.
        let mut presence = String::new();
        if let Some(lt) = field("login_time") {
            presence.push_str(&format!("On since {}", lt));
        }
        if let Some(tty) = field("tty") {
            if presence.is_empty() {
                presence.push_str("On");
            }
            presence.push_str(&format!(" on {}", tty));
        }
        if let Some(idle) = field("idle") {
            if presence.is_empty() {
                presence.push_str(&format!("Idle {}", idle));
            } else {
                presence.push_str(&format!(", idle {}", idle));
            }
        }
        if !presence.is_empty() {
            out.push_str(&presence);
            out.push_str("\r\n");
        }

        if let Some(project) = multiline("project") {
            out.push_str("Project:\r\n");
            out.push_str(&to_crlf(&project));
        }
        if let Some(plan) = multiline("plan") {
            out.push_str("Plan:\r\n");
            out.push_str(&to_crlf(&plan));
        }

        Ok(ActionResult::Output(out.into_bytes()))
    }

    fn execute_send_finger_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let text = action
            .get("text")
            .and_then(|v| v.as_str())
            .context("Missing 'text' parameter")?;

        Ok(ActionResult::Output(
            to_crlf(&strip_controls_multiline(text)).into_bytes(),
        ))
    }

    fn execute_send_finger_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .map(strip_controls)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "no such user".to_string());

        Ok(ActionResult::Output(
            format!("finger: {}\r\n", message).into_bytes(),
        ))
    }
}

fn send_finger_user_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_finger_user".to_string(),
        description: "Send one user's information as the conventional finger block (Login/Name, \
                      Shell, Office, the 'On since ... idle ...' line, Project and Plan). Only \
                      'login' is required; every field you omit omits its line rather than \
                      printing a placeholder. Invent the values - this server reads nothing \
                      from the host. The server closes the connection once the response is \
                      written (RFC 1288), so close_connection is only needed to answer with \
                      nothing at all."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "login".to_string(),
                type_hint: "string".to_string(),
                description: "Login name".to_string(),
                required: true,
            },
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "Real name".to_string(),
                required: false,
            },
            Parameter {
                name: "tty".to_string(),
                type_hint: "string".to_string(),
                description: "Terminal the user is logged in on, e.g. 'ttys002'".to_string(),
                required: false,
            },
            Parameter {
                name: "idle".to_string(),
                type_hint: "string".to_string(),
                description: "Idle time as text, e.g. '5 minutes' or '2:11'".to_string(),
                required: false,
            },
            Parameter {
                name: "login_time".to_string(),
                type_hint: "string".to_string(),
                description: "Login time as text, e.g. 'Mon Sep  1 09:12'".to_string(),
                required: false,
            },
            Parameter {
                name: "office".to_string(),
                type_hint: "string".to_string(),
                description: "Office location".to_string(),
                required: false,
            },
            Parameter {
                name: "office_phone".to_string(),
                type_hint: "string".to_string(),
                description: "Office phone number".to_string(),
                required: false,
            },
            Parameter {
                name: "shell".to_string(),
                type_hint: "string".to_string(),
                description: "Login shell, e.g. '/bin/sh'".to_string(),
                required: false,
            },
            Parameter {
                name: "plan".to_string(),
                type_hint: "string".to_string(),
                description: "Contents of the user's .plan, printed under a 'Plan:' heading. \
                              May be several lines."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "project".to_string(),
                type_hint: "string".to_string(),
                description: "Contents of the user's .project, printed under a 'Project:' \
                              heading. May be several lines."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_finger_user",
            "login": "alice",
            "name": "Alice Smith",
            "tty": "ttys002",
            "idle": "5 minutes",
            "login_time": "Mon Sep  1 09:12",
            "office": "Room 101",
            "office_phone": "x1234",
            "shell": "/bin/sh",
            "project": "Networking",
            "plan": "Ship the finger server."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FINGER user {login}")
                .with_debug("FINGER send_finger_user: login={login}, tty={tty}, idle={idle}"),
        ),
    }
}

fn send_finger_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_finger_response".to_string(),
        description: "Send free text as the finger response - a listing of several users, a \
                      header line, or anything the user block does not fit. Line endings are \
                      normalised to CRLF. The server closes once the response is written."
            .to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The text to send. Newlines are allowed and become CRLF.".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_finger_response",
            "text": "Login     Name          Tty  Idle  Login Time\nalice     Alice Smith   *    2     Mon 09:12\nbob       Bob Jones     con  -     Mon 08:40"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FINGER response ({text_len}B)")
                .with_debug("FINGER send_finger_response: {text_len} bytes"),
        ),
    }
}

fn send_finger_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_finger_error".to_string(),
        description: "Refuse the query with a one-line 'finger: <message>' notice - an unknown \
                      login, a refused listing, a refused forwarding attempt."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Reason, e.g. 'no such user' (default) or 'listing all users is not \
                          permitted'"
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_finger_error",
            "message": "no such user"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FINGER error: {message}")
                .with_debug("FINGER send_finger_error: {message}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the connection without writing anything further. The server \
                      already closes after each response (RFC 1288), so this is only needed \
                      to answer with nothing at all."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("FINGER connection closed")
                .with_debug("FINGER close_connection"),
        ),
    }
}

fn finger_actions() -> Vec<ActionDefinition> {
    vec![
        send_finger_user_action(),
        send_finger_response_action(),
        send_finger_error_action(),
        close_connection_action(),
    ]
}

/// Raised once per connection, when the client's `{Q1}`/`{Q2}` line has been read.
///
/// `forward_host` is present exactly when the client sent `user@host`. It is surfaced rather
/// than hidden so the attempt is visible to the model, to a handler and in the TUI - but
/// nothing NetGet does with the answer ever contacts that host.
pub static FINGER_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "finger_query",
        "Client sent a Finger (RFC 1288) query",
        // Rendered verbatim into the documentation the model reads, so it must be an action
        // this protocol's executor actually accepts.
        json!({
            "type": "send_finger_user",
            "login": "alice",
            "name": "Alice Smith",
            "tty": "ttys002",
            "idle": "5 minutes",
            "login_time": "Mon Sep  1 09:12",
            "office": "Room 101",
            "office_phone": "x1234",
            "shell": "/bin/sh",
            "plan": "Ship the finger server."
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "username".to_string(),
            type_hint: "string|null".to_string(),
            description: "The requested login name, or null when the query was empty".to_string(),
            required: false,
        },
        Parameter {
            name: "verbose".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client sent '/W', asking for the long format".to_string(),
            required: true,
        },
        Parameter {
            name: "forward_host".to_string(),
            type_hint: "string|null".to_string(),
            description: "The '@host' of a forwarding query, or null. NetGet never contacts \
                          this host; the field exists so the attempt is visible."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "list_all".to_string(),
            type_hint: "boolean".to_string(),
            description: "No username was given: the client asked for every user".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("FINGER query user={username} verbose={verbose} list_all={list_all}")
            .with_debug("FINGER query: user={username} forward_host={forward_host}")
            .with_trace("FINGER: {json_pretty(.)}"),
    )
    .with_actions(finger_actions())
    .with_alternative_example(json!({
        "type": "send_finger_error",
        "message": "no such user"
    }))
});

pub fn get_finger_event_types() -> Vec<EventType> {
    vec![FINGER_QUERY_EVENT.clone()]
}
