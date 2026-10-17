//! NNTP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

pub const DEFAULT_REQUIRE_AUTH: bool = false;

/// NNTP protocol action handler
pub struct NntpProtocol {
    /// Map of active connections to their state (if needed in future)
    #[allow(dead_code)]
    connections: Arc<Mutex<HashMap<ConnectionId, ()>>>,
}

impl NntpProtocol {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Execute send_nntp_message action
    fn execute_send_nntp_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' field")?;

        // Ensure message ends with \r\n. A bare trailing \n is replaced, not added to: appending
        // \r after it put "\n\r" on the wire, which ends no NNTP line.
        let formatted = if message.ends_with("\r\n") {
            message.to_string()
        } else if let Some(line) = message.strip_suffix('\n') {
            format!("{}\r\n", line)
        } else {
            format!("{}\r\n", message)
        };

        Ok(ActionResult::Output(formatted.into_bytes()))
    }

    /// Execute send_nntp_response action
    fn execute_send_nntp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action
            .get("code")
            .and_then(|v| v.as_u64())
            .context("Missing 'code' field")?;
        let text = action
            .get("text")
            .and_then(|v| v.as_str())
            .context("Missing 'text' field")?;

        let response = format!("{} {}\r\n", code, text);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    /// Execute send_nntp_article action
    fn execute_send_nntp_article(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(220); // Default: 220 <n> <message-id> article retrieved
        let message_id = action
            .get("message_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let headers = action
            .get("headers")
            .and_then(|v| v.as_str())
            .context("Missing 'headers' field")?;
        let body = action.get("body").and_then(|v| v.as_str()).unwrap_or("");

        let number = action["number"].as_u64().unwrap_or(1);
        let id = if message_id.is_empty() {
            "<netget@localhost>"
        } else {
            super::extensions::message_id(message_id)?
        };
        anyhow::ensure!((220..=223).contains(&code), "article code must be 220..223");
        let mut response = format!("{code} {number} {id} article follows\r\n").into_bytes();
        if code != 223 {
            let payload = match code {
                221 => headers.to_string(),
                222 => body.to_string(),
                _ => format!(
                    "{}\n\n{}",
                    headers.replace("\r\n", "\n").trim_end_matches('\n'),
                    body
                ),
            };
            response.extend(super::extensions::dot_block(&payload)?);
        }
        Ok(ActionResult::Output(response))
    }

    /// Execute send_nntp_list action
    fn execute_send_nntp_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let groups = action
            .get("groups")
            .and_then(|v| v.as_array())
            .context("Missing 'groups' array field")?;

        let mut response = String::from("215 list of newsgroups follows\r\n");

        for group in groups {
            let name = group
                .get("name")
                .and_then(|v| v.as_str())
                .context("Missing 'name' in group")?;
            let high = group.get("high").and_then(|v| v.as_u64()).unwrap_or(0);
            let low = group.get("low").and_then(|v| v.as_u64()).unwrap_or(0);
            let status = group.get("status").and_then(|v| v.as_str()).unwrap_or("y");

            response.push_str(&format!("{} {} {} {}\r\n", name, high, low, status));
        }

        response.push_str(".\r\n");
        Ok(ActionResult::Output(response.into_bytes()))
    }

    /// Execute send_nntp_group action
    fn execute_send_nntp_group(&self, action: serde_json::Value) -> Result<ActionResult> {
        let name = action
            .get("name")
            .and_then(|v| v.as_str())
            .context("Missing 'name' field")?;
        let count = action.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let low = action.get("low").and_then(|v| v.as_u64()).unwrap_or(0);
        let high = action.get("high").and_then(|v| v.as_u64()).unwrap_or(0);

        // Format: 211 count low high group
        let response = format!("211 {} {} {} {}\r\n", count, low, high, name);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    /// Execute send_nntp_overview action
    fn execute_send_nntp_overview(&self, action: serde_json::Value) -> Result<ActionResult> {
        let articles = action
            .get("articles")
            .and_then(|v| v.as_array())
            .context("Missing 'articles' array field")?;

        let mut response = String::from("224 overview information follows\r\n");

        for article in articles {
            let number = article
                .get("number")
                .and_then(|v| v.as_u64())
                .context("Missing 'number'")?;
            let subject = article
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let from = article.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let date = article.get("date").and_then(|v| v.as_str()).unwrap_or("");
            let message_id = article
                .get("message_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let references = article
                .get("references")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let bytes = article.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let lines = article.get("lines").and_then(|v| v.as_u64()).unwrap_or(0);

            response.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\r\n",
                number, subject, from, date, message_id, references, bytes, lines
            ));
        }

        response.push_str(".\r\n");
        Ok(ActionResult::Output(response.into_bytes()))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NntpProtocol {
    /// None.
    ///
    /// `send_first` used to be declared here and nothing read it. It could not have been read:
    /// RFC 3977 5.1 makes the greeting **mandatory** — a client blocks reading a status line the
    /// instant it connects — so `handle_connection` raises the greeting event unconditionally and
    /// `send_first: false` would produce a session no NNTP client can begin. The flag was not a
    /// knob that was left unwired; it was a knob that must not exist. `ftp` declares none for the
    /// same reason and says so.
    ///
    /// `server_startup` warns when a caller passes top-level `send_first` to a protocol that
    /// declares none, so the request is refused audibly rather than silently accepted.
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // The read deadlines, and nothing else: their right value is a property of who is on
        // the other end, which only the operator knows. The defaults serve NetGet's own NNTP
        // client parked at the dashboard waiting for a person; a listener exposed to
        // strangers wants the first one much lower.
        let mut fields = vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no command at all - not even \
                              a CAPABILITIES after the greeting - before the server closes it. \
                              Default 300, matching the window a `manual` rule gives a human \
                              to answer one event. The peer is often NetGet's own NNTP client, \
                              which reads the welcome line in its read loop and writes nothing \
                              until an action or [ send message ] says to. Lower it (60 was \
                              the old value) for a listener exposed to strangers."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::FIRST_COMMAND_READ_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established connection may go without a further \
                              command before the server closes it. Default 600: a newsreader \
                              is idle for as long as the person at it takes to read an \
                              article, so this is on a human timescale rather than a machine \
                              one."
                    .to_string(),
                required: false,
                example: json!(600),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_COMMANDS_TIMEOUT.as_secs()
                )),
            },
        ];
        fields.extend(crate::server::p2p_support::tls_parameters(true));
        fields.push(crate::llm::actions::ParameterDefinition{name:"require_auth".into(),type_hint:"boolean".into(),description:"Require handler-approved AUTHINFO authentication before reader/feed operations; requires TLS".into(),required:false,example:json!(true),default:Some(json!(DEFAULT_REQUIRE_AUTH))});
        fields
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // NNTP could have async actions like post_article in the future
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = vec![
            send_nntp_message_action(),
            send_nntp_response_action(),
            send_nntp_article_action(),
            send_nntp_list_action(),
            send_nntp_group_action(),
            send_nntp_overview_action(),
            wait_for_more_action(),
            close_connection_action(),
        ];
        actions.extend(super::extensions::server_actions());
        actions
    }
    fn protocol_name(&self) -> &'static str {
        "NNTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_nntp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NNTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nntp", "usenet", "news", "newsgroup"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(119)
            .implementation("Bounded NNTP reader, posting and sequential feed framing (RFC 3977/4643/4644); optional implicit TLS")
            .llm_control("Reader content, authentication decisions and POST/IHAVE/TAKETHIS article acceptance")
            .e2e_testing("Independent Python nntplib reader/post/feed and NNTP_SSL authentication; malformed input and owner shutdown")
            .max_inbound_bytes(crate::server::nntp::extensions::MAX_ARTICLE)
            .notes("Handler-owned articles and accounts; no persistent spool, STARTTLS, SASL or compression. Streaming commands are processed sequentially; credentials require TLS.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Pipelined reading commands (GROUP, LIST, ARTICLE/HEAD/BODY, OVER and the rest,
            // ending at QUIT) that arrive during a call are answered in one; an answer without
            // exactly one response per command is replaced by 403 for each. AUTHINFO, MODE,
            // CAPABILITIES and article transfers are never batched. See `nntp_batch_role`.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "Usenet news server (NNTP)"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Usenet news server"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 119,
                "base_stack": "nntp",
                "instruction": "NNTP news server with newsgroups comp.lang.rust and misc.test"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 119,
                "base_stack": "nntp",
                "event_handlers": [{
                    "event_pattern": "nntp_command_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle NNTP commands\ncmd = event.get('command', '').upper()\nif cmd == 'LIST':\n    respond([{'type': 'send_nntp_list', 'groups': [{'name': 'comp.lang.rust', 'high': 100, 'low': 1, 'status': 'y'}]}])\nelif cmd.startswith('GROUP'):\n    respond([{'type': 'send_nntp_group', 'name': 'comp.lang.rust', 'count': 100, 'low': 1, 'high': 100}])\nelif cmd == 'QUIT':\n    respond([{'type': 'send_nntp_response', 'code': 205, 'text': 'Goodbye'}])\nelse:\n    respond([{'type': 'send_nntp_response', 'code': 200, 'text': 'OK'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 119,
                "base_stack": "nntp",
                "event_handlers": [{
                    "event_pattern": "nntp_command_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_nntp_response",
                            "code": 200,
                            "text": "NetGet NNTP Server Ready"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for NntpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::nntp::NntpServer;

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

            let tls = crate::server::p2p_support::server_tls(ctx.startup_params.as_ref())?;
            let require_auth = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("require_auth"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_REQUIRE_AUTH);
            anyhow::ensure!(
                !require_auth || tls.is_some(),
                "require_auth requires implicit TLS"
            );
            NntpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
                tls,
                require_auth,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        if matches!(
            action_type,
            "nntp_auth_result" | "nntp_check_result" | "nntp_article_result"
        ) {
            anyhow::ensure!(action["accepted"].is_boolean(), "accepted boolean required");
            return Ok(ActionResult::Custom {
                name: action_type.into(),
                data: action,
            });
        }
        match action_type {
            "send_nntp_message" => self.execute_send_nntp_message(action),
            "send_nntp_response" => self.execute_send_nntp_response(action),
            "send_nntp_article" => self.execute_send_nntp_article(action),
            "send_nntp_list" => self.execute_send_nntp_list(action),
            "send_nntp_group" => self.execute_send_nntp_group(action),
            "send_nntp_overview" => self.execute_send_nntp_overview(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown NNTP action: {}", action_type)),
        }
    }
}

// Event type definition
pub static NNTP_COMMAND_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nntp_command_received",
        "A client sent an NNTP command line, or the connection just opened (command \
         \"GREETING\"). Answer with exactly one action, chosen by the command - answer_with \
         names it for this one: a plain status line with send_nntp_response, GROUP with \
         send_nntp_group (or 411 when there is no such group), LIST/NEWGROUPS with \
         send_nntp_list, ARTICLE/HEAD/BODY with send_nntp_article, XOVER/OVER with \
         send_nntp_overview, or any raw line with send_nntp_message. QUIT should be answered \
         with a 205 and then close_connection. CAPABILITIES and MODE READER are answered by \
         NetGet and never reach you.",
        json!({
            "type": "send_nntp_response",
            "code": 200,
            "text": "NetGet NNTP Service Ready"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The NNTP command line the client sent, without its trailing CRLF. The \
                          literal string \"GREETING\" instead of a command means the connection \
                          has just opened and is waiting for the initial banner"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which action and reply code answer this command, when its verb says"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "group".to_string(),
            type_hint: "string".to_string(),
            description: "GROUP only: the newsgroup the client asked for".to_string(),
            required: false,
        },
        Parameter {
            name: "article".to_string(),
            type_hint: "string".to_string(),
            description: "ARTICLE/HEAD/BODY only: the article number or message-id asked for"
                .to_string(),
            required: false,
        },
    ])
    // All eight sync actions can answer this event - it is the protocol's only event and covers
    // every NNTP command. Without this list `call_llm` would offer the model none of them, since
    // it builds the model's tool list from the event type rather than from get_sync_actions().
    .with_actions(
        vec![
            send_nntp_response_action(),
            send_nntp_group_action(),
            send_nntp_list_action(),
            send_nntp_article_action(),
            send_nntp_overview_action(),
            send_nntp_message_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
        .into_iter()
        .chain(super::extensions::server_actions())
        .collect(),
    )
    .with_log_template(
        LogTemplate::new()
            .with_info("NNTP command: {command}")
            .with_debug("NNTP {command}")
            .with_trace("NNTP: {json_pretty(.)}"),
    )
});

fn get_nntp_event_types() -> Vec<EventType> {
    vec![NNTP_COMMAND_RECEIVED_EVENT.clone()]
}

// Action definitions

fn send_nntp_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_message".to_string(),
        description: "Send raw NNTP message (auto-adds \\r\\n if not present)".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "NNTP message to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_nntp_message",
            "message": "111 20260101000000"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP: {preview(message,60)}")
                .with_debug("NNTP send_nntp_message: {message}"),
        ),
    }
}

fn send_nntp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_response".to_string(),
        description: "One status line, '<code> <text>': the greeting (200/201), 411 for a \
                      group that does not exist, 423/430 for a missing article, 205 for QUIT. \
                      The example is a greeting; any other command takes its own code."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "NNTP response code (e.g., 200, 211, 220, 500)".to_string(),
                required: true,
            },
            Parameter {
                name: "text".to_string(),
                type_hint: "string".to_string(),
                description: "Response text".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_nntp_response",
            "code": 201,
            "text": "news.example.invalid ready, posting prohibited"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP {code} {text}")
                .with_debug("NNTP send_nntp_response: code={code}"),
        ),
    }
}

fn send_nntp_article_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_article".to_string(),
        description: "Send NNTP article with headers and body (multi-line response)".to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Response code (220=article, 221=head, 222=body)".to_string(),
                required: false,
            },
            Parameter {
                name: "message_id".to_string(),
                type_hint: "string".to_string(),
                description: "Message-ID (optional)".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "string".to_string(),
                description: "Article headers (one per line)".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Article body text".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nntp_article",
            "code": 220,
            "message_id": "<12345@example.com>",
            "headers": "Subject: Test\r\nFrom: user@example.com",
            "body": "This is a test article."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP {code} {message_id} article")
                .with_debug("NNTP send_nntp_article: code={code}, message_id={message_id}"),
        ),
    }
}

fn send_nntp_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_list".to_string(),
        description: "The answer to LIST (LIST ACTIVE): every group the server carries, as \
                      a 215 block; NetGet adds the terminating '.'. The example's group is a \
                      placeholder."
            .to_string(),
        parameters: vec![Parameter {
            name: "groups".to_string(),
            type_hint: "array".to_string(),
            description: "Array of newsgroups with name, high, low, status".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_nntp_list",
            "groups": [
                {"name": "comp.lang.rust", "high": 100, "low": 1, "status": "y"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP 215 {groups_len} newsgroups")
                .with_debug("NNTP send_nntp_list: {groups_len} groups"),
        ),
    }
}

fn send_nntp_group_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_group".to_string(),
        description: "The answer to GROUP for a group that exists: '211 <count> <low> \
                      <high> <name>'. For a group that does not exist, send_nntp_response with \
                      code 411 instead."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "Newsgroup name".to_string(),
                required: true,
            },
            Parameter {
                name: "count".to_string(),
                type_hint: "number".to_string(),
                description: "Estimated number of articles".to_string(),
                required: false,
            },
            Parameter {
                name: "low".to_string(),
                type_hint: "number".to_string(),
                description: "Lowest article number".to_string(),
                required: false,
            },
            Parameter {
                name: "high".to_string(),
                type_hint: "number".to_string(),
                description: "Highest article number".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nntp_group",
            "name": "comp.lang.rust",
            "count": 100,
            "low": 1,
            "high": 100
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP 211 {name} {count} articles")
                .with_debug("NNTP send_nntp_group: name={name}, count={count}"),
        ),
    }
}

fn send_nntp_overview_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nntp_overview".to_string(),
        description: "Send article overview information (XOVER/OVER command)".to_string(),
        parameters: vec![Parameter {
            name: "articles".to_string(),
            type_hint: "array".to_string(),
            description: "Array of articles with number, subject, from, date, message_id, references, bytes, lines".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_nntp_overview",
            "articles": [
                {
                    "number": 1,
                    "subject": "Test",
                    "from": "user@example.com",
                    "date": "Mon, 1 Jan 2024 00:00:00 +0000",
                    "message_id": "<12345@example.com>",
                    "references": "",
                    "bytes": 100,
                    "lines": 5
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NNTP 224 {articles_len} articles")
                .with_debug("NNTP send_nntp_overview: {articles_len} articles"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding".to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("NNTP waiting for more data")
                .with_debug("NNTP wait_for_more"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the NNTP connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("NNTP connection closed")
                .with_debug("NNTP close_connection"),
        ),
    }
}
