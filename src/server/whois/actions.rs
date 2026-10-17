//! WHOIS protocol actions implementation

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

/// Strip control characters from a value that occupies one line of a WHOIS record.
///
/// A WHOIS *response* is free text and may be anything — `send_whois_response` exists for
/// exactly that and is deliberately not filtered. A WHOIS **record** is not free text: it is
/// `Key: value` lines, and a `registrar` of `"Foo\r\nRegistrant Name: Bar"` forges a field
/// the model never asserted. Whoever reads the output — a human, or more dangerously a script
/// grepping for `Registrant Name:` — cannot tell a forged line from a real one.
///
/// This is the family's signature defect (FTP's `send_ftp_response` documented that text must
/// not contain CR/LF and checked nothing, turning a 331 into a successful login), and it is
/// worth noting that **both of this server's neighbours added the guard independently and
/// WHOIS did not** — `gopher`'s `sanitize_field`, `finger`'s `strip_controls`, `ident`'s
/// `sanitize_token`. WHOIS is the protocol the simple ones in this repo were told to copy, so
/// it is the one place the omission propagates from.
///
/// The guarantee is **no forged line**, not "the words disappear". `"Foo\r\nRegistrant Name:
/// Bar"` still says `Registrant Name: Bar` — it just says it inside the `Registrar:` field,
/// where a line-oriented reader attributes it correctly.
///
/// Every control character becomes a space rather than vanishing, which is `gopher`'s choice
/// next door and the better one: deleting them concatenates the two sides into a single word
/// (`Good RegistrarRegistrant`), which reads as one value and is its own small lie. ESC goes
/// with CR, LF and tab, because this text lands in a terminal and on the operator's own
/// dashboard, where an escape sequence forges a screen rather than merely a line.
fn sanitize_line_field(s: &str) -> String {
    crate::utils::sanitize::line_field(s)
}

/// `extra_fields` entries `send_whois_record` renders. A bound, not a style: every entry is a
/// line on the wire, and a record is a summary rather than a transport for a model's whole
/// output — `send_whois_response` is the free-text action for that.
pub const MAX_EXTRA_FIELDS: usize = 32;

pub struct WhoisProtocol;

impl WhoisProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WhoisProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no query before the server \
                              closes it. Default 300, matching the window a `manual` rule \
                              gives a human to answer one event - a peer is often NetGet's \
                              own WHOIS client, which sends nothing at all until someone \
                              types a domain into [ send message ]. Lower it for a listener \
                              exposed to strangers."
                    .to_string(),
                required: false,
                example: serde_json::json!(300),
                default: Some(serde_json::json!(super::FIRST_QUERY_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the server keeps reading after it has answered a query, \
                              for a client that wants to send another down the same socket. \
                              Default 15, deliberately short: RFC 3912 says the connection is \
                              over at this point, and this bound is what unblocks a real \
                              client when a handler answered without close_connection. Raise \
                              it for a session where a human issues several queries by hand."
                    .to_string(),
                required: false,
                example: serde_json::json!(15),
                default: Some(serde_json::json!(super::IDLE_AFTER_REPLY_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new() // WHOIS has no async actions
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_whois_response_action(),
            send_whois_record_action(),
            send_error_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "WHOIS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_whois_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>WHOIS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["whois"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(43))
            .well_known_port(43)
            .implementation("Manual TCP connection handling")
            .llm_control("WHOIS query responses (domain, registrant, contact info)")
            .e2e_testing(
                "tests/server/whois/e2e_test.rs, 6 LLM calls. One test drives the real whois(1) \
                 binary (`whois -h localhost -p PORT example.com`) and asserts the record it \
                 prints; the rest use a raw TCP socket for the cases whois(1) cannot reach - an \
                 error reply, two queries on one connection, and connection logging. Note macOS \
                 whois(1) segfaults when -h is given an IP literal; a hostname works. \
                 line_framing_test.rs additionally pins that a query split across four TCP \
                 segments raises one event, and that 16 KiB with no newline is refused; \
                 peer_inject_test.rs covers dashboard injection with zero LLM calls.",
            )
            .notes(
                "Simple line-based protocol. RFC 3912 has the server close as soon as its output \
                 is finished; this server keeps reading so several queries can share a \
                 connection, so a handler that answers without close_connection leaves whois(1) \
                 blocked on EOF until the 15s post-reply idle timeout closes it. Pair the answer \
                 with close_connection. Queries are read as lines, capped at 4 KiB.",
            )
            .max_inbound_bytes(crate::server::whois::MAX_QUERY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "WHOIS domain lookup server"
    }
    fn example_prompt(&self) -> &'static str {
        "WHOIS server on port 43 - respond with fake registrar information for any domain"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 43,
                "base_stack": "whois",
                "instruction": "WHOIS server responding with fake registration info for any domain"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 43,
                "base_stack": "whois",
                "event_handlers": [{
                    "event_pattern": "whois_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Return WHOIS record for queried domain\ndomain = event.get('query', 'unknown.com').strip()\nrespond([{'type': 'send_whois_record', 'domain': domain, 'registrar': 'Example Registrar Inc.', 'registrant': 'Example Organization', 'name_servers': ['ns1.example.com', 'ns2.example.com']}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 43,
                "base_stack": "whois",
                "event_handlers": [{
                    "event_pattern": "whois_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Example Registrar Inc.",
                            "registrant": "Example Organization",
                            "name_servers": ["ns1.example.com", "ns2.example.com"]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for WhoisProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::whois::WhoisServer;
            // Both read bounds are tunable because their right value is a property of who is on
            // the other end, which only the operator knows. The first default serves NetGet's
            // own client waiting on a human at `[ send message ]`; a listener exposed to
            // strangers wants it much lower.
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

            WhoisServer::spawn_with_llm_actions(
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
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_whois_response" => self.execute_send_whois_response(action),
            "send_whois_record" => self.execute_send_whois_record(action),
            "send_error" => self.execute_send_error(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown WHOIS action: {}", action_type)),
        }
    }
}

impl WhoisProtocol {
    fn execute_send_whois_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = action
            .get("response")
            .and_then(|v| v.as_str())
            .context("Missing 'response' parameter")?;

        // WHOIS protocol ends responses with CRLF
        let mut data = response.to_string();
        if !data.ends_with('\n') {
            data.push_str("\r\n");
        }

        Ok(ActionResult::Output(data.into_bytes()))
    }

    fn execute_send_whois_record(&self, action: serde_json::Value) -> Result<ActionResult> {
        let domain = action
            .get("domain")
            .and_then(|v| v.as_str())
            .context("Missing 'domain' parameter")?;
        let text = |key: &str| action.get(key).and_then(|v| v.as_str());

        // `domain_status` is a list in real records (one `Domain Status:` line per EPP status);
        // a single string is accepted because that is what a model writes for one status.
        let statuses: Vec<&str> = match action.get("domain_status") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::String(s)) => vec![s.as_str()],
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .context("send_whois_record 'domain_status' entries must be strings")
                })
                .collect::<Result<_>>()?,
            Some(other) => anyhow::bail!(
                "send_whois_record 'domain_status' must be a string or a list of strings, \
                 got {other}"
            ),
        };

        let extra: Vec<(&String, &str)> = match action.get("extra_fields") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Object(map)) => {
                if map.len() > MAX_EXTRA_FIELDS {
                    anyhow::bail!(
                        "send_whois_record 'extra_fields' has {} entries; at most {} are \
                         rendered. Put the rest in send_whois_response.",
                        map.len(),
                        MAX_EXTRA_FIELDS
                    );
                }
                map.iter()
                    .map(|(k, v)| {
                        v.as_str().map(|v| (k, v)).with_context(|| {
                            format!("send_whois_record extra field {k:?} must be a string")
                        })
                    })
                    .collect::<Result<_>>()?
            }
            Some(other) => anyhow::bail!(
                "send_whois_record 'extra_fields' must be an object of \"Key\": \"value\", \
                 got {other}"
            ),
        };

        let name_servers = action
            .get("name_servers")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        // Every field is one line of a `Key: value` record, so each is sanitised: a CR or LF
        // in any of them would forge a field the model never asserted. See
        // `sanitize_line_field`. Use `send_whois_response` when free text is wanted.
        //
        // A field the model did not give is left out rather than filled in. This used to print
        // `Registrar: Example Registrar, Inc.`, `Registrant Name: Registrant Contact` and
        // `Admin Name: Admin Contact` whenever those were omitted — assertions nobody made, in
        // the one format whose readers take every line at its word.
        let mut response = String::new();
        let mut line = |key: &str, value: &str| {
            response.push_str(&format!(
                "{}: {}\r\n",
                sanitize_line_field(key),
                sanitize_line_field(value)
            ));
        };
        line("Domain Name", domain);
        if let Some(v) = text("registrar") {
            line("Registrar", v);
        }
        for status in statuses {
            line("Domain Status", status);
        }
        if let Some(v) = text("registrant") {
            line("Registrant Name", v);
        }
        if let Some(v) = text("registrant_organization").or_else(|| text("registrant_org")) {
            line("Registrant Organization", v);
        }
        if let Some(v) = text("admin_contact") {
            line("Admin Name", v);
        }
        for (key, value) in extra {
            // A colon in the key would move the `Key:` boundary a line-oriented reader splits on.
            line(&key.replace(':', " "), value);
        }
        for ns in name_servers {
            line("Name Server", ns);
        }

        response.push_str("\r\n");
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error_msg = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Domain not found");

        // One line, so it is sanitised: `Error: nope\r\nDomain Name: evil.test` would forge a
        // record out of a refusal.
        let response = format!("Error: {}\r\n\r\n", sanitize_line_field(error_msg));
        Ok(ActionResult::Output(response.into_bytes()))
    }
}

fn send_whois_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_whois_response".to_string(),
        description: "Send custom WHOIS response - free text, written exactly as given (a CRLF \
                      is appended if missing), so this is the action to use for multi-line \
                      output. Use send_whois_record instead when the answer is a record: its \
                      fields are single lines and are sanitised, and this one is not. RFC 3912 \
                      has the server close as soon as the output is finished, and a real client \
                      (whois(1)) reads until EOF, so pair this with close_connection unless you \
                      intend the client to block"
            .to_string(),
        parameters: vec![Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "Response text to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_whois_response",
            "response": "Domain Name: example.com\nRegistrar: Example Inc.\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WHOIS response ({response_len}B)")
                .with_debug("WHOIS send_whois_response: {response_len} bytes"),
        ),
    }
}

fn send_whois_record_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_whois_record".to_string(),
        description: "Send a WHOIS record as standard `Key: value` lines. Every field the \
                      instruction mentions goes in its own parameter - registrar, registrant, \
                      registrant organisation, domain status - and anything else goes in \
                      extra_fields; a field you leave out is not printed. RFC 3912 has the \
                      server close as soon as the output is finished, and a real client \
                      (whois(1)) reads until EOF, so pair this with close_connection unless you \
                      intend the client to block"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name".to_string(),
                required: true,
            },
            Parameter {
                name: "registrar".to_string(),
                type_hint: "string".to_string(),
                description: "Registrar name".to_string(),
                required: false,
            },
            Parameter {
                name: "registrant".to_string(),
                type_hint: "string".to_string(),
                description: "Registrant name (a person), printed as Registrant Name".to_string(),
                required: false,
            },
            Parameter {
                name: "registrant_organization".to_string(),
                type_hint: "string".to_string(),
                description: "Registrant organisation (a company), printed as Registrant \
                              Organization"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "domain_status".to_string(),
                type_hint: "array".to_string(),
                description: "EPP status codes, e.g. [\"clientTransferProhibited\"]; one \
                              Domain Status line each. A single string is accepted."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "admin_contact".to_string(),
                type_hint: "string".to_string(),
                description: "Admin contact name".to_string(),
                required: false,
            },
            Parameter {
                name: "name_servers".to_string(),
                type_hint: "array".to_string(),
                description: "List of nameservers".to_string(),
                required: false,
            },
            Parameter {
                name: "extra_fields".to_string(),
                type_hint: "object".to_string(),
                description: "Any other record lines, as {\"Key\": \"value\"} - e.g. \
                              {\"Creation Date\": \"2020-01-01\"}. At most 32."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_whois_record",
            "domain": "example.com",
            "registrar": "VeriSign Registry",
            "registrant_organization": "Example Inc.",
            "domain_status": ["ok"],
            "name_servers": ["ns1.example.com", "ns2.example.com"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WHOIS {domain} ({registrar})")
                .with_debug("WHOIS send_whois_record: domain={domain}, registrar={registrar}"),
        ),
    }
}

fn send_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_error".to_string(),
        description: "Send error message for domain not found".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Error message".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_error",
            "message": "Domain not found in database"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WHOIS error: {message}")
                .with_debug("WHOIS send_error: {message}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the WHOIS connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("WHOIS connection closed")
                .with_debug("WHOIS close_connection"),
        ),
    }
}

/// WHOIS query event - triggered when client sends a query
pub static WHOIS_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "whois_query",
        "Client sent a WHOIS domain lookup query",
        // Rendered verbatim into the protocol documentation the model reads
        // (src/llm/actions/tools.rs and src/mcp_stdio/docs.rs), so it must be an action the
        // executor actually accepts - the previous {"type": "placeholder"} was not.
        json!({
            "type": "send_whois_record",
            "domain": "example.com",
            "registrar": "Example Registrar, Inc.",
            "registrant": "Example Organization",
            "name_servers": ["ns1.example.com", "ns2.example.com"]
        }),
    )
    .with_parameters(vec![Parameter {
        name: "query".to_string(),
        type_hint: "string".to_string(),
        description: "The WHOIS query string".to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("WHOIS {query}")
            .with_debug("WHOIS query: {query}")
            .with_trace("WHOIS: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_whois_response_action(),
        send_whois_record_action(),
        send_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_error",
        "message": "No match for domain \"example.invalid\""
    }))
});

pub fn get_whois_event_types() -> Vec<EventType> {
    vec![WHOIS_QUERY_EVENT.clone()]
}
