//! XMPP protocol actions implementation

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
use tracing::debug;

/// Default server domain when the `domain` startup parameter is not supplied.
pub const DEFAULT_XMPP_DOMAIN: &str = "localhost";

/// Escape text for inclusion in XML character data or a single-quoted attribute value.
///
/// Every string reaching an XMPP stanza here comes from the model - message bodies, status
/// text, JIDs, error conditions. Interpolating them raw meant a body containing `&`, `<` or an
/// apostrophe emitted a malformed stanza, and a real client's XML parser drops the whole
/// stream on the first well-formedness error rather than skipping the stanza.
///
/// Characters XML 1.0 does not allow at all are **dropped**. Its `Char` production (§2.2)
/// admits tab, LF, CR and `U+0020` upwards, less the surrogate block and `U+FFFE`/`U+FFFF`.
/// The rest - the C0 controls `U+0000`-`U+0008`, `U+000B`, `U+000C`, `U+000E`-`U+001F`, and
/// the two noncharacters - make a document ill-formed however they are written, because a
/// character reference to them (`&#1;`) is forbidden too. A strict parser (rxml, under every
/// tokio-xmpp client, or expat) answers by ending the whole stream, so one stray `U+001B`
/// in a model-composed body would cost the peer its session. The character carries nothing
/// a chat client could show, so removing it loses nothing; tab, LF and CR are kept.
/// Surrogates need no check: a Rust `char` cannot hold one.
///
/// `send_raw_xml` and `send_iq_result`'s `payload` are deliberately *not* escaped: they exist
/// precisely so the model can emit markup, and both say so in their descriptions.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c if is_xml_char(c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// Whether XML 1.0's `Char` production (§2.2) admits `c`.
fn is_xml_char(c: char) -> bool {
    matches!(
        c,
        '\u{9}'
            | '\u{A}'
            | '\u{D}'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}'
    )
}

/// XMPP protocol action handler
///
/// Holds only the configured server domain. An `XmppClientState` map (JID, authenticated,
/// stream id, resource) with insert/update/lookup helpers used to live here, but nothing ever
/// called any of it - no JID was ever recorded and `authenticated` was never set. Session
/// state belongs to the model, not to the protocol.
pub struct XmppProtocol {
    /// Server domain, used as the default `from` on stream headers.
    domain: String,
}

impl XmppProtocol {
    pub fn new() -> Self {
        Self::with_domain(DEFAULT_XMPP_DOMAIN.to_string())
    }

    /// Build a handler bound to a specific server domain (the `domain` startup parameter).
    pub fn with_domain(domain: String) -> Self {
        Self { domain }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for XmppProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "XMPP server domain name (e.g., 'localhost', 'example.com')"
                    .to_string(),
                required: false,
                example: serde_json::json!("localhost"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a connected peer may send nothing at all before the server closes \
                     it. Default 30, the window ejabberd's `negotiation_timeout` gives for the \
                     same phase: RFC 6120 §4.2 has the initiating entity send the opening \
                     stream header first, so a peer that has sent nothing has begun no stream."
                        .to_string(),
                required: false,
                example: serde_json::json!(30),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established stream may carry no further bytes before the \
                     server closes it. Default 900. A silent XMPP session is normal — a \
                     connected person who is not typing sends nothing — and neither ejabberd \
                     nor Prosody closes one at all, so this bounds the held socket rather than \
                     enforcing a session policy; it sits above every keepalive interval real \
                     clients use."
                    .to_string(),
                required: false,
                example: serde_json::json!(900),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_STANZAS_TIMEOUT.as_secs()
                )),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // XMPP could have async actions like broadcast_message in the future
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_stream_header_action(),
            send_stream_features_action(),
            send_message_action(),
            send_presence_action(),
            send_iq_result_action(),
            send_iq_error_action(),
            send_auth_success_action(),
            send_auth_failure_action(),
            send_raw_xml_action(),
            wait_for_more_action(),
            close_stream_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "XMPP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_xmpp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>XMPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["xmpp", "jabber", "messaging"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(5222)
            .implementation(
                "No XML parser: raw bytes are buffered and handed to the model as text, which \
                 decides where stanzas begin and end",
            )
            .llm_control("All XMPP stanzas (message, presence, iq) and the SASL outcome")
            .e2e_testing(
                "tests/server/xmpp/test.rs, 6 LLM calls. A TCP peer that parses everything the \
                 server writes with xmpp-parsers 0.22 - the stanza layer tokio-xmpp clients are \
                 built on. Verified: the stream header (namespace, from, id, version='1.0' and \
                 the XML declaration), <stream:features/> decoded into StreamFeatures with its \
                 SASL mechanism list, a message stanza decoded into Message (JIDs with resource, \
                 type, body round-tripped through XML escaping with &, <, > and an apostrophe in \
                 it), and a presence stanza decoded into Presence (no 'type' attribute when \
                 available, show, status). Not verified against a real client end to end: \
                 tokio_xmpp::Client cannot connect because there is no STARTTLS and no SASL \
                 exchange. IQ, auth and stream restart are untested.",
            )
            .notes(
                "Core stanzas only. No roster, no presence distribution, no MUC, no S2S, no \
                 TLS/STARTTLS, and no credential checking - the model decides every auth outcome.",
            )
            .max_inbound_bytes(crate::server::xmpp::MAX_XMPP_BUFFER_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // No stanza framing: an event is the connection's whole unconsumed byte buffer, so
            // what arrives during a call is already in the next event and there are no
            // separate events to batch — or to deliver one at a time with batching off.
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "XMPP instant messaging server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an XMPP server for instant messaging"
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
                "port": 5222,
                "base_stack": "xmpp",
                "instruction": "XMPP messaging server, accept all authentication, echo messages"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 5222,
                "base_stack": "xmpp",
                "event_handlers": [{
                    "event_pattern": "xmpp_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle XMPP XML data\nxml = event.get('xml_data', '')\nif '<stream:stream' in xml:\n    respond([{'type': 'send_stream_header', 'from': 'localhost'}, {'type': 'send_stream_features', 'mechanisms': ['PLAIN']}])\nelif '<auth' in xml:\n    respond([{'type': 'send_auth_success'}])\nelif '<message' in xml:\n    respond([{'type': 'send_message', 'from': 'server@localhost', 'to': 'user@localhost', 'body': 'Message received'}])\nelse:\n    respond([{'type': 'wait_for_more'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 5222,
                "base_stack": "xmpp",
                "event_handlers": [{
                    "event_pattern": "xmpp_data_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_stream_header",
                            "from": "localhost",
                            "stream_id": "stream-123"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for XmppProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::xmpp::XmppServer;

            // `domain` was declared as a startup parameter but never read, so a server started
            // with domain='example.com' still announced 'localhost' in its stream header.
            let domain = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("domain"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| DEFAULT_XMPP_DOMAIN.to_string());

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

            XmppServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                domain,
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
            "send_stream_header" => self.execute_send_stream_header(action),
            "send_stream_features" => self.execute_send_stream_features(action),
            "send_message" => self.execute_send_message(action),
            "send_presence" => self.execute_send_presence(action),
            "send_iq_result" => self.execute_send_iq_result(action),
            "send_iq_error" => self.execute_send_iq_error(action),
            "send_auth_success" => self.execute_send_auth_success(action),
            "send_auth_failure" => self.execute_send_auth_failure(action),
            "send_raw_xml" => self.execute_send_raw_xml(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_stream" => self.execute_close_stream(action),
            // The dashboard's `[ disconnect this peer ]` injects `close_connection`. It is not
            // in the model's vocabulary (the model uses `close_stream`, which also emits the
            // closing tag); this arm exists only so the injected disconnect half-closes the
            // socket instead of answering "Unknown action".
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown XMPP action: {}", action_type)),
        }
    }
}

// Action implementation methods
impl XmppProtocol {
    fn execute_send_stream_header(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Defaults to the domain the server was started with, so a server opened with
        // `domain: "example.com"` announces that even when the model omits `from`.
        let from = action
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.domain);

        let stream_id = action
            .get("stream_id")
            .and_then(|v| v.as_str())
            .unwrap_or("stream-id-123");

        let xml = format!(
            r#"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='{}' id='{}' version='1.0'>"#,
            xml_escape(from),
            xml_escape(stream_id)
        );

        debug!("XMPP sending stream header");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_stream_features(&self, action: serde_json::Value) -> Result<ActionResult> {
        let mechanisms = action
            .get("mechanisms")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| format!("<mechanism>{}</mechanism>", xml_escape(s)))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_else(|| "<mechanism>PLAIN</mechanism>".to_string());

        let xml = format!(
            r#"<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</mechanisms></stream:features>"#,
            mechanisms
        );

        debug!("XMPP sending stream features");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let from = action
            .get("from")
            .and_then(|v| v.as_str())
            .context("Missing 'from' parameter")?;

        let to = action
            .get("to")
            .and_then(|v| v.as_str())
            .context("Missing 'to' parameter")?;

        let body = action
            .get("body")
            .and_then(|v| v.as_str())
            .context("Missing 'body' parameter")?;

        let msg_type = action
            .get("message_type")
            .and_then(|v| v.as_str())
            .unwrap_or("chat");

        let xml = format!(
            r#"<message from='{}' to='{}' type='{}'><body>{}</body></message>"#,
            xml_escape(from),
            xml_escape(to),
            xml_escape(msg_type),
            xml_escape(body)
        );

        debug!("XMPP sending message from {} to {}", from, to);
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_presence(&self, action: serde_json::Value) -> Result<ActionResult> {
        let from = action.get("from").and_then(|v| v.as_str()).unwrap_or("");

        let presence_type = action
            .get("presence_type")
            .and_then(|v| v.as_str())
            .unwrap_or("available");

        let show = action.get("show").and_then(|v| v.as_str());

        let status = action.get("status").and_then(|v| v.as_str());

        let mut xml = if from.is_empty() {
            "<presence".to_string()
        } else {
            format!("<presence from='{}'", xml_escape(from))
        };

        if presence_type != "available" {
            xml.push_str(&format!(" type='{}'", xml_escape(presence_type)));
        }
        xml.push('>');

        if let Some(s) = show {
            xml.push_str(&format!("<show>{}</show>", xml_escape(s)));
        }
        if let Some(s) = status {
            xml.push_str(&format!("<status>{}</status>", xml_escape(s)));
        }

        xml.push_str("</presence>");

        debug!("XMPP sending presence");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_iq_result(&self, action: serde_json::Value) -> Result<ActionResult> {
        let id = action
            .get("id")
            .and_then(|v| v.as_str())
            .context("Missing 'id' parameter")?;

        let to = action.get("to").and_then(|v| v.as_str());

        let payload = action.get("payload").and_then(|v| v.as_str()).unwrap_or("");

        let to_attr = to
            .map(|t| format!(" to='{}'", xml_escape(t)))
            .unwrap_or_default();

        // `payload` is intentionally raw - it is documented as an XML payload.
        let xml = format!(
            r#"<iq type='result' id='{}'{}>{}</iq>"#,
            xml_escape(id),
            to_attr,
            payload
        );

        debug!("XMPP sending IQ result");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_iq_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let id = action
            .get("id")
            .and_then(|v| v.as_str())
            .context("Missing 'id' parameter")?;

        let error_type = action
            .get("error_type")
            .and_then(|v| v.as_str())
            .unwrap_or("cancel");

        let condition = action
            .get("condition")
            .and_then(|v| v.as_str())
            .unwrap_or("feature-not-implemented");

        // `condition` becomes an element *name*, so anything but a bare RFC 6120 condition
        // token would produce garbage no amount of escaping fixes - reject it instead.
        if !condition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || condition.is_empty()
        {
            anyhow::bail!(
                "Invalid 'condition' {:?}: must be an XMPP stanza error condition such as \
                 'feature-not-implemented', 'item-not-found' or 'service-unavailable'",
                condition
            );
        }

        let xml = format!(
            r#"<iq type='error' id='{}'><error type='{}'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"#,
            xml_escape(id),
            xml_escape(error_type),
            condition
        );

        debug!("XMPP sending IQ error");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_auth_success(&self, _action: serde_json::Value) -> Result<ActionResult> {
        let xml = r#"<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"#;
        debug!("XMPP sending auth success");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_auth_failure(&self, action: serde_json::Value) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("not-authorized");

        // Same as send_iq_error: this is an element name, not text.
        if reason.is_empty()
            || !reason
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            anyhow::bail!(
                "Invalid 'reason' {:?}: must be a SASL failure condition such as \
                 'not-authorized', 'temporary-auth-failure' or 'invalid-mechanism'",
                reason
            );
        }

        let xml = format!(
            r#"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{}/></failure>"#,
            reason
        );

        debug!("XMPP sending auth failure");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_send_raw_xml(&self, action: serde_json::Value) -> Result<ActionResult> {
        let xml = action
            .get("xml")
            .and_then(|v| v.as_str())
            .context("Missing 'xml' parameter")?;

        debug!("XMPP sending raw XML");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_close_stream(&self, _action: serde_json::Value) -> Result<ActionResult> {
        let xml = r#"</stream:stream>"#;
        debug!("XMPP closing stream");
        Ok(ActionResult::Multiple(vec![
            ActionResult::Output(xml.as_bytes().to_vec()),
            ActionResult::CloseConnection,
        ]))
    }
}

// Action definitions
fn send_stream_header_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stream_header".to_string(),
        description: "Send XMPP stream header to initiate XML stream".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Server domain name".to_string(),
                required: false,
            },
            Parameter {
                name: "stream_id".to_string(),
                type_hint: "string".to_string(),
                description: "Unique stream identifier".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stream_header",
            "from": "localhost",
            "stream_id": "stream-123"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP stream header from={from}")
                .with_debug("XMPP send_stream_header: from={from}, stream_id={stream_id}"),
        ),
    }
}

fn send_stream_features_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stream_features".to_string(),
        description: "Send stream features (authentication mechanisms, etc.)".to_string(),
        parameters: vec![Parameter {
            name: "mechanisms".to_string(),
            type_hint: "array".to_string(),
            description: "List of SASL mechanisms (e.g., ['PLAIN', 'SCRAM-SHA-1'])".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_stream_features",
            "mechanisms": ["PLAIN"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP stream features")
                .with_debug("XMPP send_stream_features: mechanisms={mechanisms}"),
        ),
    }
}

fn send_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_message".to_string(),
        description: "Send XMPP message stanza".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Sender JID".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Recipient JID".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Message body text".to_string(),
                required: true,
            },
            Parameter {
                name: "message_type".to_string(),
                type_hint: "string".to_string(),
                description: "Message type: chat, groupchat, headline, normal".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_message",
            "from": "bot@localhost",
            "to": "user@localhost",
            "body": "Hello, world!",
            "message_type": "chat"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP {from} -> {to}: {preview(body,40)}")
                .with_debug("XMPP send_message: from={from}, to={to}, type={message_type}"),
        ),
    }
}

fn send_presence_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_presence".to_string(),
        description: "Send XMPP presence stanza".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Sender JID".to_string(),
                required: false,
            },
            Parameter {
                name: "presence_type".to_string(),
                type_hint: "string".to_string(),
                description: "Presence type: available, unavailable, subscribe, etc.".to_string(),
                required: false,
            },
            Parameter {
                name: "show".to_string(),
                type_hint: "string".to_string(),
                description: "Availability: away, chat, dnd, xa".to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "string".to_string(),
                description: "Status message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_presence",
            "from": "user@localhost/resource",
            "show": "chat",
            "status": "Available for chat"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP presence: {presence_type}")
                .with_debug("XMPP send_presence: from={from}, show={show}"),
        ),
    }
}

fn send_iq_result_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_iq_result".to_string(),
        description: "Send IQ result stanza".to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "IQ ID (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Recipient JID".to_string(),
                required: false,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Optional XML payload".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_iq_result",
            "id": "iq-123",
            "to": "user@localhost",
            "payload": "<query xmlns='jabber:iq:roster'/>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP IQ result id={id}")
                .with_debug("XMPP send_iq_result: id={id}, to={to}"),
        ),
    }
}

fn send_iq_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_iq_error".to_string(),
        description: "Send IQ error stanza".to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "IQ ID (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "error_type".to_string(),
                type_hint: "string".to_string(),
                description: "Error type: cancel, continue, modify, auth, wait".to_string(),
                required: false,
            },
            Parameter {
                name: "condition".to_string(),
                type_hint: "string".to_string(),
                description: "Error condition".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_iq_error",
            "id": "iq-123",
            "error_type": "cancel",
            "condition": "feature-not-implemented"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP IQ error id={id}: {condition}")
                .with_debug(
                    "XMPP send_iq_error: id={id}, type={error_type}, condition={condition}",
                ),
        ),
    }
}

fn send_auth_success_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_auth_success".to_string(),
        description: "Send SASL authentication success".to_string(),
        parameters: vec![],
        example: json!({
            "type": "send_auth_success"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP auth success")
                .with_debug("XMPP send_auth_success"),
        ),
    }
}

fn send_auth_failure_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_auth_failure".to_string(),
        description: "Send SASL authentication failure".to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Failure reason".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_auth_failure",
            "reason": "not-authorized"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP auth failure: {reason}")
                .with_debug("XMPP send_auth_failure: reason={reason}"),
        ),
    }
}

fn send_raw_xml_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_raw_xml".to_string(),
        description: "Send raw XML data (for custom stanzas)".to_string(),
        parameters: vec![Parameter {
            name: "xml".to_string(),
            type_hint: "string".to_string(),
            description: "Raw XML string to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_raw_xml",
            "xml": "<custom xmlns='example:custom'/>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XMPP raw: {preview(xml,60)}")
                .with_debug("XMPP send_raw_xml"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding (accumulate in buffer)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("XMPP waiting for more data")
                .with_debug("XMPP wait_for_more"),
        ),
    }
}

fn close_stream_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_stream".to_string(),
        description: "Close XMPP stream and connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_stream"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("XMPP stream closed")
                .with_debug("XMPP close_stream"),
        ),
    }
}

// Event types
pub static XMPP_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmpp_data_received",
        "XML received from an XMPP client. This is whatever bytes have arrived, not a parsed \
         stanza: it may hold several stanzas or half of one. If it is incomplete, answer with \
         wait_for_more and the next event will carry it appended to what you already saw.",
        json!({"type": "send_stream_header", "from": "localhost", "stream_id": "stream-123"}),
    )
    .with_parameters(vec![Parameter {
        name: "xml_data".to_string(),
        type_hint: "string".to_string(),
        description: "Raw XML text received so far on this stream".to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_stream_header_action(),
        send_stream_features_action(),
        send_message_action(),
        send_presence_action(),
        send_iq_result_action(),
        send_iq_error_action(),
        send_auth_success_action(),
        send_auth_failure_action(),
        send_raw_xml_action(),
        wait_for_more_action(),
        close_stream_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("XMPP data received")
            .with_debug("XMPP XML: {xml_data}")
            .with_trace("XMPP: {json_pretty(.)}"),
    )
});

pub fn get_xmpp_event_types() -> Vec<EventType> {
    vec![XMPP_DATA_RECEIVED_EVENT.clone()]
}
