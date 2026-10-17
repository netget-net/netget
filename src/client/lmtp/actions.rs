use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::lmtp::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct LmtpClientProtocol;
impl LmtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub const DEFAULT_LHLO_DOMAIN: &str = "netget.local";
/// Largest body the client will compose.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

fn send_action() -> ActionDefinition {
    action(
        "lmtp_send",
        "Deliver one message: MAIL FROM, one RCPT TO per recipient, DATA. LMTP then reports \
         a delivery result for every accepted recipient, raised as lmtp_result.",
        vec![
            parameter(
                "from",
                "string",
                "Sender address for MAIL FROM and the From header (may be empty for a bounce)",
                true,
            ),
            parameter("to", "array", "Recipient addresses (1 to 100)", true),
            parameter(
                "subject",
                "string",
                "Subject line of the message, sent as its Subject header field",
                false,
            ),
            parameter(
                "body",
                "string",
                "Plain-text body; newlines are sent as CRLF",
                true,
            ),
            parameter(
                "headers",
                "object",
                "Extra header fields {name: value}",
                false,
            ),
        ],
        json!({"type":"lmtp_send","from":"sender@example.test","to":["alice@example.test"],"subject":"Hello","body":"Hello Alice"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Send QUIT and close the LMTP connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![send_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lmtp_connected",
        "Connected and LHLO accepted; send a message or disconnect",
        send_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "LMTP server address", true),
        parameter("greeting", "string", "Text of the 220 greeting", true),
        parameter(
            "capabilities",
            "array",
            "Extensions from the LHLO reply, such as PIPELINING or SIZE 10485760",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lmtp_result",
        "Outcome of one lmtp_send: the MAIL reply, each recipient's RCPT reply and, for \
         accepted recipients, its own delivery reply after DATA",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("from", "string", "Sender of the transaction", true),
        parameter("mail", "object", "{code, text} reply to MAIL FROM", true),
        parameter(
            "recipients",
            "array",
            "[{recipient, rcpt: {code,text}, delivery: {code,text} or null, delivered: bool}]",
            true,
        ),
        parameter(
            "data",
            "object",
            "{code, text} reply to DATA, or null when DATA was not sent",
            false,
        ),
        parameter(
            "delivered",
            "array",
            "Recipients whose delivery reply was 2xx",
            true,
        ),
    ])
    .with_actions(actions())
});

/// A validated outgoing message.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub from: String,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

fn header_value_ok(value: &str) -> bool {
    value.len() <= 900 && !value.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
}

impl Outgoing {
    pub fn from_action(v: &Value) -> Result<Self> {
        let from = v["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("from must be a string"))?
            .to_string();
        ensure!(
            wire::valid_mailbox(&from, true),
            "from is not a valid mailbox"
        );
        let to = v["to"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("to must be an array of addresses"))?
            .iter()
            .map(|a| {
                a.as_str()
                    .filter(|a| wire::valid_mailbox(a, false))
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("every recipient must be a non-empty mailbox"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            (1..=wire::MAX_RECIPIENTS).contains(&to.len()),
            "to must name 1 to {} recipients",
            wire::MAX_RECIPIENTS
        );
        let subject = match v.get("subject") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if header_value_ok(s) => Some(s.clone()),
            _ => bail!("subject must be a single-line string"),
        };
        let body = v["body"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("body must be a string"))?
            .to_string();
        ensure!(
            body.len() <= MAX_BODY_BYTES,
            "body exceeds {MAX_BODY_BYTES} bytes"
        );
        let mut headers = Vec::new();
        if let Some(extra) = v.get("headers").filter(|h| !h.is_null()) {
            let extra = extra
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("headers must be an object"))?;
            ensure!(extra.len() <= 50, "at most 50 extra headers");
            for (name, value) in extra {
                let value = value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("header {name} must be a string"))?;
                ensure!(
                    !name.is_empty()
                        && name.len() <= 76
                        && name.bytes().all(|b| b.is_ascii_graphic() && b != b':'),
                    "invalid header name {name}"
                );
                ensure!(
                    header_value_ok(value),
                    "header {name} must be a single line"
                );
                headers.push((name.clone(), value.to_string()));
            }
        }
        Ok(Self {
            from,
            to,
            subject,
            body,
            headers,
        })
    }

    pub fn to_json(&self) -> Value {
        let headers: Map<String, Value> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        json!({"type":"lmtp_send","from":self.from,"to":self.to,"subject":self.subject,"body":self.body,"headers":headers})
    }

    /// The RFC 5322 message: generated Date and Message-ID unless supplied.
    pub fn compose(&self, domain: &str) -> String {
        let has = |name: &str| {
            self.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        let mut out = String::new();
        if !has("Date") {
            out.push_str(&format!("Date: {}\n", chrono::Utc::now().to_rfc2822()));
        }
        if !has("Message-ID") {
            out.push_str(&format!(
                "Message-ID: <{}@{}>\n",
                uuid::Uuid::new_v4(),
                domain
            ));
        }
        if !has("From") {
            out.push_str(&format!("From: <{}>\n", self.from));
        }
        if !has("To") {
            let to: Vec<String> = self.to.iter().map(|a| format!("<{a}>")).collect();
            out.push_str(&format!("To: {}\n", to.join(", ")));
        }
        if let Some(subject) = &self.subject {
            if !has("Subject") {
                out.push_str(&format!("Subject: {subject}\n"));
            }
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("{name}: {value}\n"));
        }
        out.push('\n');
        out.push_str(&self.body);
        out
    }
}

impl Protocol for LmtpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "LMTP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>LMTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["lmtp", "rfc2033", "lhlo", "mail delivery"]
    }
    fn description(&self) -> &'static str {
        "LMTP client that delivers messages and reports per-recipient results"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "lhlo_domain".into(),
            type_hint: "string".into(),
            description: "Domain the client names in LHLO and in generated Message-IDs".into(),
            required: false,
            example: json!("client.example.test"),
            default: Some(json!(DEFAULT_LHLO_DOMAIN)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(24)
            .implementation("Tokio TCP: greeting and LHLO on connect, then MAIL/RCPT/DATA per message with one delivery reply read per accepted recipient")
            .llm_control("Which messages to send to which recipients, and what to do with each per-recipient result")
            .e2e_testing("tests/client/lmtp: scripted wire fixture, injected sends, malformed replies; aiosmtpd's LMTP server as the independent peer")
            .notes("Plain TCP only (no STARTTLS or AUTH). Replies are bounded to 1000-byte lines and 64 lines; every connect, write and reply has a 30 s deadline; bodies up to 1 MiB.")
            .max_inbound_bytes(wire::MAX_LINE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to LMTP at 127.0.0.1:2424 and deliver a test message to alice@example.test"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"lmtp","remote_addr":"127.0.0.1:2424","instruction":"Deliver a greeting to alice@example.test"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"lmtp_connected","handler":{"type":"static","actions":[{"type":"lmtp_send","from":"sender@example.test","to":["alice@example.test"],"subject":"Hello","body":"Hello Alice"}]}},
            {"event_pattern":"lmtp_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'lmtp_send','from':'sender@example.test','to':['alice@example.test'],'body':'Hello'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for LmtpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("lmtp_send") => Ok(ClientActionResult::Custom {
                name: "lmtp_send".into(),
                data: Outgoing::from_action(&v)?.to_json(),
            }),
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown LMTP client action"),
        }
    }
}
