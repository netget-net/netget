use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::milter::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct MilterClientProtocol;
impl MilterClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action("milter_connect", "Tell the filter an SMTP client connected.",
            vec![parameter("hostname", "string", "The SMTP client's hostname", true), parameter("address", "string", "The SMTP client's IPv4 or IPv6 address", true), parameter("port", "number", "The SMTP client's port", false)],
            json!({"type":"milter_connect","hostname":"client.example","address":"192.0.2.10","port":40000}), "-> milter connect {hostname}"),
        action("milter_helo", "Pass the client's HELO/EHLO name.",
            vec![parameter("name", "string", "The HELO/EHLO argument the client gave", true)],
            json!({"type":"milter_helo","name":"client.example"}), "-> milter helo {name}"),
        action("milter_mail", "Pass the envelope sender (MAIL FROM).",
            vec![parameter("sender", "string", "Envelope sender, e.g. <alice@example.com>", true), parameter("esmtp_args", "array", "ESMTP parameters, e.g. [\"SIZE=1000\"]", false)],
            json!({"type":"milter_mail","sender":"<alice@example.com>"}), "-> milter mail {sender}"),
        action("milter_rcpt", "Pass one envelope recipient (RCPT TO).",
            vec![parameter("recipient", "string", "Envelope recipient, e.g. <bob@example.net>", true), parameter("esmtp_args", "array", "ESMTP parameters after the address", false)],
            json!({"type":"milter_rcpt","recipient":"<bob@example.net>"}), "-> milter rcpt {recipient}"),
        action("milter_message", "Pass the message: DATA, its headers, end of headers, its body and end of message; the filter's verdict and modifications come back.",
            vec![parameter("headers", "array", "Each {name, value}, in order", true), parameter("body", "string", "The body as text, lines ending in CRLF", true)],
            json!({"type":"milter_message","headers":[{"name":"Subject","value":"hello"}],"body":"Hi Bob\r\n"}), "-> milter message"),
        action("milter_abort", "Abandon the current message; the filter forgets it.", vec![], json!({"type":"milter_abort"}), "-> milter abort"),
        action("disconnect", "Say QUIT and close the connection to the filter.", vec![], json!({"type":"disconnect"}), "-> milter quit"),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("milter_negotiated", "Connected to the filter and negotiated options; pass it a connection.", json!({"type":"milter_connect","hostname":"client.example","address":"192.0.2.10"}))
        .with_parameters(vec![
            parameter("version", "number", "The milter protocol version agreed", true),
            parameter("actions", "array", "What the filter may do: add_header, change_body, add_rcpt, del_rcpt, change_header, quarantine", true),
            parameter("protocol", "array", "Stages the filter asked to be left out (no_connect, no_helo, no_mail, no_rcpt, no_data, no_headers, no_eoh, no_body) or not answered (no_reply_*), and skip if it may cut the body short", true),
        ])
        .with_actions(actions())
});

pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("milter_reply", "The filter answered a stage.", json!({"type":"milter_rcpt","recipient":"<bob@example.net>"}))
        .with_parameters(vec![
            parameter("stage", "string", "connect, helo, mail, rcpt or message", true),
            parameter("decision", "string", "continue, accept, reject, tempfail, discard or replycode", true),
            parameter("implicit", "boolean", "True when the filter gave no answer because it asked for this stage to be left out or not answered; the decision is then continue", true),
            parameter("text", "string", "The SMTP reply for replycode, e.g. 550 5.7.1 rejected", false),
            parameter("modifications", "array", "At end of message: each {kind, name?, value?, index?, recipient?, body?, reason?}", true),
        ])
        .with_actions(actions())
});

impl Protocol for MilterClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Milter"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Milter"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["milter", "mail filter", "libmilter"]
    }
    fn description(&self) -> &'static str {
        "Milter client (the MTA side): passes a mail transaction to a filter and reports its verdicts and modifications"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), REPLY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's milter codec, MTA side: option negotiation offering every action and every protocol step it can honour (stages left out, stages not answered, SMFIR_SKIP during the body), then connect, helo, mail, rcpt and the message (data, headers, end of headers, body in 64 KiB chunks, end of message), reading each verdict and the modifications before it")
            .llm_control("The mail transaction to pass to the filter, and what to do with each verdict")
            .e2e_testing("tests/client/milter: NetGet's own filter; a pymilter (libmilter) filter and emersion/go-milter's server as independent filters")
            .notes("Macros are not sent. A stage the filter asked to be left out or not answered is reported as an implicit continue. A stage the filter answers with anything but continue ends the message; the handler decides what follows. A handler chain stops after 8 follow-ups.")
            .max_inbound_bytes(wire::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Pass a test message from alice@example.com to bob@example.net through the milter at 127.0.0.1:8891"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"milter","remote_addr":"127.0.0.1:8891","instruction":"Run one message from alice to bob through the filter"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"milter_negotiated","handler":{"type":"static","actions":[{"type":"milter_connect","hostname":"client.example","address":"192.0.2.10"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"milter_reply","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'milter_helo','name':'client.example'}] if e['stage']=='connect' and e['decision']=='continue' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

/// Check an action's fields.
pub fn check(v: &Value) -> Result<()> {
    let field = |k: &str| -> Result<()> {
        wire::check_field(v[k].as_str().with_context(|| format!("{k} required"))?, k)
    };
    match v["type"].as_str().unwrap_or_default() {
        "milter_connect" => {
            field("hostname")?;
            let a = v["address"].as_str().context("address required")?;
            a.parse::<std::net::IpAddr>()
                .context("address must be an IP address")?;
            ensure!(
                v["port"].as_u64().unwrap_or(0) <= 65535,
                "port out of range"
            );
        }
        "milter_helo" => field("name")?,
        "milter_mail" => field("sender")?,
        "milter_rcpt" => field("recipient")?,
        "milter_message" => {
            for h in v["headers"]
                .as_array()
                .context("headers must be an array")?
            {
                wire::check_field(
                    h["name"].as_str().context("header name required")?,
                    "header name",
                )?;
                wire::check_field(
                    h["value"].as_str().context("header value required")?,
                    "header value",
                )?;
            }
            ensure!(
                v["body"].as_str().context("body required")?.len() <= wire::MAX_BODY,
                "body larger than 1 MiB"
            );
        }
        "milter_abort" => {}
        t => bail!("Unknown milter client action {t}"),
    }
    Ok(())
}

impl Client for MilterClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
