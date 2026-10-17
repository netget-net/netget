use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::wire;

#[derive(Default)]
pub struct MilterProtocol;
impl MilterProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log)),
    }
}

fn simple(name: &str, description: &str) -> ActionDefinition {
    action(
        name,
        description,
        vec![],
        json!({"type": name}),
        &format!("-> milter {name}"),
    )
}

fn decisions() -> Vec<ActionDefinition> {
    vec![
        simple(
            "milter_continue",
            "Let the MTA go on to the next stage (the default when you say nothing).",
        ),
        simple(
            "milter_accept",
            "Accept the message now; this filter sees nothing more of it.",
        ),
        simple(
            "milter_reject",
            "Reject with the MTA's default permanent error (5xx).",
        ),
        simple(
            "milter_tempfail",
            "Refuse for now with a temporary error (4xx); the sender retries.",
        ),
        simple("milter_discard", "Accept the message but silently drop it."),
        action(
            "milter_reply",
            "Refuse with your own SMTP reply.",
            vec![
                parameter(
                    "code",
                    "number",
                    "SMTP code, 4xx (temporary) or 5xx (permanent)",
                    true,
                ),
                parameter(
                    "xcode",
                    "string",
                    "Enhanced status code, e.g. 5.7.1, matching the code's class",
                    false,
                ),
                parameter("text", "string", "The reply text, one line", true),
            ],
            json!({"type":"milter_reply","code":550,"xcode":"5.7.1","text":"Sender rejected by policy"}),
            "-> milter reply {code} {text}",
        ),
    ]
}

fn modifications() -> Vec<ActionDefinition> {
    vec![
        action("milter_add_header", "Add a header to the message (end of message only).",
            vec![parameter("name", "string", "Header field name, e.g. X-Spam-Status", true), parameter("value", "string", "Header field value, one line", true)],
            json!({"type":"milter_add_header","name":"X-NetGet","value":"checked"}), "-> milter add header {name}"),
        action("milter_change_header", "Change (or, with an empty value, delete) the index-th header of that name (end of message only).",
            vec![parameter("name", "string", "Header field name to change", true), parameter("index", "number", "Which occurrence, from 1", false), parameter("value", "string", "New value; empty deletes the header", true)],
            json!({"type":"milter_change_header","name":"Subject","index":1,"value":"[external] hello"}), "-> milter change header {name}"),
        action("milter_add_rcpt", "Add a recipient (end of message only).",
            vec![parameter("recipient", "string", "Address to add, e.g. <audit@example.com>", true)],
            json!({"type":"milter_add_rcpt","recipient":"<audit@example.com>"}), "-> milter add rcpt {recipient}"),
        action("milter_del_rcpt", "Remove a recipient (end of message only).",
            vec![parameter("recipient", "string", "Address to remove, exactly as given in RCPT", true)],
            json!({"type":"milter_del_rcpt","recipient":"<bob@example.net>"}), "-> milter del rcpt {recipient}"),
        action("milter_replace_body", "Replace the message body (end of message only).",
            vec![parameter("body", "string", "The new body, as text", true)],
            json!({"type":"milter_replace_body","body":"[removed]\r\n"}), "-> milter replace body"),
        action("milter_quarantine", "Hold the message in the MTA's quarantine (end of message only).",
            vec![parameter("reason", "string", "Why the message is held, one line, e.g. suspected phishing", true)],
            json!({"type":"milter_quarantine","reason":"suspicious attachment"}), "-> milter quarantine {reason}"),
    ]
}

fn stage_event(id: &str, description: &str, params: Vec<Parameter>, with_mods: bool) -> EventType {
    let mut acts = decisions();
    if with_mods {
        acts.extend(modifications());
    }
    let mut all = params;
    all.push(parameter(
        "connection",
        "object",
        "What the MTA said of the client: hostname, address, port, helo",
        true,
    ));
    all.push(parameter(
        "macros",
        "object",
        "Macros the MTA sent (e.g. {i}, {auth_authen})",
        true,
    ));
    EventType::new(id, description, json!({"type":"milter_continue"}))
        .with_parameters(all)
        .with_actions(acts)
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stage_event(
        "milter_connect",
        "An SMTP client connected to the MTA.",
        vec![
            parameter(
                "hostname",
                "string",
                "The client's hostname as the MTA resolved it",
                true,
            ),
            parameter("address", "string", "The client's IP address", true),
            parameter("port", "number", "The client's port", true),
        ],
        false,
    )
});
pub static HELO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stage_event(
        "milter_helo",
        "The client said HELO/EHLO.",
        vec![parameter(
            "helo",
            "string",
            "The name the client gave in HELO/EHLO",
            true,
        )],
        false,
    )
});
pub static MAIL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stage_event(
        "milter_mail",
        "The client named the sender (MAIL FROM).",
        vec![
            parameter(
                "sender",
                "string",
                "The envelope sender, e.g. <alice@example.com>",
                true,
            ),
            parameter(
                "esmtp_args",
                "array",
                "ESMTP parameters after the address",
                true,
            ),
        ],
        false,
    )
});
pub static RCPT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stage_event(
        "milter_rcpt",
        "The client named a recipient (RCPT TO).",
        vec![
            parameter(
                "recipient",
                "string",
                "The envelope recipient, e.g. <bob@example.net>",
                true,
            ),
            parameter(
                "esmtp_args",
                "array",
                "ESMTP parameters after the address",
                true,
            ),
        ],
        false,
    )
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stage_event(
        "milter_message",
        "The whole message has arrived: decide, and modify it if you want.",
        vec![
            parameter("sender", "string", "The envelope sender", true),
            parameter("recipients", "array", "The envelope recipients", true),
            parameter("headers", "array", "Each {name, value}, in order", true),
            parameter(
                "body",
                "string",
                "The body as text (truncated past 1 MiB)",
                true,
            ),
            parameter(
                "body_truncated",
                "boolean",
                "Whether the body was longer than shown",
                true,
            ),
        ],
        true,
    )
});

impl Protocol for MilterProtocol {
    fn protocol_name(&self) -> &'static str {
        "Milter"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Milter"
    }
    fn description(&self) -> &'static str {
        "Sendmail/Postfix mail filter (milter): the MTA asks at each SMTP stage and the handler accepts, rejects or modifies the message"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "milter",
            "mail filter",
            "libmilter",
            "postfix milter",
            "sendmail milter",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut a = decisions();
        a.extend(modifications());
        a
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            HELO_EVENT.clone(),
            MAIL_EVENT.clone(),
            RCPT_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds the MTA may stay silent between commands (1..=86400)".into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written milter protocol version 6 over Tokio TCP: option negotiation, macros, connect/helo/mail/rcpt decisions, headers and body collected in Rust, end-of-message decision with header, recipient, body and quarantine modifications")
            .llm_control("The decision at connect, HELO, MAIL, each RCPT and end of message, and any modification of the message")
            .e2e_testing("tests/server/milter: raw packets and bounds; OpenDKIM's miltertest and emersion/go-milter's client as independent MTA sides")
            .notes("Data, end of headers and unknown commands are continued in Rust; headers and body are collected (1 MiB body, 512 headers, 256 KiB packets). Saying nothing continues (accepts at end of message); a handler failure answers tempfail, so the sender retries rather than the mail being passed or lost. No SMFIR_SKIP, no progress keepalives.")
            .request_only("Every reply answers an MTA command")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Milter on port 8891 that rejects mail to spam@ and tags everything else with X-NetGet: checked"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"milter","port":8891,"instruction":"Reject recipients starting with spam@; add X-NetGet: checked to every accepted message"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"milter_rcpt","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'milter_reject'} if 'spam@' in e['recipient'] else {'type':'milter_continue'}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"milter_message","handler":{"type":"static","actions":[{"type":"milter_add_header","name":"X-NetGet","value":"checked"},{"type":"milter_accept"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

/// Encode one action as the reply packet it is.
pub fn reply_packet(v: &Value) -> Result<(u8, Vec<u8>)> {
    let field = |k: &str| -> Result<&str> {
        let s = v[k].as_str().with_context(|| format!("{k} required"))?;
        wire::check_field(s, k)?;
        Ok(s)
    };
    Ok(match v["type"].as_str().unwrap_or_default() {
        "milter_continue" => (wire::R_CONTINUE, vec![]),
        "milter_accept" => (wire::R_ACCEPT, vec![]),
        "milter_reject" => (wire::R_REJECT, vec![]),
        "milter_tempfail" => (wire::R_TEMPFAIL, vec![]),
        "milter_discard" => (wire::R_DISCARD, vec![]),
        "milter_reply" => (
            wire::R_REPLYCODE,
            wire::replycode(
                v["code"].as_u64().context("code required")?,
                v["xcode"].as_str(),
                field("text")?,
            )?,
        ),
        "milter_add_header" => {
            let name = field("name")?;
            ensure!(
                !name.is_empty() && !name.contains(':'),
                "header name must be non-empty without ':'"
            );
            (wire::R_ADDHEADER, wire::cstrings(&[name, field("value")?]))
        }
        "milter_change_header" => {
            let name = field("name")?;
            let index = v["index"].as_u64().unwrap_or(1);
            ensure!(
                (1..=u64::from(u32::MAX)).contains(&index),
                "index counts from 1"
            );
            let mut d = (index as u32).to_be_bytes().to_vec();
            d.extend(wire::cstrings(&[name, field("value")?]));
            (wire::R_CHGHEADER, d)
        }
        "milter_add_rcpt" => (wire::R_ADDRCPT, wire::cstrings(&[field("recipient")?])),
        "milter_del_rcpt" => (wire::R_DELRCPT, wire::cstrings(&[field("recipient")?])),
        "milter_replace_body" => {
            let body = v["body"].as_str().context("body required")?;
            ensure!(
                body.len() < wire::MAX_PACKET - 16,
                "body too long for one packet"
            );
            (wire::R_REPLBODY, body.as_bytes().to_vec())
        }
        "milter_quarantine" => (wire::R_QUARANTINE, wire::cstrings(&[field("reason")?])),
        t => bail!("Unknown milter action {t}"),
    })
}

impl Server for MilterProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        reply_packet(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
