use super::dict;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct FixProtocol;
impl FixProtocol {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> FIX {name}"))),
    }
}

/// BusinessRejectReason (380) values a handler may give.
pub const BUSINESS_REJECT: &[(&str, u32)] = &[
    ("other", 0),
    ("unknown_id", 1),
    ("unknown_security", 2),
    ("unsupported_message_type", 3),
    ("application_not_available", 4),
    ("conditionally_required_field_missing", 5),
    ("not_authorized", 6),
    ("deliver_to_firm_not_available", 7),
];

pub fn send() -> ActionDefinition {
    action(
        "fix_send",
        "Send one application message. Rust writes the header (BeginString, CompIDs, MsgSeqNum, SendingTime), BodyLength and CheckSum; give only body fields, in order (repeating groups as repeated entries after their count field).",
        vec![
            parameter("msg_type", "string", "MsgType by name or code, e.g. ExecutionReport or 8; session messages (Logon, Heartbeat, TestRequest, ResendRequest, Reject, SequenceReset, Logout) are Rust's", true),
            parameter("fields", "array", "Body fields in order: [{\"name\": \"OrderID\", \"value\": \"O-1\"}] or [{\"tag\": 37, \"value\": \"O-1\"}]; FIX 4.4 names are accepted", true),
        ],
        json!({"type": "fix_send", "msg_type": "ExecutionReport", "fields": [
            {"name": "OrderID", "value": "O-1"}, {"name": "ClOrdID", "value": "1"}, {"name": "ExecID", "value": "E-1"},
            {"name": "ExecType", "value": "0"}, {"name": "OrdStatus", "value": "0"}, {"name": "Symbol", "value": "AAPL"},
            {"name": "Side", "value": "1"}, {"name": "LeavesQty", "value": "100"}, {"name": "CumQty", "value": "0"}, {"name": "AvgPx", "value": "0"}
        ]}),
    )
}
fn reject() -> ActionDefinition {
    action(
        "fix_reject",
        "Refuse the application message with a BusinessMessageReject (MsgType j) naming its MsgSeqNum and MsgType",
        vec![
            parameter("reason", "string", "other, unknown_id, unknown_security, unsupported_message_type, application_not_available, conditionally_required_field_missing, not_authorized or deliver_to_firm_not_available", true),
            parameter("text", "string", "Text (58), up to 256 characters", true),
        ],
        json!({"type": "fix_reject", "reason": "unknown_security", "text": "symbol not traded here"}),
    )
}
fn ignore() -> ActionDefinition {
    action(
        "fix_ignore",
        "Accept the message and send nothing back (it is still counted in the session's sequence)",
        vec![],
        json!({"type": "fix_ignore"}),
    )
}
pub fn logout() -> ActionDefinition {
    action(
        "fix_logout",
        "End the session with a Logout; the connection closes when the peer answers or after a few seconds",
        vec![parameter("text", "string", "Text (58) explaining why, up to 256 characters", false)],
        json!({"type": "fix_logout", "text": "end of day"}),
    )
}
fn accept_logon() -> ActionDefinition {
    action(
        "fix_accept_logon",
        "Admit the session; Rust answers the Logon with the agreed HeartBtInt",
        vec![],
        json!({"type": "fix_accept_logon"}),
    )
}
fn reject_logon() -> ActionDefinition {
    action(
        "fix_reject_logon",
        "Refuse the session: Rust sends a Logout with this text and closes",
        vec![parameter(
            "text",
            "string",
            "Text (58), up to 256 characters",
            true,
        )],
        json!({"type": "fix_reject_logon", "text": "unknown counterparty"}),
    )
}

pub static LOGON_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("fix_logon", "A counterparty logs on. BeginString, CompIDs, BodyLength, CheckSum and sequence were checked by Rust.", accept_logon().example.clone())
        .with_parameters(vec![
            parameter("sender_comp_id", "string", "The counterparty's SenderCompID", true),
            parameter("target_comp_id", "string", "The TargetCompID it addressed (this acceptor's)", true),
            parameter("heartbeat_secs", "number", "HeartBtInt it asked for", true),
            parameter("reset_seq_num", "boolean", "Whether it asked to reset sequence numbers (141=Y)", true),
            parameter("username", "string", "Username (553), when given", false),
            parameter("password", "string", "Password (554), when given", false),
        ])
        .with_actions(vec![accept_logon(), reject_logon()])
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fix_message",
        "An in-sequence application message from the counterparty",
        send().example.clone(),
    )
    .with_parameters(vec![
        parameter("msg_type", "string", "MsgType code, e.g. D", true),
        parameter(
            "msg_type_name",
            "string",
            "MsgType name, e.g. NewOrderSingle",
            true,
        ),
        parameter(
            "seq",
            "number",
            "The message's MsgSeqNum (34) in this session, which a BusinessMessageReject refers to",
            true,
        ),
        parameter(
            "sender_comp_id",
            "string",
            "The counterparty's SenderCompID",
            true,
        ),
        parameter(
            "fields",
            "array",
            "Body fields in wire order: [{tag, name, value}]",
            true,
        ),
    ])
    .with_actions(vec![send(), reject(), ignore(), logout()])
});

/// Body fields from an action, as (tag, value).
pub fn body_fields(v: &Value) -> Result<Vec<(u32, String)>> {
    let list = v["fields"]
        .as_array()
        .filter(|l| l.len() <= 500)
        .context("fields is an array of at most 500 {name|tag, value}")?;
    list.iter()
        .map(|f| {
            let tag = match (
                f.get("tag").and_then(Value::as_u64),
                f.get("name").and_then(Value::as_str),
            ) {
                (Some(t), _) => u32::try_from(t)
                    .ok()
                    .filter(|t| (1..=999_999).contains(t))
                    .context("tag is 1 to 999999")?,
                (None, Some(n)) => dict::field_tag(n).with_context(|| {
                    format!("{n:?} is not a FIX 4.4 field name; give its tag number")
                })?,
                _ => bail!("each field has a tag or a name"),
            };
            ensure!(
                !super::session::SESSION_TAGS.contains(&tag),
                "tag {tag} belongs to the session header or trailer"
            );
            let value = match &f["value"] {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => bail!("tag {tag}: value is a string or number"),
            };
            ensure!(
                !value.is_empty()
                    && value.len() <= 4096
                    && !crate::utils::sanitize::has_controls(&value),
                "tag {tag}: value is 1 to 4096 printable characters"
            );
            Ok((tag, value))
        })
        .collect()
}

/// An application MsgType from a name or code.
pub fn app_msg_type(v: &Value) -> Result<String> {
    let raw = v["msg_type"].as_str().context("msg_type is required")?;
    let code = dict::message_type(raw)
        .map(str::to_owned)
        .or_else(|| {
            (raw.len() <= 3 && raw.bytes().all(|b| b.is_ascii_alphanumeric()))
                .then(|| raw.to_owned())
        })
        .with_context(|| format!("{raw:?} is not a FIX MsgType"))?;
    ensure!(
        !dict::MESSAGES
            .iter()
            .any(|(t, _, admin)| *t == code && *admin),
        "{raw} is a session message, which Rust sends itself"
    );
    Ok(code)
}

fn text_ok(v: &Value, key: &str, required: bool) -> Result<()> {
    match v.get(key).filter(|t| !t.is_null()) {
        None => ensure!(!required, "{key} is required"),
        Some(t) => ensure!(
            t.as_str().is_some_and(|t| !t.is_empty()
                && t.len() <= 256
                && !crate::utils::sanitize::has_controls(&t)),
            "{key} is 1 to 256 printable characters"
        ),
    }
    Ok(())
}

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 1024 * 1024, 20_000, 8),
        "answer exceeds the FIX bounds"
    );
    match v["type"].as_str() {
        Some("fix_accept_logon" | "fix_ignore") => {}
        Some("fix_reject_logon") => text_ok(v, "text", true)?,
        Some("fix_logout") => text_ok(v, "text", false)?,
        Some("fix_reject") => {
            let r = v["reason"].as_str().unwrap_or_default();
            ensure!(
                BUSINESS_REJECT.iter().any(|(n, _)| *n == r),
                "unknown reason {r:?}"
            );
            text_ok(v, "text", true)?;
        }
        Some("fix_send") => {
            app_msg_type(v)?;
            body_fields(v)?;
        }
        _ => bail!("Unknown FIX server action"),
    }
    Ok(())
}

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for FixProtocol {
    fn protocol_name(&self) -> &'static str {
        "FIX"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FIX"
    }
    fn description(&self) -> &'static str {
        "FIX 4.x acceptor: session layer (logon, sequence numbers, resend and gap fill, heartbeats, logout) with application messages answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "fix",
            "fix protocol",
            "financial information exchange",
            "acceptor",
            "order entry",
            "execution report",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send(), logout()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_logon(),
            reject_logon(),
            send(),
            reject(),
            ignore(),
            logout(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOGON_EVENT.clone(), MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "sender_comp_id",
                "string",
                "This acceptor's SenderCompID; counterparties must address it as TargetCompID",
                json!("EXCHANGE"),
                Some(json!(super::DEFAULT_COMP_ID)),
            ),
            startup(
                "begin_string",
                "string",
                "FIX.4.0, FIX.4.1, FIX.4.2, FIX.4.3 or FIX.4.4",
                json!("FIX.4.2"),
                Some(json!(super::DEFAULT_BEGIN_STRING)),
            ),
            startup(
                "logon_timeout_secs",
                "integer",
                "Seconds a new connection has to send its Logon",
                json!(5),
                Some(json!(super::LOGON_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written FIX tag=value codec (BodyLength, CheckSum, data fields, repeated tags) and session layer shared with the client; FIX 4.4 names from the FIX44.xml dictionary QuickFIX ships")
            .llm_control("Which counterparties may log on and how each application message is answered")
            .e2e_testing("tests/server/fix: QuickFIX/Go 0.9.12 (independent, validating against FIX44.xml) logs on, sends NewOrderSingles answered with an ExecutionReport and a BusinessMessageReject, exchanges heartbeats and logs out, and is refused with a wrong SenderCompID")
            .notes("One session per connection, in memory; sequence numbers restart with each connection. No FIXT.1.1/FIX 5.0, no message persistence across restarts, no encryption (EncryptMethod 0 only). Application messages are not validated against the dictionary.")
            .answers_on_failure()
            .max_inbound_bytes(super::codec::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "FIX 4.4 acceptor on port 9876 that fills every limit order at its price"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"fix","port":9876,"instruction":"Acknowledge every NewOrderSingle with an ExecutionReport (OrdStatus New)","startup_params":{"sender_comp_id":"EXCHANGE"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"fix_logon","handler":{"type":"static","actions":[{"type":"fix_accept_logon"}]}},
            {"event_pattern":"fix_message","handler":{"type":"static","actions":[{"type":"fix_reject","reason":"application_not_available","text":"orders closed"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nf={x['tag']:x['value'] for x in e['fields']}\nprint(json.dumps({'actions':[{'type':'fix_send','msg_type':'ExecutionReport','fields':[{'tag':37,'value':'O-'+f.get(11,'')},{'tag':11,'value':f.get(11,'')},{'tag':17,'value':'E-'+f.get(11,'')},{'tag':150,'value':'0'},{'tag':39,'value':'0'},{'tag':55,'value':f.get(55,'')},{'tag':54,'value':f.get(54,'1')},{'tag':151,'value':f.get(38,'0')},{'tag':14,'value':'0'},{'tag':6,'value':'0'}]}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for FixProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
