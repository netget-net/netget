use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::fix::actions::{action, check_answer, logout, parameter, send};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct FixClientProtocol;
impl FixClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Log out and close the connection without waiting for the counterparty's Logout",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![send(), logout(), disconnect()]
}

pub static LOGGED_ON_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fix_logged_on",
        "The acceptor answered the Logon; the session is up",
        send().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "sender_comp_id",
            "string",
            "This initiator's SenderCompID",
            true,
        ),
        parameter("target_comp_id", "string", "The acceptor's CompID", true),
        parameter("heartbeat_secs", "number", "The agreed HeartBtInt", true),
    ])
    .with_actions(actions())
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fix_message",
        "An in-sequence application message from the acceptor",
        json!({"type": "fix_logout"}),
    )
    .with_parameters(vec![
        parameter("msg_type", "string", "MsgType code, e.g. 8", true),
        parameter(
            "msg_type_name",
            "string",
            "MsgType name, e.g. ExecutionReport",
            true,
        ),
        parameter(
            "seq",
            "number",
            "The message's MsgSeqNum (34) in this session, which a BusinessMessageReject refers to",
            true,
        ),
        parameter(
            "fields",
            "array",
            "Body fields in wire order: [{tag, name, value}]",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static LOGGED_OUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fix_logged_out",
        "The session ended",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![parameter(
        "reason",
        "string",
        "Why: the counterparty's Logout text, a sequence problem or a heartbeat timeout",
        true,
    )])
    .with_actions(vec![disconnect()])
});

impl Protocol for FixClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "FIX"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FIX"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "fix",
            "fix protocol",
            "initiator",
            "order entry",
            "new order single",
        ]
    }
    fn description(&self) -> &'static str {
        "FIX 4.x initiator: logs on, keeps the session (sequence numbers, resend and gap fill, heartbeats) and sends application messages"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            LOGGED_ON_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            LOGGED_OUT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "sender_comp_id",
                "string",
                "This initiator's SenderCompID",
                json!("BUYSIDE"),
                Some(json!(crate::server::fix::DEFAULT_COMP_ID)),
            ),
            p(
                "target_comp_id",
                "string",
                "The acceptor's CompID",
                json!("EXCHANGE"),
                Some(json!(super::DEFAULT_TARGET)),
            ),
            p(
                "begin_string",
                "string",
                "FIX.4.0 to FIX.4.4",
                json!("FIX.4.2"),
                Some(json!(crate::server::fix::DEFAULT_BEGIN_STRING)),
            ),
            p(
                "heartbeat_secs",
                "integer",
                "HeartBtInt to propose (0 to 3600)",
                json!(10),
                Some(json!(super::DEFAULT_HEARTBEAT.as_secs())),
            ),
            p(
                "reset_seq_num",
                "boolean",
                "Ask the acceptor to reset sequence numbers (141=Y)",
                json!(true),
                Some(json!(true)),
            ),
            p(
                "username",
                "string",
                "Username (553) for the Logon",
                json!("trader"),
                None,
            ),
            p(
                "password",
                "string",
                "Password (554) for the Logon",
                json!("secret"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The FIX codec and session layer the acceptor uses, as initiator")
            .llm_control("Which application messages to send and how to react to the acceptor's")
            .e2e_testing("tests/client/fix: QuickFIX/Go 0.9.12 (independent, validating against FIX44.xml) as acceptor answers a NewOrderSingle with an ExecutionReport and an OrderCancelRequest with a BusinessMessageReject; logout")
            .notes("One session per client, in memory. No FIXT.1.1/FIX 5.0 and no reconnect.")
            .max_inbound_bytes(crate::server::fix::codec::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Log on to the FIX acceptor at 127.0.0.1:9876 as BUYSIDE and buy 100 AAPL at 150"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"fix","remote_addr":"127.0.0.1:9876","instruction":"Buy 100 AAPL at 150","startup_params":{"sender_comp_id":"BUYSIDE","target_comp_id":"EXCHANGE"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"fix_logged_on","handler":{"type":"static","actions":[{"type":"fix_send","msg_type":"NewOrderSingle","fields":[{"name":"ClOrdID","value":"1"},{"name":"HandlInst","value":"1"},{"name":"Symbol","value":"AAPL"},{"name":"Side","value":"1"},{"name":"TransactTime","value":"20261001-12:00:00.000"},{"name":"OrderQty","value":"100"},{"name":"OrdType","value":"2"},{"name":"Price","value":"150"}]}]}},
            {"event_pattern":"fix_message","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'fix_logout','text':'done'}] if e['msg_type']=='8' else []}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for FixClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("fix_send" | "fix_logout") => check_answer(&v)?,
            _ => bail!("Unknown FIX client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
