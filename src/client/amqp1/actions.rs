use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::amqp1::actions::{action, check_message, message_parameter, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Amqp1ClientProtocol;
impl Amqp1ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn send() -> ActionDefinition {
    action(
        "amqp1_send",
        "Send a message to an address over a sending link (attached on first use) and report the outcome the server settles it with",
        vec![parameter("address", "string", "Target address (node name), e.g. orders", true), message_parameter()],
        json!({"type": "amqp1_send", "address": "orders", "message": {"body": {"order": 42}, "properties": {"message_id": "m-42"}}}),
    )
}
fn receive() -> ActionDefinition {
    action(
        "amqp1_receive",
        "Attach a receiving link to an address, grant credit for `count` messages, accept what arrives within the timeout, then detach and report the messages",
        vec![
            parameter("address", "string", "Source address to consume from", true),
            parameter("count", "number", "Messages to accept, 1 to 100 (default 1)", false),
            parameter("timeout_secs", "number", "How long to wait, 1 to 60 (default 5)", false),
        ],
        json!({"type": "amqp1_receive", "address": "orders.confirmed", "count": 1, "timeout_secs": 5}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection (close performative)",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![send(), receive(), disconnect()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp1_connected",
        "The connection and a session are open",
        send().example.clone(),
    )
    .with_parameters(vec![
        parameter("container_id", "string", "The server's container-id", true),
        parameter(
            "max_frame_size",
            "number",
            "The negotiated max-frame-size",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static OUTCOME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("amqp1_outcome", "How the server settled a sent message, or why the link was refused", receive().example.clone())
        .with_parameters(vec![
            parameter("address", "string", "The target address", true),
            parameter("outcome", "string", "accepted, rejected, released, modified, settled (pre-settled), or refused (the link was not attached)", true),
            parameter("condition", "string", "The error condition when rejected or refused", false),
            parameter("description", "string", "The error description when rejected or refused", false),
        ])
        .with_actions(actions())
});
pub static MESSAGES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp1_messages",
        "What an amqp1_receive got",
        disconnect().example.clone(),
    )
    .with_parameters(vec![
        parameter("address", "string", "The source address", true),
        parameter(
            "messages",
            "array",
            "Each message as {properties, application_properties, body, body_type}",
            true,
        ),
        parameter(
            "error",
            "string",
            "Why the link was refused or ended, when it was",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for Amqp1ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "AMQP1"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>AMQP1"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["amqp 1.0", "amqp1", "service bus", "artemis", "qpid"]
    }
    fn description(&self) -> &'static str {
        "AMQP 1.0 client: SASL, a connection and session, sending links with outcomes and receiving links with credit"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            OUTCOME_EVENT.clone(),
            MESSAGES_EVENT.clone(),
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
                "sasl",
                "string",
                "anonymous, plain (with username and password) or none (no SASL layer)",
                json!("plain"),
                Some(json!(super::DEFAULT_SASL)),
            ),
            p(
                "username",
                "string",
                "PLAIN authentication identity",
                json!("app"),
                None,
            ),
            p(
                "password",
                "string",
                "PLAIN password, sent in the SASL initial response (only with sasl plain)",
                json!("secret"),
                None,
            ),
            p(
                "hostname",
                "string",
                "hostname to put in open (virtual host); defaults to the remote host",
                json!("broker.example"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's AMQP 1.0 codec as a client: SASL ANONYMOUS/PLAIN, one session, sending links with dispositions, receiving links with link credit, multi-frame transfers, keep-alive frames")
            .llm_control("What to send to which address and what to consume")
            .e2e_testing("tests/client/amqp1: a rhea 3.0.5 container (JavaScript, independent) acting as a broker accepts, rejects and routes the client's messages and delivers one to its receiving link")
            .notes("One session; links are attached per address on demand; no transactions or link recovery.")
            .max_inbound_bytes(crate::server::amqp1::frame::MAX_FRAME as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the AMQP 1.0 broker at 127.0.0.1:5672 and send an order to the orders address"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"amqp1","remote_addr":"127.0.0.1:5672","instruction":"Send order 42 to orders","startup_params":{"sasl":"anonymous"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"amqp1_connected","handler":{"type":"static","actions":[send().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}] if e.get('outcome')=='accepted' else []}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for Amqp1ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 1024 * 1024, 100_000, 32),
            "action exceeds the AMQP bounds"
        );
        let address_ok = v["address"].as_str().is_some_and(|a| {
            !a.is_empty() && a.len() <= 256 && !crate::utils::sanitize::has_controls(&a)
        });
        match v["type"].as_str() {
            Some("amqp1_send") => {
                ensure!(address_ok, "address is a node name");
                check_message(&v["message"])?;
            }
            Some("amqp1_receive") => {
                ensure!(address_ok, "address is a node name");
                if let Some(c) = v.get("count").filter(|c| !c.is_null()) {
                    ensure!(
                        c.as_u64().is_some_and(|c| (1..=100).contains(&c)),
                        "count is 1 to 100"
                    );
                }
                if let Some(t) = v.get("timeout_secs").filter(|t| !t.is_null()) {
                    ensure!(
                        t.as_f64().is_some_and(|t| (1.0..=60.0).contains(&t)),
                        "timeout_secs is 1 to 60"
                    );
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown AMQP 1.0 client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
