use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Amqp1Protocol;
impl Amqp1Protocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> AMQP1 {name}"))),
    }
}

pub fn message_parameter() -> Parameter {
    parameter(
        "message",
        "object",
        "{\"body\": any JSON, \"body_type\": \"value\" (default) or \"data\" (body is text sent as bytes), \"properties\": {message_id, to, subject, reply_to, correlation_id, content_type, ...}, \"application_properties\": {key: simple value}}",
        true,
    )
}

fn accept() -> ActionDefinition {
    action("amqp1_accept", "Allow it: admit the connection or link, or settle the message with the accepted outcome (then Rust relays it to every receiver of its address)", vec![], json!({"type": "amqp1_accept"}))
}
fn reject() -> ActionDefinition {
    action(
        "amqp1_reject",
        "Refuse it: SASL authentication failure or a closed connection, a link detached with this error, or the rejected outcome for a message",
        vec![
            parameter("condition", "string", "AMQP error condition, e.g. amqp:unauthorized-access, amqp:not-found, amqp:precondition-failed, amqp:not-allowed", true),
            parameter("description", "string", "Human-readable description, up to 256 characters", true),
        ],
        json!({"type": "amqp1_reject", "condition": "amqp:unauthorized-access", "description": "this address is closed"}),
    )
}
fn release() -> ActionDefinition {
    action(
        "amqp1_release",
        "Settle the message with the released outcome: not processed, the sender may try again",
        vec![],
        json!({"type": "amqp1_release"}),
    )
}
pub fn send() -> ActionDefinition {
    action(
        "amqp1_send",
        "Deliver a message to the receivers of an address (each with credit gets it; one without credit holds up to 1000). With no address it goes to the link that asked for messages.",
        vec![parameter("address", "string", "The address (node name) whose receivers get it, e.g. orders", false), message_parameter()],
        json!({"type": "amqp1_send", "address": "orders.confirmed", "message": {"body": {"order": 42, "status": "confirmed"}, "properties": {"subject": "confirmation"}}}),
    )
}
fn ignore() -> ActionDefinition {
    action("amqp1_ignore", "Send nothing now; the receiver keeps its credit and gets whatever is published to its address later", vec![], json!({"type": "amqp1_ignore"}))
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp1_connect",
        "A client authenticates (SASL) or opens a connection without SASL",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "mechanism",
            "string",
            "PLAIN, ANONYMOUS or none (no SASL layer)",
            true,
        ),
        parameter(
            "user",
            "string",
            "PLAIN authentication identity, when given",
            false,
        ),
        parameter("password", "string", "PLAIN password, when given", false),
        parameter(
            "container_id",
            "string",
            "The client's container-id (only when there is no SASL layer)",
            false,
        ),
        parameter(
            "hostname",
            "string",
            "The hostname the client opened (only when there is no SASL layer)",
            false,
        ),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static ATTACH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp1_attach",
        "A client attaches a link to an address: to publish to it or to consume from it",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "direction",
            "string",
            "publish (the client sends) or consume (the client receives)",
            true,
        ),
        parameter(
            "address",
            "string",
            "The target address (publish) or source address (consume)",
            true,
        ),
        parameter("link_name", "string", "The link's name", true),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("amqp1_message", "A complete message on a publishing link. Settle it with one outcome; amqp1_send may answer with other messages.", accept().example.clone())
        .with_parameters(vec![
            parameter("address", "string", "The link's target address", true),
            parameter("message", "object", "{properties, application_properties, body, body_type: value|data|sequence}; data bodies are text when UTF-8, else {binary_length}", true),
            parameter("settled", "boolean", "true when the client sent it pre-settled (the outcome is then not sent back)", true),
        ])
        .with_actions(vec![accept(), reject(), release(), send()])
});
pub static CREDIT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("amqp1_credit", "A consuming link was given credit and nothing is waiting for it: produce messages for it now, or wait for publishers", ignore().example.clone())
        .with_parameters(vec![
            parameter("address", "string", "The link's source address", true),
            parameter("credit", "number", "How many messages it may receive", true),
        ])
        .with_actions(vec![send(), ignore()])
});

pub fn check_message(m: &Value) -> Result<()> {
    super::message::encode(m).map(|_| ())
}

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 1024 * 1024, 100_000, 32),
        "answer exceeds the AMQP bounds"
    );
    match v["type"].as_str() {
        Some("amqp1_accept" | "amqp1_release" | "amqp1_ignore") => {}
        Some("amqp1_reject") => {
            ensure!(
                v["condition"].as_str().is_some_and(|c| !c.is_empty()
                    && c.len() <= 128
                    && c.bytes().all(|b| b.is_ascii_graphic())),
                "condition is a symbol such as amqp:not-found"
            );
            ensure!(
                v["description"]
                    .as_str()
                    .is_some_and(|d| d.len() <= 256 && !crate::utils::sanitize::has_controls(&d)),
                "description is up to 256 printable characters"
            );
        }
        Some("amqp1_send") => {
            if let Some(a) = v.get("address").filter(|a| !a.is_null()) {
                ensure!(
                    a.as_str().is_some_and(|a| !a.is_empty()
                        && a.len() <= 256
                        && !crate::utils::sanitize::has_controls(&a)),
                    "address is a node name"
                );
            }
            check_message(&v["message"])?;
        }
        _ => bail!("Unknown AMQP 1.0 server action"),
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

impl Protocol for Amqp1Protocol {
    fn protocol_name(&self) -> &'static str {
        "AMQP1"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>AMQP1"
    }
    fn description(&self) -> &'static str {
        "AMQP 1.0 container: SASL, connections, sessions, links with credit, transfers, settlement and outcomes; publishers' accepted messages are relayed to receivers of the same address"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "amqp 1.0",
            "amqp1",
            "oasis amqp",
            "service bus",
            "artemis",
            "qpid",
            "message broker",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject(), release(), send(), ignore()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            ATTACH_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            CREDIT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "container_id",
                "string",
                "This server's container-id in open",
                json!("broker-1"),
                Some(json!(super::DEFAULT_CONTAINER)),
            ),
            startup(
                "require_sasl",
                "boolean",
                "Refuse clients that skip the SASL layer",
                json!(true),
                Some(json!(false)),
            ),
            startup(
                "idle_timeout_secs",
                "integer",
                "idle-time-out announced in open; a client silent for this long is closed",
                json!(30),
                Some(json!(super::IDLE_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(5672)
            .implementation("Hand-written AMQP 1.0: the type system, frames, SASL ANONYMOUS/PLAIN, open/begin/attach/flow/transfer/disposition/detach/end/close, link credit and delivery counts, multi-frame transfers, settlement with accepted/rejected/released outcomes, keep-alive frames; an in-memory relay from accepted messages to receivers of the same address")
            .llm_control("Which clients and links are admitted, the outcome of every message, and messages produced for receivers")
            .e2e_testing("tests/server/amqp1: rhea 3.0.5 (JavaScript) and go-amqp 1.5 (Go), independent, publish and consume through the server, see accepted and rejected outcomes and are refused unauthorized links and credentials")
            .notes("Addresses are topics: a message reaches the receivers attached when it is accepted (a receiver without credit holds 1000). No durable storage, transactions, link recovery, filters or AMQP over WebSocket. Separate from the AMQP 0-9-1 `amqp` feature.")
            .answers_on_failure()
            .max_inbound_bytes(super::frame::MAX_FRAME as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "AMQP 1.0 broker on port 5672 that accepts orders on the orders address and rejects anything without an order id"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"amqp1","port":5672,"instruction":"Admit everyone; accept messages on orders that carry an order id, reject the rest"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"amqp1_credit","handler":{"type":"static","actions":[{"type":"amqp1_ignore"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"amqp1_accept"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"amqp1_message","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nb=e['message'].get('body')\nok=isinstance(b,dict) and 'order' in b\nprint(json.dumps({'actions':[{'type':'amqp1_accept'} if ok else {'type':'amqp1_reject','condition':'amqp:precondition-failed','description':'no order id'}]}))"}});
        scripted["event_handlers"].as_array_mut().map(|a| a.push(json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"amqp1_accept"}]}})));
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for Amqp1Protocol {
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
