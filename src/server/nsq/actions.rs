//! NSQ actions: what the model is told, and how its answers become frames.
//!
//! The model is the broker's judgement: it accepts or refuses publishes and subscriptions, and
//! it decides which messages a subscriber receives. It never writes a frame. Every action here
//! returns a structured answer (`ActionResult::Custom "nsq_answer"`) that the session loop
//! renders through [`super::wire`] — the loop, not the model, assigns message ids and
//! timestamps and holds deliveries to the client's RDY count.

use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct NsqProtocol;

impl NsqProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NsqProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// The name of every structured answer this protocol's executor returns.
pub const ANSWER: &str = "nsq_answer";

/// One answer, read back from what [`NsqProtocol::execute_action`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Ok,
    Error { code: String, message: String },
    Deliver(Vec<Delivery>),
    Close,
}

/// A message the model wants delivered: its body and the attempts count the frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub body: String,
    pub attempts: u16,
}

impl Answer {
    /// Read an executor result back. `None` for anything that is not an NSQ answer.
    pub fn from_result(result: &ActionResult) -> Option<Answer> {
        match result {
            ActionResult::CloseConnection => Some(Answer::Close),
            ActionResult::Custom { name, data } if name == ANSWER => {
                match data.get("kind")?.as_str()? {
                    "ok" => Some(Answer::Ok),
                    "error" => Some(Answer::Error {
                        code: data.get("code")?.as_str()?.to_string(),
                        message: data
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    }),
                    "deliver" => Some(Answer::Deliver(
                        data.get("messages")?
                            .as_array()?
                            .iter()
                            .filter_map(|m| {
                                Some(Delivery {
                                    body: m.get("body")?.as_str()?.to_string(),
                                    attempts: m
                                        .get("attempts")
                                        .and_then(Value::as_u64)
                                        .and_then(|a| u16::try_from(a).ok())
                                        .unwrap_or(1),
                                })
                            })
                            .collect(),
                    )),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl Protocol for NsqProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a new connection may send nothing (not even the '  V2' \
                              magic) before the server closes it. Default 300, the window a \
                              `manual` rule gives a human - the peer may be NetGet's own TCP \
                              client parked for its operator."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(json!(super::FIRST_BYTE_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "heartbeat_interval_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds between the _heartbeat_ frames sent to a client that did \
                              not ask for its own interval in IDENTIFY. A client silent for two \
                              intervals is closed, as nsqd does. Default 30 (nsqd's)."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::HEARTBEAT_INTERVAL.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds of silence after which a client that disabled heartbeats \
                              (heartbeat_interval -1 in IDENTIFY) is closed. Default 300. A \
                              client waiting for the model's answer is not idle."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ok_action(),
            error_action(),
            deliver_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "NSQ"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NSQ_PUBLISH_EVENT.clone(),
            NSQ_SUBSCRIBE_EVENT.clone(),
            NSQ_READY_EVENT.clone(),
            NSQ_FINISH_EVENT.clone(),
            NSQ_REQUEUE_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NSQ"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nsq", "nsqd", "message queue", "nsq_tail", "to_nsq"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta on evidence: tests/server/nsq/real_client_test.rs drives the NSQ project's
            // own to_nsq and nsq_tail (go-nsq) and hard-fails when they are absent. Not Stable:
            // both are one implementation (go-nsq), there is no pcap oracle (Wireshark has no
            // NSQ dissector), and in-flight timeouts are not implemented.
            .state(DevelopmentState::Beta)
            .well_known_port(4150)
            // 4150 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written nsqd TCP protocol (V2) over tokio: the '  V2' magic, \
                 newline-terminated commands with size-prefixed bodies, and size/type framed \
                 responses, errors and messages, all rendered by NetGet; message ids and \
                 timestamps generated by NetGet",
            )
            .llm_control(
                "Whether each PUB/MPUB/DPUB and SUB is accepted (OK) or refused (an nsqd error \
                 code), and which messages a subscriber receives when it signals RDY, finishes \
                 or requeues one",
            )
            .e2e_testing(
                "tests/server/nsq/real_client_test.rs drives the NSQ project's own to_nsq \
                 (publishes stdin lines) and nsq_tail (subscribes and prints what it receives) - \
                 go-nsq, Go; Homebrew `nsq`, the release tarball on Ubuntu - asserting that \
                 to_nsq's lines reach the handler as nsq_publish and that nsq_tail prints exactly \
                 the bodies delivered. It fails, never skips, when the binaries are absent. \
                 tests/server/nsq/e2e_test.rs covers the mocked-model path on a raw socket.",
            )
            .notes(
                "Implements the V2 magic; IDENTIFY (plain OK, or the feature-negotiation JSON \
                 with TLS, deflate, snappy and auth off); SUB; RDY; FIN; REQ; TOUCH; PUB, MPUB \
                 and DPUB; NOP; CLS (CLOSE_WAIT); heartbeats (_heartbeat_ on the negotiated \
                 interval, and a client silent for two intervals is closed). AUTH answers \
                 E_AUTH_DISABLED. NetGet is not a queue: nothing published is stored or routed \
                 to other connections - the model decides what each subscriber receives. \
                 In-flight messages never time out and are not redelivered unless the model \
                 redelivers a requeued one. Bodies are capped at nsqd's defaults (1 MiB per \
                 message, 5 MiB per MPUB/IDENTIFY body), judged from the declared size before \
                 allocation. On backend failure a PUB gets E_PUB_FAILED and a SUB E_INVALID, \
                 both with a fixed text.",
            )
            .max_inbound_bytes(wire::MAX_BODY_SIZE)
            // PUB/MPUB/DPUB get E_*PUB_FAILED and SUB gets E_INVALID; RDY, FIN and REQ take no
            // reply in nsqd, so a failure there delivers nothing, which is the honest answer.
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "NSQ message broker (nsqd TCP protocol) - the model decides what is accepted and delivered"
    }
    fn example_prompt(&self) -> &'static str {
        "NSQ broker on port 4150 - accept every publish, and give subscribers of topic 'orders' \
         the message 'order 1 shipped'"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 4150,
                "base_stack": "nsq",
                "instruction": "NSQ broker. Accept every publish and every subscription. The \
                                topic 'orders' holds two messages: 'order 1 shipped' and \
                                'order 2 packed'. Deliver them once each to a subscriber."
            }),
            json!({
                "type": "open_server",
                "port": 4150,
                "base_stack": "nsq",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\ni = json.load(sys.stdin)\nt = i['event_type_id']\ne = i['event']\nif t in ('nsq_publish', 'nsq_subscribe'):\n    a = [{'type': 'send_nsq_ok'}]\nelif t == 'nsq_ready':\n    a = [{'type': 'deliver_nsq_messages', 'messages': [{'body': 'hello from ' + e.get('topic', '')}]}]\nelse:\n    a = []\nprint(json.dumps({'actions': a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 4150,
                "base_stack": "nsq",
                "event_handlers": [
                    {
                        "event_pattern": "nsq_publish",
                        "handler": {"type": "static", "actions": [{"type": "send_nsq_ok"}]}
                    },
                    {
                        "event_pattern": "nsq_subscribe",
                        "handler": {"type": "static", "actions": [{"type": "send_nsq_ok"}]}
                    },
                    {
                        "event_pattern": "nsq_ready",
                        "handler": {"type": "static", "actions": [
                            {"type": "deliver_nsq_messages", "messages": [{"body": "hello"}]}
                        ]}
                    }
                ]
            }),
        )
    }
}

impl Server for NsqProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let config = super::NsqConfig {
                first_byte_timeout: secs("first_byte_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::FIRST_BYTE_TIMEOUT),
                heartbeat_interval: secs("heartbeat_interval_secs")?
                    .map(|s| std::time::Duration::from_secs(s.max(1)))
                    .unwrap_or(super::HEARTBEAT_INTERVAL),
                idle_timeout: secs("idle_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::IDLE_TIMEOUT),
            };

            crate::server::nsq::NsqServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                config,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        let data = match action_type {
            "send_nsq_ok" => json!({"kind": "ok"}),
            "send_nsq_error" => {
                let code = action
                    .get("code")
                    .and_then(Value::as_str)
                    .context("send_nsq_error needs 'code'")?
                    .trim()
                    .to_ascii_uppercase();
                if !wire::ERROR_CODES.contains(&code.as_str()) {
                    return Err(anyhow!(
                        "send_nsq_error: unknown code {code:?}; use one of {}",
                        wire::ERROR_CODES.join(", ")
                    ));
                }
                let message = action.get("message").and_then(Value::as_str).unwrap_or("");
                let message = crate::utils::truncate_for_log(
                    &crate::utils::sanitize::line_field(message),
                    256,
                );
                json!({"kind": "error", "code": code, "message": message})
            }
            "deliver_nsq_messages" => {
                let messages = action
                    .get("messages")
                    .and_then(Value::as_array)
                    .context("deliver_nsq_messages needs 'messages', a list of {body}")?;
                let mut out = Vec::with_capacity(messages.len());
                for (i, m) in messages.iter().enumerate() {
                    let body = match m {
                        Value::String(s) => s.clone(),
                        Value::Object(o) => match o.get("body") {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Null) | None => {
                                return Err(anyhow!("message {i} has no 'body'"))
                            }
                            Some(other) => other.to_string(),
                        },
                        other => other.to_string(),
                    };
                    if body.len() > wire::MAX_MSG_SIZE {
                        return Err(anyhow!(
                            "message {i} is {} bytes, over the {} byte limit",
                            body.len(),
                            wire::MAX_MSG_SIZE
                        ));
                    }
                    let attempts = match m.get("attempts") {
                        None | Some(Value::Null) => 1,
                        Some(v) => v
                            .as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                            .filter(|a| (1..=u16::MAX as u64).contains(a))
                            .with_context(|| {
                                format!("message {i}: 'attempts' must be 1 to 65535")
                            })?,
                    };
                    out.push(json!({"body": body, "attempts": attempts}));
                }
                json!({"kind": "deliver", "messages": out})
            }
            "close_connection" => return Ok(ActionResult::CloseConnection),
            _ => return Err(anyhow!("Unknown NSQ action: {}", action_type)),
        };
        Ok(ActionResult::Custom {
            name: ANSWER.to_string(),
            data,
        })
    }
}

fn ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nsq_ok".to_string(),
        description: "Accept a publish (PUB, MPUB, DPUB) or a subscription (SUB): the client \
                      receives OK."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "send_nsq_ok"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NSQ OK")
                .with_debug("NSQ send_nsq_ok"),
        ),
    }
}

fn error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nsq_error".to_string(),
        description: "Refuse the request with one of nsqd's error codes. E_PUB_FAILED, \
                      E_MPUB_FAILED or E_DPUB_FAILED refuse a publish; E_BAD_TOPIC, \
                      E_BAD_CHANNEL, E_UNAUTHORIZED or E_TOO_MANY_CHANNEL_CONSUMERS refuse a \
                      subscription. Every code except E_FIN_FAILED, E_REQ_FAILED and \
                      E_TOUCH_FAILED closes the connection, as nsqd does."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "The nsqd error code".to_string(),
                required: true,
            }
            .with_choices(wire::ERROR_CODES.iter().copied()),
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "One line saying why, after the code".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_nsq_error", "code": "E_PUB_FAILED", "message": "<why>"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NSQ {code}")
                .with_debug("NSQ send_nsq_error: code={code}"),
        ),
    }
}

fn deliver_action() -> ActionDefinition {
    ActionDefinition {
        name: "deliver_nsq_messages".to_string(),
        description: "Deliver messages to this subscriber. NetGet gives each one its message id \
                      and timestamp, and sends no more than the client's RDY count allows; the \
                      rest wait in order until the client finishes one. Only a subscribed \
                      connection can receive messages."
            .to_string(),
        parameters: vec![Parameter {
            name: "messages".to_string(),
            type_hint: "array".to_string(),
            description: "List of {body, attempts}: body is the message text, attempts \
                          (optional, default 1) how many times it has been delivered"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "deliver_nsq_messages",
            "messages": [{"body": "<message body>"}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NSQ deliver messages")
                .with_debug("NSQ deliver_nsq_messages"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the NSQ connection after any reply".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("NSQ connection closed")
                .with_debug("NSQ close_connection"),
        ),
    }
}

fn param(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: true,
    }
}

fn answer_with_param() -> Parameter {
    param(
        "answer_with",
        "string",
        "Which answer this request takes, and where its content comes from",
    )
}

/// The `answer_with` field of `nsq_publish`.
pub fn publish_answer_with(command: &str, topic: &str, count: usize) -> String {
    let refusal = match command {
        "MPUB" => "E_MPUB_FAILED",
        "DPUB" => "E_DPUB_FAILED",
        _ => "E_PUB_FAILED",
    };
    format!(
        "exactly one action: send_nsq_ok to accept the {count} message(s) published to topic \
         '{topic}', or send_nsq_error with code {refusal} only if your instructions say this \
         topic refuses publishes"
    )
}

/// The `answer_with` field of `nsq_subscribe`.
pub fn subscribe_answer_with(topic: &str, channel: &str) -> String {
    format!(
        "exactly one action: send_nsq_ok to accept the subscription to topic '{topic}' on \
         channel '{channel}', or send_nsq_error (E_BAD_TOPIC, E_BAD_CHANNEL or E_UNAUTHORIZED) \
         only if your instructions say it is refused. No messages yet: the client has not sent \
         RDY"
    )
}

/// The `answer_with` field of `nsq_ready`, `nsq_finish` and `nsq_requeue` for a delivery.
pub fn deliver_answer_with(topic: &str, can_deliver: u64, pending: usize) -> String {
    let queued = if pending > 0 {
        format!(" {pending} message(s) you gave earlier are already queued and will follow;")
    } else {
        String::new()
    };
    format!(
        "deliver_nsq_messages with at most {can_deliver} message(s) your instructions say are \
         waiting on topic '{topic}' that you have not delivered before, each body word for \
         word as your instructions give it;{queued} no action at all when none are waiting"
    )
}

/// The `answer_with` field of `nsq_requeue`.
pub fn requeue_answer_with(attempts: u16) -> String {
    format!(
        "deliver_nsq_messages with this message's body again and attempts {} if your \
         instructions say a requeued message is retried; no action at all to drop it",
        attempts.saturating_add(1)
    )
}

fn deliver_actions() -> Vec<ActionDefinition> {
    vec![deliver_action(), error_action(), close_connection_action()]
}

/// `PUB`, `MPUB` and `DPUB`.
pub static NSQ_PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nsq_publish",
        "A client published messages to a topic. Accept them with send_nsq_ok or refuse them \
         with send_nsq_error; exactly one of the two. answer_with says which fits.",
        json!({"type": "send_nsq_ok"}),
    )
    .with_parameters(vec![
        param("command", "string", "PUB, MPUB or DPUB").with_choices(["PUB", "MPUB", "DPUB"]),
        param("topic", "string", "The topic published to"),
        param(
            "messages",
            "array",
            "The message bodies as text (invalid UTF-8 replaced), the first 20, each cut at \
             1000 characters",
        ),
        param(
            "message_count",
            "number",
            "How many messages were published",
        ),
        param("total_bytes", "number", "The bodies' total size in bytes"),
        answer_with_param(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NSQ {command} {topic} ({message_count} message(s))")
            .with_debug("NSQ nsq_publish: topic={topic} bytes={total_bytes}"),
    )
    .with_actions(vec![
        ok_action(),
        error_action(),
        deliver_action(),
        close_connection_action(),
    ])
    .with_alternative_example(
        json!({"type": "send_nsq_error", "code": "E_PUB_FAILED", "message": "<why>"}),
    )
});

/// `SUB`.
pub static NSQ_SUBSCRIBE_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
            "nsq_subscribe",
            "A client subscribed to a topic's channel. Accept with send_nsq_ok or refuse with \
         send_nsq_error; exactly one of the two. Messages cannot be delivered yet.",
            json!({"type": "send_nsq_ok"}),
        )
        .with_parameters(vec![
        param("topic", "string", "The topic the client subscribes to"),
        param(
            "channel",
            "string",
            "The channel on that topic; each channel receives its own copy of the topic's messages",
        ),
        param("ephemeral", "boolean", "Whether the channel name ends in #ephemeral"),
        param("client_id", "string", "The client_id from IDENTIFY (may be empty)"),
        param("user_agent", "string", "The user_agent from IDENTIFY (may be empty)"),
        answer_with_param(),
    ])
        .with_log_template(
            LogTemplate::new()
                .with_info("NSQ SUB {topic} {channel}")
                .with_debug("NSQ nsq_subscribe: topic={topic} channel={channel}"),
        )
        .with_actions(vec![ok_action(), error_action(), close_connection_action()])
        .with_alternative_example(
            json!({"type": "send_nsq_error", "code": "E_UNAUTHORIZED", "message": "<why>"}),
        )
    });

fn flow_parameters() -> Vec<Parameter> {
    vec![
        param("topic", "string", "The subscribed topic"),
        param("channel", "string", "The subscribed channel"),
        param(
            "ready",
            "number",
            "The client's RDY count: how many messages it takes at once",
        ),
        param(
            "in_flight",
            "number",
            "Messages delivered and not yet finished or requeued",
        ),
        param(
            "pending",
            "number",
            "Messages you already gave that wait for RDY capacity; NetGet sends them first",
        ),
        param(
            "can_deliver",
            "number",
            "How many more messages the client can receive right now",
        ),
    ]
}

/// `RDY` with room for at least one message.
pub static NSQ_READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = vec![param(
        "count",
        "number",
        "The RDY count the client just sent",
    )];
    parameters.extend(flow_parameters());
    parameters.push(answer_with_param());
    EventType::new(
        "nsq_ready",
        "A subscriber is ready for messages (RDY). Deliver the messages your instructions say \
         are waiting with deliver_nsq_messages, or answer with no action when there are none.",
        json!({"type": "deliver_nsq_messages", "messages": [{"body": "<message body>"}]}),
    )
    .with_parameters(parameters)
    .with_log_template(
        LogTemplate::new()
            .with_info("NSQ RDY {count} on {topic}/{channel}")
            .with_debug("NSQ nsq_ready: in_flight={in_flight} can_deliver={can_deliver}"),
    )
    .with_actions(deliver_actions())
});

/// `FIN` of a message in flight.
pub static NSQ_FINISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = vec![param(
        "message_id",
        "string",
        "The id of the message the client finished",
    )];
    parameters.extend(flow_parameters());
    parameters.push(answer_with_param());
    EventType::new(
        "nsq_finish",
        "A subscriber finished (acknowledged) a message. Deliver more with \
         deliver_nsq_messages only if your instructions say more are waiting; otherwise \
         answer with no action.",
        json!({"type": "deliver_nsq_messages", "messages": [{"body": "<message body>"}]}),
    )
    .with_parameters(parameters)
    .with_log_template(
        LogTemplate::new()
            .with_info("NSQ FIN {message_id}")
            .with_debug("NSQ nsq_finish: in_flight={in_flight} pending={pending}"),
    )
    .with_actions(deliver_actions())
});

/// `REQ` of a message in flight.
pub static NSQ_REQUEUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = vec![
        param(
            "message_id",
            "string",
            "The id of the message the client requeued",
        ),
        param(
            "timeout_ms",
            "number",
            "How long the client asked the message to wait before redelivery",
        ),
        param(
            "attempts",
            "number",
            "How many times the message has been delivered",
        ),
        param("body", "string", "The requeued message's body"),
    ];
    parameters.extend(flow_parameters());
    parameters.push(answer_with_param());
    EventType::new(
        "nsq_requeue",
        "A subscriber requeued a message (it could not process it now). Redeliver it with \
         deliver_nsq_messages and attempts one higher if your instructions say to retry; \
         otherwise answer with no action.",
        json!({"type": "deliver_nsq_messages", "messages": [{"body": "<message body>", "attempts": 2}]}),
    )
    .with_parameters(parameters)
    .with_log_template(
        LogTemplate::new()
            .with_info("NSQ REQ {message_id} ({timeout_ms} ms)")
            .with_debug("NSQ nsq_requeue: attempts={attempts}"),
    )
    .with_actions(deliver_actions())
});
