//! Clients for the six classic inetd services, sharing one engine.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::inetd::{
    actions::{action, parameter, Service},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Characters read from a chargen stream when the action names no count.
pub const DEFAULT_CHARGEN_READ: u64 = 1024;
/// Upper bound on a chargen read.
pub const MAX_CHARGEN_READ: u64 = 64 * 1024;

pub fn query_action_name(service: Service) -> &'static str {
    match service {
        Service::Echo => "echo_send",
        Service::Discard => "discard_send",
        Service::Daytime => "daytime_query",
        Service::Qotd => "qotd_query",
        Service::Chargen => "chargen_query",
        Service::Time => "time_query",
    }
}

fn query_action(service: Service) -> ActionDefinition {
    let name = query_action_name(service);
    match service {
        Service::Echo => action(
            name,
            "Send data to the echo service and read it back; the reply arrives as echo_response.",
            vec![
                parameter("data", "string", "Bytes to send, as text or hex per encoding", true),
                parameter("encoding", "string", "Encoding of data: utf8 (default) or hex", false),
            ],
            json!({"type":name,"data":"ping"}),
        ),
        Service::Discard => action(
            name,
            "Send data to the discard service, which answers nothing; discard_sent confirms it left.",
            vec![
                parameter("data", "string", "Bytes to send, as text or hex per encoding", true),
                parameter("encoding", "string", "Encoding of data: utf8 (default) or hex", false),
            ],
            json!({"type":name,"data":"into the void"}),
        ),
        Service::Chargen => action(
            name,
            "Read generated characters; the text arrives as chargen_response with a check against the RFC 864 pattern.",
            vec![parameter("bytes", "number", "Bytes to read over TCP before closing (default 1024, at most 65536)", false)],
            json!({"type":name}),
        ),
        Service::Daytime => action(name, "Ask for the date and time; the line arrives as daytime_response.", vec![], json!({"type":name})),
        Service::Qotd => action(name, "Ask for the quote of the day; it arrives as qotd_response.", vec![], json!({"type":name})),
        Service::Time => action(name, "Ask for the RFC 868 time; it arrives as time_response, decoded.", vec![], json!({"type":name})),
    }
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this client",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions(service: Service) -> Vec<ActionDefinition> {
    vec![query_action(service), disconnect_action()]
}

pub fn response_event_id(service: Service) -> &'static str {
    match service {
        Service::Echo => "echo_response",
        Service::Discard => "discard_sent",
        Service::Daytime => "daytime_response",
        Service::Qotd => "qotd_response",
        Service::Chargen => "chargen_response",
        Service::Time => "time_response",
    }
}

fn ready_event_id(service: Service) -> &'static str {
    match service {
        Service::Echo => "echo_ready",
        Service::Discard => "discard_ready",
        Service::Daytime => "daytime_ready",
        Service::Qotd => "qotd_ready",
        Service::Chargen => "chargen_ready",
        Service::Time => "time_ready",
    }
}

fn build_ready(service: Service) -> EventType {
    EventType::new(
        ready_event_id(service),
        "The client is ready; each query is one TCP connection or one UDP datagram.",
        query_action(service).example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "remote_addr",
            "string",
            "Address of the service being queried",
            true,
        ),
        parameter(
            "transport",
            "string",
            "tcp or udp, from the transport startup parameter",
            true,
        ),
    ])
    .with_actions(actions(service))
}

fn build_response(service: Service) -> EventType {
    let transport = parameter(
        "transport",
        "string",
        "tcp or udp: how the exchange was made",
        true,
    );
    let params = match service {
        Service::Echo => vec![
            transport,
            parameter(
                "data",
                "string",
                "What came back, as text or hex per encoding",
                true,
            ),
            parameter(
                "encoding",
                "string",
                "utf8 when the bytes are printable text, otherwise hex",
                true,
            ),
            parameter("bytes", "number", "Number of bytes received", true),
            parameter(
                "matches",
                "boolean",
                "True when the reply equals what was sent",
                true,
            ),
        ],
        Service::Discard => vec![
            transport,
            parameter("bytes", "number", "Bytes sent and discarded", true),
        ],
        Service::Daytime => vec![
            transport,
            parameter(
                "text",
                "string",
                "The date and time line, without its line ending",
                true,
            ),
        ],
        Service::Qotd => vec![
            transport,
            parameter(
                "quote",
                "string",
                "The quote, line endings normalised to newlines",
                true,
            ),
        ],
        Service::Chargen => vec![
            transport,
            parameter("text", "string", "The characters received", true),
            parameter("bytes", "number", "Number of bytes received", true),
            parameter(
                "conforms",
                "boolean",
                "True when the text follows RFC 864's rotating printable-ASCII pattern",
                true,
            ),
        ],
        Service::Time => vec![
            transport,
            parameter(
                "seconds_since_1900",
                "number",
                "The raw 32-bit RFC 868 value",
                true,
            ),
            parameter(
                "unix_seconds",
                "number",
                "The same instant as Unix seconds",
                true,
            ),
            parameter(
                "iso8601",
                "string",
                "The same instant as an RFC 3339 timestamp",
                true,
            ),
        ],
    };
    EventType::new(
        response_event_id(service),
        "The service's answer to one query.",
        query_action(service).example.clone(),
    )
    .with_parameters(params)
    .with_actions(actions(service))
}

macro_rules! events {
    ($ready:ident, $response:ident, $service:expr) => {
        pub static $ready: LazyLock<EventType> = LazyLock::new(|| build_ready($service));
        pub static $response: LazyLock<EventType> = LazyLock::new(|| build_response($service));
    };
}
events!(ECHO_READY, ECHO_RESPONSE, Service::Echo);
events!(DISCARD_READY, DISCARD_RESPONSE, Service::Discard);
events!(DAYTIME_READY, DAYTIME_RESPONSE, Service::Daytime);
events!(QOTD_READY, QOTD_RESPONSE, Service::Qotd);
events!(CHARGEN_READY, CHARGEN_RESPONSE, Service::Chargen);
events!(TIME_READY, TIME_RESPONSE, Service::Time);

pub fn ready_event(service: Service) -> &'static EventType {
    match service {
        Service::Echo => &ECHO_READY,
        Service::Discard => &DISCARD_READY,
        Service::Daytime => &DAYTIME_READY,
        Service::Qotd => &QOTD_READY,
        Service::Chargen => &CHARGEN_READY,
        Service::Time => &TIME_READY,
    }
}

pub fn response_event(service: Service) -> &'static EventType {
    match service {
        Service::Echo => &ECHO_RESPONSE,
        Service::Discard => &DISCARD_RESPONSE,
        Service::Daytime => &DAYTIME_RESPONSE,
        Service::Qotd => &QOTD_RESPONSE,
        Service::Chargen => &CHARGEN_RESPONSE,
        Service::Time => &TIME_RESPONSE,
    }
}

/// A validated query: bytes to send (Echo, Discard) and bytes to read (Chargen).
#[derive(Debug, Clone)]
pub struct Query {
    pub payload: Vec<u8>,
    pub read_bytes: u64,
}

pub fn parse_query(service: Service, v: &Value) -> Result<Query> {
    ensure!(
        v["type"].as_str() == Some(query_action_name(service)),
        "Unknown {} client action",
        service.name()
    );
    let payload = match service {
        Service::Echo | Service::Discard => {
            let data = v["data"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("data must be a string"))?;
            let bytes = wire::decode(data, v["encoding"].as_str())?;
            ensure!(
                bytes.len() <= wire::READ_CHUNK,
                "data exceeds {} bytes",
                wire::READ_CHUNK
            );
            ensure!(
                !bytes.is_empty() || service == Service::Discard,
                "echo data must not be empty"
            );
            bytes
        }
        _ => Vec::new(),
    };
    let read_bytes = match v.get("bytes").filter(|b| !b.is_null()) {
        None => DEFAULT_CHARGEN_READ,
        Some(b) => {
            let n = b
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("bytes must be a positive integer"))?;
            ensure!(
                (1..=MAX_CHARGEN_READ).contains(&n),
                "bytes must be 1 to {MAX_CHARGEN_READ}"
            );
            n
        }
    };
    Ok(Query {
        payload,
        read_bytes,
    })
}

pub fn startup_parameters() -> Vec<ParameterDefinition> {
    vec![ParameterDefinition {
        name: "transport".into(),
        type_hint: "string".into(),
        description: "tcp (one connection per query) or udp (one datagram per query)".into(),
        required: false,
        example: json!("udp"),
        default: Some(json!(super::DEFAULT_TRANSPORT)),
    }]
}

pub fn metadata(service: Service) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::*;
    ProtocolMetadataV2::builder()
        .state(DevelopmentState::Experimental)
        .privilege_requirement(PrivilegeRequirement::None)
        .well_known_port(match service {
            Service::Echo => 7,
            Service::Discard => 9,
            Service::Daytime => 13,
            Service::Qotd => 17,
            Service::Chargen => 19,
            Service::Time => 37,
        })
        .implementation("One query per TCP connection or UDP datagram, bounded and with deadlines")
        .llm_control("When to query the service and what to do with each answer")
        .e2e_testing("tests/client/inetd: xinetd's own built-in services (and an external QOTD program) as the independent server")
        .notes("Replies are bounded to 64 KiB on TCP and 8 KiB per datagram; connect, write and reply deadlines are 30 s on TCP, 5 s for a UDP reply. A UDP query that gets no reply raises no event and is logged.")
        .max_inbound_bytes(wire::MAX_STREAM_REPLY)
        .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
}

pub fn startup_examples(service: Service) -> crate::llm::actions::StartupExamples {
    let name = service.feature_name();
    let llm = json!({"type":"open_client","protocol":name,"remote_addr":format!("127.0.0.1:{}", 10000 + service.port()),"instruction":format!("Query the {} service once", service.name())});
    let query = query_action(service).example;
    let mut static_example = llm.clone();
    static_example["event_handlers"] = json!([
        {"event_pattern": ready_event_id(service), "handler": {"type":"static","actions":[query.clone()]}},
        {"event_pattern": response_event_id(service), "handler": {"type":"static","actions":[{"type":"disconnect"}]}}
    ]);
    let mut scripted = static_example.clone();
    scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":format!("import json\nprint(json.dumps({{'actions':[{query}]}}))")});
    crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
}

pub fn execute(service: Service, v: Value) -> Result<ClientActionResult> {
    match v["type"].as_str() {
        Some("disconnect") => Ok(ClientActionResult::Disconnect),
        Some(name) if name == query_action_name(service) => {
            parse_query(service, &v)?;
            Ok(ClientActionResult::Custom {
                name: name.to_string(),
                data: v,
            })
        }
        _ => bail!("Unknown {} client action", service.name()),
    }
}

macro_rules! inetd_client {
    ($ty:ident, $service:expr, $prompt:literal) => {
        #[derive(Default)]
        pub struct $ty;
        impl $ty {
            pub fn new() -> Self {
                Self
            }
        }
        impl Protocol for $ty {
            fn protocol_name(&self) -> &'static str {
                $service.name()
            }
            fn stack_name(&self) -> &'static str {
                $service.stack_name()
            }
            fn keywords(&self) -> Vec<&'static str> {
                $service.keywords()
            }
            fn description(&self) -> &'static str {
                match $service {
                    Service::Echo => "Echo client (RFC 862) over TCP or UDP",
                    Service::Discard => "Discard client (RFC 863) over TCP or UDP",
                    Service::Daytime => "Daytime client (RFC 867) over TCP or UDP",
                    Service::Qotd => "Quote of the Day client (RFC 865) over TCP or UDP",
                    Service::Chargen => "Character Generator client (RFC 864) over TCP or UDP",
                    Service::Time => "Time client (RFC 868) over TCP or UDP",
                }
            }
            fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
                actions($service)
            }
            fn get_sync_actions(&self) -> Vec<ActionDefinition> {
                vec![]
            }
            fn get_event_types(&self) -> Vec<EventType> {
                vec![
                    ready_event($service).clone(),
                    response_event($service).clone(),
                ]
            }
            fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
                startup_parameters()
            }
            fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
                metadata($service)
            }
            fn example_prompt(&self) -> &'static str {
                $prompt
            }
            fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
                startup_examples($service)
            }
            fn group_name(&self) -> &'static str {
                "Network Services"
            }
        }
        impl Client for $ty {
            fn connect(
                &self,
                ctx: ConnectContext,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>,
            > {
                Box::pin(super::connect(ctx, $service))
            }
            fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
                execute($service, v)
            }
        }
    };
}

inetd_client!(
    EchoClientProtocol,
    Service::Echo,
    "Send 'hello' to the echo service at 127.0.0.1:10007 and check it comes back"
);
inetd_client!(
    DiscardClientProtocol,
    Service::Discard,
    "Send a test line to the discard service at 127.0.0.1:10009"
);
inetd_client!(
    DaytimeClientProtocol,
    Service::Daytime,
    "Ask the daytime service at 127.0.0.1:10013 for the time"
);
inetd_client!(
    QotdClientProtocol,
    Service::Qotd,
    "Fetch the quote of the day from 127.0.0.1:10017"
);
inetd_client!(
    ChargenClientProtocol,
    Service::Chargen,
    "Read 2 KB from the chargen service at 127.0.0.1:10019"
);
inetd_client!(
    TimeClientProtocol,
    Service::Time,
    "Ask the RFC 868 time server at 127.0.0.1:10037 for the time"
);

pub fn protocol(service: Service) -> &'static dyn Client {
    match service {
        Service::Echo => &EchoClientProtocol,
        Service::Discard => &DiscardClientProtocol,
        Service::Daytime => &DaytimeClientProtocol,
        Service::Qotd => &QotdClientProtocol,
        Service::Chargen => &ChargenClientProtocol,
        Service::Time => &TimeClientProtocol,
    }
}
