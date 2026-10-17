//! The six classic inetd services as protocols sharing one engine. Each protocol type is a
//! thin wrapper over [`Service`], which carries its metadata, event and action.
use super::wire;
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
        log_template: Some(LogTemplate::new().with_info(format!("-> {name}"))),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Echo,
    Discard,
    Daytime,
    Qotd,
    Chargen,
    Time,
}

fn transport_parameter() -> Parameter {
    parameter(
        "transport",
        "string",
        "tcp or udp: how the request arrived",
        true,
    )
}

fn echo_action() -> ActionDefinition {
    action(
        "echo_reply",
        "Send the echo. Omit data to echo the received bytes exactly, as RFC 862 defines; supply data to send something else.",
        vec![
            parameter("data", "string", "Bytes to send instead of the received ones", false),
            parameter("encoding", "string", "Encoding of data: utf8 (default) or hex", false),
        ],
        json!({"type":"echo_reply"}),
    )
}
fn discard_action() -> ActionDefinition {
    action(
        "discard_reply",
        "Accept the connection and silently discard what it sends. To turn it away, use discard_refuse.",
        vec![parameter("max_bytes", "number", "Close after discarding this many bytes; omit for no limit", false)],
        json!({"type":"discard_reply"}),
    )
}
fn daytime_action() -> ActionDefinition {
    action(
        "daytime_reply",
        "Answer a daytime request with one line of human-readable date and time. Omit text to send the server clock.",
        vec![parameter("text", "string", "The date and time line to send (at most 256 characters)", false)],
        json!({"type":"daytime_reply"}),
    )
}
fn qotd_action() -> ActionDefinition {
    action(
        "qotd_reply",
        "Answer a quote-of-the-day request with a short message of at most 512 characters.",
        vec![parameter(
            "quote",
            "string",
            "The quote to send; newlines are kept",
            true,
        )],
        json!({"type":"qotd_reply","quote":"Simplicity is prerequisite for reliability. - Dijkstra"}),
    )
}
fn chargen_action() -> ActionDefinition {
    action(
        "chargen_reply",
        "Start generating characters: the rotating RFC 864 pattern over the given character set, until the client closes or max_bytes is reached.",
        vec![
            parameter("charset", "string", "Printable ASCII characters to rotate through; default all 95", false),
            parameter("line_length", "number", "Characters per line before CRLF, 1 to 512; default 72", false),
            parameter("max_bytes", "number", "Stop and close after this many bytes; omit to stream until the client closes", false),
        ],
        json!({"type":"chargen_reply"}),
    )
}
fn time_action() -> ActionDefinition {
    action(
        "time_reply",
        "Answer a time request. Rust sends it as RFC 868's 32-bit seconds since 1900. Omit both fields to send the server clock.",
        vec![
            parameter("unix_seconds", "number", "The time to report, as seconds since 1970", false),
            parameter("iso8601", "string", "The time to report, as an RFC 3339 timestamp", false),
        ],
        json!({"type":"time_reply"}),
    )
}

fn refuse_action(service: Service) -> ActionDefinition {
    let name = service.refuse_name();
    action(
        name,
        "Deliberately send nothing: close the TCP connection, or leave the UDP datagram unanswered. Logged as a refusal, unlike silence.",
        vec![parameter("reason", "string", "Why the request is refused, for the log only", false)],
        json!({"type": name}),
    )
}

pub static ECHO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "echo_request",
        "Data arrived for the echo service: one TCP read or one UDP datagram.",
        echo_action().example.clone(),
    )
    .with_parameters(vec![
        transport_parameter(),
        parameter(
            "data",
            "string",
            "The received bytes, as text or hex per encoding",
            true,
        ),
        parameter(
            "encoding",
            "string",
            "utf8 when the bytes are printable text, otherwise hex",
            true,
        ),
        parameter("bytes", "number", "Number of bytes received", true),
    ])
    .with_actions(vec![echo_action(), refuse_action(Service::Echo)])
});
pub static DISCARD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "discard_request",
        "A client connected to the discard service.",
        discard_action().example.clone(),
    )
    .with_parameters(vec![
        transport_parameter(),
        parameter(
            "remote_addr",
            "string",
            "Address of the connecting client",
            true,
        ),
    ])
    .with_actions(vec![discard_action(), refuse_action(Service::Discard)])
});
pub static DAYTIME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "daytime_request",
        "A client asked for the date and time (a TCP connection or a UDP datagram).",
        daytime_action().example.clone(),
    )
    .with_parameters(vec![transport_parameter()])
    .with_actions(vec![daytime_action(), refuse_action(Service::Daytime)])
});
pub static QOTD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "qotd_request",
        "A client asked for the quote of the day (a TCP connection or a UDP datagram).",
        qotd_action().example.clone(),
    )
    .with_parameters(vec![transport_parameter()])
    .with_actions(vec![qotd_action(), refuse_action(Service::Qotd)])
});
pub static CHARGEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "chargen_request",
        "A client asked for generated characters (a TCP connection or a UDP datagram).",
        chargen_action().example.clone(),
    )
    .with_parameters(vec![transport_parameter()])
    .with_actions(vec![chargen_action(), refuse_action(Service::Chargen)])
});
pub static TIME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "time_request",
        "A client asked for the machine-readable time (a TCP connection or a UDP datagram).",
        time_action().example.clone(),
    )
    .with_parameters(vec![transport_parameter()])
    .with_actions(vec![time_action(), refuse_action(Service::Time)])
});

impl Service {
    pub const ALL: [Service; 6] = [
        Service::Echo,
        Service::Discard,
        Service::Daytime,
        Service::Qotd,
        Service::Chargen,
        Service::Time,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Service::Echo => "Echo",
            Service::Discard => "Discard",
            Service::Daytime => "Daytime",
            Service::Qotd => "QOTD",
            Service::Chargen => "Chargen",
            Service::Time => "Time",
        }
    }
    pub fn feature_name(self) -> &'static str {
        match self {
            Service::Echo => "echo",
            Service::Discard => "discard",
            Service::Daytime => "daytime",
            Service::Qotd => "qotd",
            Service::Chargen => "chargen",
            Service::Time => "time",
        }
    }
    pub fn port(self) -> u16 {
        match self {
            Service::Echo => 7,
            Service::Discard => 9,
            Service::Daytime => 13,
            Service::Qotd => 17,
            Service::Chargen => 19,
            Service::Time => 37,
        }
    }
    pub fn stack_name(self) -> &'static str {
        match self {
            Service::Echo => "ETH>IP>TCP>ECHO",
            Service::Discard => "ETH>IP>TCP>DISCARD",
            Service::Daytime => "ETH>IP>TCP>DAYTIME",
            Service::Qotd => "ETH>IP>TCP>QOTD",
            Service::Chargen => "ETH>IP>TCP>CHARGEN",
            Service::Time => "ETH>IP>TCP>TIME",
        }
    }
    pub fn rfc(self) -> &'static str {
        match self {
            Service::Echo => "RFC 862",
            Service::Discard => "RFC 863",
            Service::Daytime => "RFC 867",
            Service::Qotd => "RFC 865",
            Service::Chargen => "RFC 864",
            Service::Time => "RFC 868",
        }
    }
    pub fn event_type(self) -> &'static EventType {
        match self {
            Service::Echo => &ECHO_EVENT,
            Service::Discard => &DISCARD_EVENT,
            Service::Daytime => &DAYTIME_EVENT,
            Service::Qotd => &QOTD_EVENT,
            Service::Chargen => &CHARGEN_EVENT,
            Service::Time => &TIME_EVENT,
        }
    }
    pub fn event(self) -> EventType {
        match self {
            Service::Echo => ECHO_EVENT.clone(),
            Service::Discard => DISCARD_EVENT.clone(),
            Service::Daytime => DAYTIME_EVENT.clone(),
            Service::Qotd => QOTD_EVENT.clone(),
            Service::Chargen => CHARGEN_EVENT.clone(),
            Service::Time => TIME_EVENT.clone(),
        }
    }
    pub fn refuse_name(self) -> &'static str {
        match self {
            Service::Echo => "echo_refuse",
            Service::Discard => "discard_refuse",
            Service::Daytime => "daytime_refuse",
            Service::Qotd => "qotd_refuse",
            Service::Chargen => "chargen_refuse",
            Service::Time => "time_refuse",
        }
    }
    pub fn reply_definition(self) -> ActionDefinition {
        match self {
            Service::Echo => echo_action(),
            Service::Discard => discard_action(),
            Service::Daytime => daytime_action(),
            Service::Qotd => qotd_action(),
            Service::Chargen => chargen_action(),
            Service::Time => time_action(),
        }
    }
    pub fn action_name(self) -> &'static str {
        match self {
            Service::Echo => "echo_reply",
            Service::Discard => "discard_reply",
            Service::Daytime => "daytime_reply",
            Service::Qotd => "qotd_reply",
            Service::Chargen => "chargen_reply",
            Service::Time => "time_reply",
        }
    }
    /// Echo and Discard read from the client, so they have an idle deadline.
    pub fn reads(self) -> bool {
        matches!(self, Service::Echo | Service::Discard)
    }
    pub fn description(self) -> &'static str {
        match self {
            Service::Echo => "Echo service (RFC 862) over TCP and UDP; the handler may echo verbatim or answer differently",
            Service::Discard => "Discard service (RFC 863) over TCP and UDP; the handler decides which TCP connections it keeps",
            Service::Daytime => "Daytime service (RFC 867) over TCP and UDP; the handler chooses the date line",
            Service::Qotd => "Quote of the Day service (RFC 865) over TCP and UDP; the handler writes the quote",
            Service::Chargen => "Character Generator service (RFC 864) over TCP and UDP; the handler shapes the pattern",
            Service::Time => "Time service (RFC 868) over TCP and UDP; the handler chooses the time reported",
        }
    }
    pub fn keywords(self) -> Vec<&'static str> {
        match self {
            Service::Echo => vec!["echo service", "rfc862", "inetd echo"],
            Service::Discard => vec!["discard", "rfc863", "inetd discard"],
            Service::Daytime => vec!["daytime", "rfc867"],
            Service::Qotd => vec!["qotd", "quote of the day", "rfc865"],
            Service::Chargen => vec!["chargen", "character generator", "rfc864"],
            Service::Time => vec!["time protocol", "rfc868", "rdate"],
        }
    }
    pub fn llm_control(self) -> &'static str {
        match self {
            Service::Echo => {
                "What is echoed for each TCP read or UDP datagram (verbatim by default)"
            }
            Service::Discard => {
                "Whether each TCP connection is kept, and after how many bytes it is closed"
            }
            Service::Daytime => "The date and time line each request receives",
            Service::Qotd => "The quote each request receives",
            Service::Chargen => {
                "The character set, line length and byte limit of the generated stream"
            }
            Service::Time => "The time each request is told",
        }
    }
    pub fn validate(self, v: &Value) -> Result<()> {
        match self {
            Service::Echo => {
                ensure!(
                    v.get("data").is_none_or(|d| d.is_null() || d.is_string()),
                    "data must be a string"
                );
                if let Some(data) = v["data"].as_str() {
                    let bytes = wire::decode(data, v["encoding"].as_str())?;
                    ensure!(
                        bytes.len() <= 4 * wire::READ_CHUNK,
                        "data exceeds {} bytes",
                        4 * wire::READ_CHUNK
                    );
                }
            }
            Service::Discard => {
                ensure!(
                    v.get("max_bytes").is_none_or(|m| m.is_null() || m.is_u64()),
                    "max_bytes must be a non-negative integer"
                );
            }
            Service::Daytime => {
                ensure!(
                    v.get("text").is_none_or(|t| t.is_null() || t.is_string()),
                    "text must be a string"
                );
                ensure!(
                    v["text"]
                        .as_str()
                        .is_none_or(|t| t.chars().count() <= wire::MAX_DAYTIME_CHARS),
                    "text exceeds 256 characters"
                );
            }
            Service::Qotd => {
                let quote = v["quote"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("quote must be a string"))?;
                ensure!(
                    quote.chars().count() <= wire::MAX_QUOTE_CHARS,
                    "quote exceeds 512 characters (RFC 865)"
                );
            }
            Service::Chargen => {
                wire::charset(v.get("charset"))?;
                if let Some(length) = v.get("line_length").filter(|l| !l.is_null()) {
                    let length = length
                        .as_u64()
                        .ok_or_else(|| anyhow::anyhow!("line_length must be an integer"))?;
                    ensure!(
                        (1..=wire::MAX_CHARGEN_LINE as u64).contains(&length),
                        "line_length must be 1 to 512"
                    );
                }
                ensure!(
                    v.get("max_bytes").is_none_or(|m| m.is_null() || m.is_u64()),
                    "max_bytes must be a non-negative integer"
                );
            }
            Service::Time => {
                wire::requested_time(v)?;
            }
        }
        Ok(())
    }
}

/// The protocol surface every service shares, parameterised by the service.
pub fn startup_parameters(service: Service) -> Vec<ParameterDefinition> {
    let mut params = vec![ParameterDefinition {
        name: "transport".into(),
        type_hint: "string".into(),
        description: "tcp, udp, or both on the same port number".into(),
        required: false,
        example: json!("tcp"),
        default: Some(json!(super::DEFAULT_TRANSPORT)),
    }];
    if service.reads() {
        params.push(ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a TCP connection may stay silent before it is closed (1..=3600)"
                .into(),
            required: false,
            example: json!(60),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        });
    }
    params
}

pub fn metadata(service: Service) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::*;
    let builder = ProtocolMetadataV2::builder().state(DevelopmentState::Experimental);
    // Literal ports, privilege first, so a source scan reads the declaration it checks.
    let builder = match service {
        Service::Echo => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(7))
            .well_known_port(7),
        Service::Discard => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(9))
            .well_known_port(9),
        Service::Daytime => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(13))
            .well_known_port(13),
        Service::Qotd => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(17))
            .well_known_port(17),
        Service::Chargen => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(19))
            .well_known_port(19),
        Service::Time => builder
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(37))
            .well_known_port(37),
    };
    let builder = builder
        .implementation(match service {
            Service::Echo => "RFC 862 over Tokio TCP and UDP: each TCP read or UDP datagram is one request",
            Service::Discard => "RFC 863 over Tokio TCP and UDP: TCP data is read and dropped, UDP datagrams are dropped unanswered",
            Service::Daytime => "RFC 867 over Tokio TCP and UDP: one line per TCP connection or UDP datagram",
            Service::Qotd => "RFC 865 over Tokio TCP and UDP: one quote per TCP connection or UDP datagram",
            Service::Chargen => "RFC 864 over Tokio TCP and UDP: the rotating 72-column pattern streamed on TCP, one line per UDP datagram",
            Service::Time => "RFC 868 over Tokio TCP and UDP: a 32-bit big-endian count of seconds since 1900",
        })
        .llm_control(service.llm_control())
        .e2e_testing("tests/server/inetd: raw TCP and UDP exchanges for all six; Perl Net::Ping and Net::Time, rdate and nc as independent clients")
        .notes(match service {
            Service::Echo => "A handler failure closes the TCP connection or leaves the datagram unanswered; it never echoes something it was not told to. 8 KiB per read or datagram; idle deadline; UDP handling is bounded to 64 requests in flight.",
            Service::Discard => "UDP discard raises no event: nothing is decided and nothing is sent. A refusal or a handler failure closes the TCP connection.",
            Service::Daytime => "A handler failure closes the TCP connection without a line and leaves a UDP request unanswered: no fabricated time.",
            Service::Qotd => "A handler failure closes the TCP connection without a quote and leaves a UDP request unanswered.",
            Service::Chargen => "TCP output streams until the client closes, a write stalls past 30 s, or max_bytes; client input is ignored. A UDP request gets one line of at most 512 characters. A handler failure sends nothing.",
            Service::Time => "The 32-bit value wraps in 2036, as RFC 868's does. A handler failure sends nothing.",
        })
        .max_inbound_bytes(wire::READ_CHUNK);
    let builder = if service == Service::Echo {
        builder.request_only("Echo answers the data it received; it never sends first")
    } else {
        builder
    };
    // Each service answers one connection or datagram and has no conversation to remember.
    builder
        .history(crate::protocol::metadata::HistoryMode::Off)
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
}

pub fn startup_examples(service: Service) -> crate::llm::actions::StartupExamples {
    let name = service.feature_name();
    let llm = json!({"type":"open_server","base_stack":name,"port":10000 + service.port(),"instruction":format!("Run the {} service", service.name())});
    let static_action = match service {
        Service::Qotd => {
            json!({"type":"qotd_reply","quote":"Simplicity is prerequisite for reliability."})
        }
        other => json!({"type": other.action_name()}),
    };
    let mut static_example = llm.clone();
    static_example["event_handlers"] = json!([{"event_pattern": service.event().id, "handler": {"type":"static","actions":[static_action.clone()]}}]);
    let mut scripted = llm.clone();
    let code = format!(
        "import json\nprint(json.dumps({{'actions':[{}]}}))",
        static_action.to_string().replace("true", "True")
    );
    scripted["event_handlers"] = json!([{"event_pattern": service.event().id, "handler": {"type":"script","language":"python","code":code}}]);
    crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
}

pub fn execute(service: Service, v: Value) -> Result<ActionResult> {
    match v["type"].as_str() {
        Some(name) if name == service.action_name() => {
            service.validate(&v)?;
            Ok(ActionResult::Custom {
                name: name.to_string(),
                data: v,
            })
        }
        Some(name) if name == service.refuse_name() => {
            ensure!(
                v.get("reason").is_none_or(|r| r.is_null() || r.is_string()),
                "reason must be a string"
            );
            Ok(ActionResult::Custom {
                name: name.to_string(),
                data: v,
            })
        }
        _ => bail!("Unknown {} server action", service.name()),
    }
}

macro_rules! inetd_protocol {
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
            fn description(&self) -> &'static str {
                $service.description()
            }
            fn keywords(&self) -> Vec<&'static str> {
                $service.keywords()
            }
            fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
                vec![]
            }
            fn get_sync_actions(&self) -> Vec<ActionDefinition> {
                vec![$service.reply_definition(), refuse_action($service)]
            }
            fn get_event_types(&self) -> Vec<EventType> {
                vec![$service.event()]
            }
            fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
                startup_parameters($service)
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
        impl Server for $ty {
            fn spawn(
                &self,
                ctx: SpawnContext,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>,
            > {
                Box::pin(super::spawn(ctx, $service))
            }
            fn execute_action(&self, v: Value) -> Result<ActionResult> {
                execute($service, v)
            }
        }
    };
}

inetd_protocol!(
    EchoProtocol,
    Service::Echo,
    "Echo service on port 10007 over TCP and UDP"
);
inetd_protocol!(
    DiscardProtocol,
    Service::Discard,
    "Discard service on port 10009 that accepts every connection"
);
inetd_protocol!(
    DaytimeProtocol,
    Service::Daytime,
    "Daytime service on port 10013 that always reports noon on 1 January 2000"
);
inetd_protocol!(
    QotdProtocol,
    Service::Qotd,
    "Quote of the Day service on port 10017 with a different programming quote each time"
);
inetd_protocol!(
    ChargenProtocol,
    Service::Chargen,
    "Character generator on port 10019 that stops after 10 KB"
);
inetd_protocol!(
    TimeProtocol,
    Service::Time,
    "RFC 868 time server on port 10037"
);

/// The protocol object for a service, for the shared engine's model calls.
pub fn protocol(service: Service) -> &'static dyn Server {
    match service {
        Service::Echo => &EchoProtocol,
        Service::Discard => &DiscardProtocol,
        Service::Daytime => &DaytimeProtocol,
        Service::Qotd => &QotdProtocol,
        Service::Chargen => &ChargenProtocol,
        Service::Time => &TimeProtocol,
    }
}
