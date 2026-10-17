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
pub struct WebTransportProtocol;
impl WebTransportProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("WebTransport {name}"))),
    }
}

fn data_params(what: &str) -> Vec<Parameter> {
    vec![
        parameter("data", "string", what, true),
        parameter(
            "encoding",
            "string",
            "How data is written: utf8 (the default) sends the text as is, hex decodes it to bytes",
            false,
        ),
    ]
}

pub fn accept() -> ActionDefinition {
    action(
        "webtransport_accept",
        "Accept the session request with 200; later actions in the same answer run on the new session",
        vec![parameter(
            "headers",
            "object",
            "Extra response header fields, lowercase names, e.g. {\"x-room\": \"lobby\"}",
            false,
        )],
        json!({"type": "webtransport_accept"}),
    )
}
pub fn reject() -> ActionDefinition {
    action(
        "webtransport_reject",
        "Refuse the session request with an HTTP status",
        vec![parameter(
            "status",
            "number",
            "403 (forbidden), 404 (no such endpoint) or 429 (too many requests)",
            true,
        )],
        json!({"type": "webtransport_reject", "status": 403}),
    )
}
pub fn reply() -> ActionDefinition {
    action(
        "webtransport_reply",
        "Answer a bidirectional stream: write the data on it and finish it",
        data_params("The answer written back on the stream that raised the event"),
        json!({"type": "webtransport_reply", "data": "pong"}),
    )
}
pub fn send_datagram() -> ActionDefinition {
    action(
        "webtransport_send_datagram",
        "Send an unreliable datagram on the session (at most the path's datagram size, about 1200 bytes)",
        data_params("The datagram's payload"),
        json!({"type": "webtransport_send_datagram", "data": "tick"}),
    )
}
pub fn open_uni() -> ActionDefinition {
    action(
        "webtransport_open_uni",
        "Open a unidirectional stream to the peer, write the data and finish it",
        data_params("What the stream carries"),
        json!({"type": "webtransport_open_uni", "data": "news: doors open at 9"}),
    )
}
pub fn open_bi() -> ActionDefinition {
    action(
        "webtransport_open_bi",
        "Open a bidirectional stream, write the data, finish the sending side and wait for the peer's answer, which raises webtransport_stream_reply",
        data_params("The request written on the stream"),
        json!({"type": "webtransport_open_bi", "data": "status?"}),
    )
}
pub fn close() -> ActionDefinition {
    action(
        "webtransport_close",
        "Close the session with an application error code and a reason the peer receives",
        vec![
            parameter(
                "code",
                "number",
                "Application error code, 0 to 4294967295 (0 is a normal close)",
                false,
            ),
            parameter(
                "reason",
                "string",
                "Text the peer receives with the close, e.g. done",
                false,
            ),
        ],
        json!({"type": "webtransport_close", "code": 0, "reason": "done"}),
    )
}

/// What any session-level event may answer with.
pub fn session_actions() -> Vec<ActionDefinition> {
    vec![send_datagram(), open_uni(), open_bi(), close()]
}

pub fn payload_params() -> Vec<Parameter> {
    vec![
        parameter(
            "data",
            "string",
            "What arrived, as text, or as hex when it is not UTF-8",
            true,
        ),
        parameter(
            "encoding",
            "string",
            "utf8 when data is the text that arrived, hex when the bytes were not UTF-8",
            true,
        ),
    ]
}

pub fn stream_event(id: &'static str, description: &'static str, with_reply: bool) -> EventType {
    let mut params = vec![
        parameter(
            "stream_id",
            "number",
            "The QUIC stream id the data arrived on",
            true,
        ),
        parameter(
            "direction",
            "string",
            "bidirectional (answer with webtransport_reply) or unidirectional (nothing to answer on)",
            true,
        ),
    ];
    params.extend(payload_params());
    let mut answers = if with_reply { vec![reply()] } else { vec![] };
    answers.extend(session_actions());
    EventType::new(
        id,
        description,
        if with_reply {
            reply().example
        } else {
            open_uni().example
        },
    )
    .with_parameters(params)
    .with_actions(answers)
}

pub static SESSION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut answers = vec![accept(), reject()];
    answers.extend(session_actions());
    EventType::new(
        "webtransport_session_request",
        "A client asked to open a WebTransport session (extended CONNECT); accept it or refuse it",
        accept().example,
    )
    .with_parameters(vec![
        parameter("path", "string", "The requested path, e.g. /chat", true),
        parameter(
            "authority",
            "string",
            "The :authority the client named",
            true,
        ),
        parameter(
            "origin",
            "string",
            "The Origin header a browser sends, e.g. https://example.com",
            false,
        ),
        parameter(
            "headers",
            "object",
            "Every request header field by lowercase name",
            true,
        ),
        parameter("peer_addr", "string", "The client's UDP address", true),
    ])
    .with_actions(answers)
});
pub static STREAM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "webtransport_stream",
        "The peer opened a stream and finished sending on it; a bidirectional stream waits for webtransport_reply",
        true,
    )
});
pub static DATAGRAM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webtransport_datagram",
        "A datagram arrived on the session",
        send_datagram().example,
    )
    .with_parameters(payload_params())
    .with_actions(session_actions())
});
pub static STREAM_REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = vec![
        parameter(
            "stream_id",
            "number",
            "The stream webtransport_open_bi opened",
            true,
        ),
        parameter("request", "string", "What was written on it, as sent", true),
    ];
    params.extend(payload_params());
    EventType::new(
        "webtransport_stream_reply",
        "The peer answered a stream opened with webtransport_open_bi and finished it",
        json!({"type": "webtransport_send_datagram", "data": "thanks"}),
    )
    .with_parameters(params)
    .with_actions(session_actions())
});

/// Check one action's fields, so a bad answer is refused before anything is written.
pub fn validate(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("webtransport_accept") => {
            if let Some(h) = v.get("headers").filter(|h| !h.is_null()) {
                let h = h.as_object().context("headers is an object")?;
                ensure!(h.len() <= 16, "at most 16 extra headers");
                for (k, value) in h {
                    ensure!(
                        !k.is_empty()
                            && k.len() <= 64
                            && k.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                        "{k:?} is not a lowercase header name"
                    );
                    let value = value.as_str().context("header values are strings")?;
                    ensure!(
                        value.len() <= 1024 && !crate::utils::sanitize::has_controls(&value),
                        "the {k} header value is too long or carries control characters"
                    );
                }
            }
        }
        Some("webtransport_reject") => ensure!(
            matches!(v["status"].as_u64(), Some(403 | 404 | 429)),
            "status is 403, 404 or 429"
        ),
        Some(
            "webtransport_reply"
            | "webtransport_send_datagram"
            | "webtransport_open_uni"
            | "webtransport_open_bi",
        ) => {
            super::session::payload(v)?;
        }
        Some("webtransport_close") => {
            if let Some(code) = v.get("code").filter(|c| !c.is_null()) {
                ensure!(
                    code.as_u64().is_some_and(|c| c <= u32::MAX as u64),
                    "code is 0 to 4294967295"
                );
            }
            if let Some(reason) = v.get("reason").filter(|r| !r.is_null()) {
                let reason = reason.as_str().context("reason is text")?;
                ensure!(reason.len() <= 1024, "reason is at most 1024 bytes");
            }
        }
        Some(other) => bail!("Unknown WebTransport action {other}"),
        None => bail!("an action names its type"),
    }
    Ok(())
}

impl Protocol for WebTransportProtocol {
    fn protocol_name(&self) -> &'static str {
        "WebTransport"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>HTTP3>WebTransport"
    }
    fn description(&self) -> &'static str {
        "WebTransport over HTTP/3 server: browsers and other clients open sessions the handler accepts or refuses, then exchange streams and datagrams with it"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "webtransport",
            "webtransport server",
            "web transport",
            "http3 webtransport",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        session_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut all = vec![accept(), reject(), reply()];
        all.extend(session_actions());
        all
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SESSION_REQUEST_EVENT.clone(),
            STREAM_EVENT.clone(),
            DATAGRAM_EVENT.clone(),
            STREAM_REPLY_EVENT.clone(),
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
            p("cert_path", "string", "PEM certificate chain; without it (and key_path) a self-signed ECDSA certificate valid 14 days is generated and its SHA-256 logged for browsers' serverCertificateHashes", json!("cert.pem"), None),
            p("key_path", "string", "PEM private key for cert_path", json!("key.pem"), None),
            p("max_sessions", "number", "Concurrent sessions, 1 to 256", json!(16), Some(json!(super::MAX_SESSIONS))),
            p("idle_timeout_secs", "number", "Close a session idle this long, 1 to 3600 seconds", json!(30), Some(json!(super::IDLE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .port_transport(PortTransport::Udp)
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("wtransport 0.7.2 (vendored with driver, settings and QPACK bounds) over quinn: HTTP/3 extended CONNECT with draft-02 headers, session admission, bidirectional and unidirectional streams read to their end, and datagrams")
            .llm_control("Which sessions are admitted, the answer on every stream, datagrams, server-opened streams and closing the session")
            .e2e_testing("tests/server/webtransport: aioquic 1.3.0 (independent, Python) opens sessions, streams and datagrams; headless Chrome's WebTransport API with serverCertificateHashes")
            .notes("Streams are delivered whole (up to 1 MiB each, 30 s to finish); 32 streams and handler turns in flight per session; one handler turn at a time per session; follow-up chains stop at depth 4. No HTTP/3 requests other than WebTransport CONNECT, no session-level flow control capsules, no pooling of several sessions on one connection.")
            .answers_on_failure()
            .max_inbound_bytes(super::session::MAX_STREAM_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "WebTransport server on UDP 4433 that accepts /echo sessions and echoes every stream and datagram"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"webtransport","port":4433,"instruction":"Accept sessions on /echo, refuse others with 404, and echo every stream and datagram"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"webtransport_session_request","handler":{"type":"static","actions":[{"type":"webtransport_accept"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"webtransport_stream","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'webtransport_reply','data':e['data'],'encoding':e['encoding']}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for WebTransportProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        validate(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
