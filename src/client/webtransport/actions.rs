use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::webtransport::actions::{
    parameter, reply, session_actions, validate, DATAGRAM_EVENT, STREAM_EVENT, STREAM_REPLY_EVENT,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct WebTransportClientProtocol;
impl WebTransportClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webtransport_connected",
        "The server accepted the session; open streams, send datagrams or wait for the server",
        json!({"type": "webtransport_open_bi", "data": "hello"}),
    )
    .with_parameters(vec![parameter(
        "url",
        "string",
        "The session's URL, e.g. https://127.0.0.1:4433/chat",
        true,
    )])
    .with_actions(session_actions())
});

impl Protocol for WebTransportClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "WebTransport"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>HTTP3>WebTransport"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["webtransport", "webtransport client", "web transport"]
    }
    fn description(&self) -> &'static str {
        "WebTransport over HTTP/3 client: opens a session on a URL, then exchanges streams and datagrams with the server"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        session_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut all = vec![reply()];
        all.extend(session_actions());
        all
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
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
            p("path", "string", "The session path requested from the server", json!("/chat"), Some(json!(super::DEFAULT_PATH))),
            p("certificate_sha256", "string", "Trust exactly the server certificate with this SHA-256 (hex, as browsers' serverCertificateHashes; ECDSA P-256, valid at most 14 days)", json!("3f1a…64 hex digits"), None),
            p("ca_cert_path", "string", "PEM CA or certificate to trust instead of the system roots", json!("ca.pem"), None),
            p("headers", "object", "Extra request header fields, e.g. {\"origin\": \"https://example.com\"}", json!({"origin": "https://example.com"}), None),
            p("idle_timeout_secs", "number", "Close the session when idle this long, 1 to 3600 seconds", json!(30), Some(json!(crate::server::webtransport::IDLE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("wtransport 0.7.2 (vendored with settings, driver and QPACK bounds) over quinn: certificate-pinned, CA or system-root TLS, extended CONNECT, streams read whole, datagrams")
            .llm_control("What the client sends on streams and datagrams, its answers to server-opened streams, and when it closes")
            .e2e_testing("tests/client/webtransport: an aioquic 1.3.0 (independent, Python) WebTransport server echoes the client's streams and datagrams and opens streams to it")
            .notes("A refused session reports only that it was refused (wtransport does not surface the status). Streams are delivered whole, up to 1 MiB within 30 s.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Open a WebTransport session to https://127.0.0.1:4433/echo and send hello on a stream"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"webtransport","remote_addr":"127.0.0.1:4433","instruction":"Send hello on a bidirectional stream and report the answer","startup_params":{"path":"/echo","certificate_sha256":"<server certificate sha-256>"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"webtransport_connected","handler":{"type":"static","actions":[{"type":"webtransport_open_bi","data":"hello"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"webtransport_datagram","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'webtransport_send_datagram','data':'ack '+e['data']}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for WebTransportClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if matches!(
            v["type"].as_str(),
            Some("webtransport_accept" | "webtransport_reject")
        ) {
            bail!("a client does not admit sessions");
        }
        validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
