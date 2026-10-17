//! Raw QUIC FIN-delimited stream exchanges, independent from HTTP/3.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

fn field(name: &str, hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required: true,
    }
}
pub static QUIC_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_connected",
        "Authenticated raw QUIC connection established",
        json!({"type":"send_quic_data","data":"hello"}),
    )
    .with_parameters(vec![
        field(
            "remote_addr",
            "string",
            "Authenticated QUIC peer's socket address",
        ),
        field(
            "max_datagram_size",
            "number",
            "Largest DATAGRAM payload the server accepts, or null when it does not support \
             RFC 9221 datagrams",
        ),
    ])
    .with_actions(QuicClientProtocol.get_sync_actions())
});
pub static QUIC_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_data_received",
        "Complete FIN-terminated raw QUIC response",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(vec![
        field("stream_id", "number", "QUIC wire stream ID"),
        field("data", "string", "Received payload"),
        field("encoding", "string", "utf8 or hex payload encoding"),
        field("bytes", "number", "Payload byte count"),
    ])
    .with_actions(QuicClientProtocol.get_sync_actions())
});
pub static QUIC_DATAGRAM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_datagram_received",
        "An unreliable QUIC DATAGRAM frame (RFC 9221) arrived from the server",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(vec![
        field(
            "data",
            "string",
            "Datagram payload, read according to encoding",
        ),
        field(
            "encoding",
            "string",
            "utf8 for printable text, otherwise hex",
        ),
        field("bytes", "number", "Payload byte count"),
    ])
    .with_actions(QuicClientProtocol.get_sync_actions())
});
pub static QUIC_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_stream_error",
        "Raw QUIC stream exchange failed",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(vec![field("error", "string", "Local failure description")])
    .with_actions(QuicClientProtocol.get_sync_actions())
});
#[derive(Default)]
pub struct QuicClientProtocol;
impl QuicClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for QuicClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "QUIC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn description(&self) -> &'static str {
        "Raw QUIC client with authenticated concurrent bidirectional stream exchanges"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["quic", "raw quic", "quic streams"]
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to localhost:4433 over raw QUIC and send hello"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = crate::utils::quic::client_parameters();
        p.push(crate::utils::quic::parameter(
            "alpn",
            "Raw stream application protocol (default netget-quic)",
            json!("netget-quic"),
            Some(json!("netget-quic")),
        ));
        p
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut a = crate::server::quic::actions::QuicProtocol.get_sync_actions();
        a.retain(|a| a.name != "close_this_stream");
        a[0].description="Open a new bidirectional QUIC stream, send raw data and FIN, and receive at most 1 MiB until peer FIN. Every action uses an independent stream. Encodings: utf8, hex, base64.".into();
        if let Some(d) = a.iter_mut().find(|a| a.name == "send_quic_datagram") {
            d.description = "Send an unreliable RFC 9221 DATAGRAM frame to the server: no \
                stream, no retransmission, at most the connection's max_datagram_size bytes \
                (from quic_connected). Any reply arrives as quic_datagram_received."
                .into();
        }
        a.push(ActionDefinition {
            name: "disconnect".into(),
            description: "Close the QUIC connection and cancel all streams".into(),
            parameters: vec![],
            example: json!({"type":"disconnect"}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("Disconnect raw QUIC peer and cancel all active streams"),
            ),
        });
        a
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            QUIC_CONNECTED_EVENT.clone(),
            QUIC_RESPONSE_EVENT.clone(),
            QUIC_ERROR_EVENT.clone(),
            QUIC_DATAGRAM_EVENT.clone(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).implementation("quinn 0.11/rustls; raw netget-quic ALPN, distinct from HTTP/3")
  .llm_control("Explicit text/hex/base64 stream payloads, response/error events, bounded follow-ups and disconnect")
  .e2e_testing("Independent aioquic 1.3.0 echo server; authenticated binary exchanges, multiplexing, injection/follow-ups and cleanup")
  .notes("Each send_quic_data opens one FIN-delimited bidirectional exchange; send_quic_datagram sends an RFC 9221 DATAGRAM and incoming datagrams arrive as quic_datagram_received. No append to existing streams, incoming server streams, 0-RTT, reconnect or application framing. Certificates and hostname always verified; custom PEM trust supported. 1 MiB per direction, 32 exchanges, four queries per automatic chain.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
  .batching(crate::protocol::metadata::BatchingMode::Unsupported)
  .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","protocol":"quic","remote_addr":"localhost:4433","instruction":"Send hello on a new QUIC stream"}),
            json!({"type":"open_client","protocol":"quic","remote_addr":"localhost:4433","event_handlers":[{"event_pattern":"quic_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'send_quic_data','data':'hello'}]}))"}}]}),
            json!({"type":"open_client","protocol":"quic","remote_addr":"localhost:4433","event_handlers":[{"event_pattern":"quic_connected","handler":{"type":"static","actions":[{"type":"send_quic_data","data":"hello"}]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]}),
        )
    }
}
impl Client for QuicClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::QuicClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_quic_data") => {
                super::payload(&action)?;
                Ok(ClientActionResult::Custom {
                    name: "quic_exchange".into(),
                    data: action,
                })
            }
            Some("send_quic_datagram") => Ok(ClientActionResult::Custom {
                name: crate::server::quic::actions::DATAGRAM_RESULT.into(),
                data: json!(hex::encode(crate::server::quic::actions::datagram_payload(
                    &action
                )?)),
            }),
            Some("wait_for_more") => Ok(ClientActionResult::WaitForMore),
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown QUIC client action"),
        }
    }
}
