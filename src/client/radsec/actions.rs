//! The RadSec client offers the model exactly the RADIUS client's vocabulary — the same
//! requests and the same reply events. Only the transport differs: one TLS connection, with no
//! retransmission (RFC 6614 §2.5).
use crate::client::radius::RadiusClientProtocol;
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};

/// How long a request waits for its reply by default.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

#[derive(Default)]
pub struct RadsecClientProtocol;
impl RadsecClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for RadsecClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RadSec"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>RadSec"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["radsec", "radius over tls", "rfc 6614"]
    }
    fn description(&self) -> &'static str {
        "RadSec client: a NAS sending RADIUS authentication and accounting over TLS (RFC 6614)"
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        RadiusClientProtocol::new().get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        RadiusClientProtocol::new().get_sync_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        RadiusClientProtocol::new().get_event_types()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = crate::server::radsec::actions::tls_parameters(false);
        p.extend([
            ParameterDefinition {
                name: "server_name".into(),
                type_hint: "string".into(),
                description: "Name the server's certificate must carry; defaults to the host of remote_addr".into(),
                required: false,
                example: json!("radsec.example.net"),
                default: None,
            },
            ParameterDefinition {
                name: "timeout_ms".into(),
                type_hint: "number".into(),
                description: "Milliseconds a request waits for its reply before it is reported unanswered (100..=60000)".into(),
                required: false,
                example: json!(5000),
                default: Some(json!(DEFAULT_TIMEOUT_MS)),
            },
        ]);
        p
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The RADIUS client's transport over a tokio-rustls stream: packets framed by their Length field, the server verified against ca_file, a client certificate when given; every reply verified (Response Authenticator, Message-Authenticator) exactly as over UDP")
            .llm_control("The same as the RADIUS client: who to authenticate and how, what to account, and what to do with each reply")
            .e2e_testing("tests/client/radsec: NetGet's own RadSec server; FreeRADIUS with a TLS listener, and radsecproxy in front of FreeRADIUS, as independent servers")
            .notes("One connection carries authentication and accounting. Nothing is retransmitted; a request waits timeout_ms and is then reported as a timeout. A connection that closes ends the client.")
            .max_inbound_bytes(crate::server::radius::packet::MAX_PACKET_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Authenticate alice with password wonderland against the RadSec server at radsec.example.net:2083"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_client","protocol":"radsec","remote_addr":"127.0.0.1:2083",
            "startup_params":{"ca_file":"/etc/netget/radsec-ca.pem","certificate_file":"/etc/netget/radsec-client.pem","private_key_file":"/etc/netget/radsec-client.key","server_name":"localhost"},
            "instruction":"Authenticate alice with password wonderland"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"radius_connected","handler":{"type":"static","actions":[
            {"type":"radius_access_request","user_name":"alice","password":"wonderland"}]}}]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"radius_access_accept","handler":{"type":"script","language":"python",
            "code":"respond([{'type': 'disconnect'}])"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for RadsecClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        RadiusClientProtocol::new().execute_action(v)
    }
}
