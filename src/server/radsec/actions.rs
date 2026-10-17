//! RadSec (RFC 6614) offers the model exactly RADIUS's vocabulary: the same events, the same
//! reply actions, the same fail-closed rule. Only the transport differs.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::radius::RadiusProtocol;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};

#[derive(Default)]
pub struct RadsecProtocol;
impl RadsecProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub(crate) fn tls_parameters(server: bool) -> Vec<ParameterDefinition> {
    let own = if server { "server" } else { "client" };
    vec![
        ParameterDefinition {
            name: "certificate_file".into(),
            type_hint: "string".into(),
            description: format!(
                "PEM file with this {own}'s certificate chain{}",
                if server {
                    "; with private_key_file. Omit both for a fresh self-signed certificate"
                } else {
                    "; with private_key_file, presented when the server asks for one"
                }
            ),
            required: false,
            example: json!(format!("/etc/netget/radsec-{own}.pem")),
            default: None,
        },
        ParameterDefinition {
            name: "private_key_file".into(),
            type_hint: "string".into(),
            description: format!("PEM file with the private key of certificate_file ({own} side)"),
            required: false,
            example: json!(format!("/etc/netget/radsec-{own}.key")),
            default: None,
        },
        ParameterDefinition {
            name: "ca_file".into(),
            type_hint: "string".into(),
            description: if server {
                "PEM file of the CA client certificates must chain to; when set, a client without one is refused at the handshake".into()
            } else {
                "PEM file of the CA the server's certificate must chain to (required: the server is always verified)".into()
            },
            required: !server,
            example: json!("/etc/netget/radsec-ca.pem"),
            default: None,
        },
        ParameterDefinition {
            name: "shared_secret".into(),
            type_hint: "string".into(),
            description: "RADIUS shared secret inside the TLS session; RFC 6614 fixes it as radsec"
                .into(),
            required: false,
            example: json!("radsec"),
            default: Some(json!(super::tls::DEFAULT_SECRET)),
        },
    ]
}

impl Protocol for RadsecProtocol {
    fn protocol_name(&self) -> &'static str {
        "RadSec"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>RadSec"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["radsec", "radius over tls", "radius/tls", "rfc 6614"]
    }
    fn description(&self) -> &'static str {
        "RadSec server: RADIUS authentication and accounting over TLS (RFC 6614), mutual TLS when a CA is given"
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        RadiusProtocol::new().get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        RadiusProtocol::new().get_sync_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        RadiusProtocol::new().get_event_types()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = tls_parameters(true);
        p.push(ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a connection may stay silent before it is closed (1..=86400)"
                .into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        });
        p
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2083)
            .implementation("RFC 6614 over tokio-rustls: RADIUS packets framed by their own Length field on a TLS stream, answered by the RADIUS server's decision path (RadiusServer::answer), so the codec, the Response Authenticator and the fail-closed rule are RADIUS's own; mutual TLS when ca_file is set")
            .llm_control("The same as RADIUS: the authorization decision (Accept, Reject, Challenge), the reply attributes, and acknowledging accounting")
            .e2e_testing("tests/server/radsec: radsecproxy (C) and FreeRADIUS proxying to NetGet as a TLS home server, each driven by radclient through it; raw TLS for framing, bounds and the client-certificate requirement")
            .notes("FAILS CLOSED as RADIUS does: no usable answer is an Access-Reject logged decision=fail_closed_*. Requests on one connection are answered concurrently (32 at a time) and may be answered out of order, which RFC 6614 allows. No retransmission handling is needed over TCP; a duplicate identifier is answered again. A length outside 20..=4096 closes the connection: a stream cannot be resynchronised. Status-Server keepalives are answered like any other request.")
            .request_only("Every packet NetGet writes answers a RADIUS request; no CoA or Disconnect-Request is sent")
            .answers_on_failure()
            .max_inbound_bytes(crate::server::radius::packet::MAX_PACKET_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RadSec server on 2083 that accepts alice with password wonderland and rejects everyone else"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"radsec","port":2083,
            "instruction":"Accept alice with password wonderland; reject everyone else"});
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"radius_access_request","handler":{"type":"script","language":"python",
            "code":"respond([{'type': 'send_access_accept'}] if event['user_name'] == 'alice' and event.get('password') == 'wonderland' else [{'type': 'send_access_reject', 'reply_message': 'denied'}])"}}]);
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"radius_access_request","handler":{"type":"static","actions":[{"type":"send_access_reject","reply_message":"This server denies everyone"}]}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for RadsecProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        RadiusProtocol::new().execute_action(v)
    }
}
