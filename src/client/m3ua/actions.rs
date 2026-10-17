//! What the model does as an M3UA ASP with an SS7 upper stack: open MAP dialogues (an MSC or SMSC
//! asking an HLR, a gsmSCF interrogating, a USSD gateway), act as a CAMEL gsmSSF (initialDP and
//! event reports), and answer what comes back. ASPUP and ASPAC are performed by Rust on connect
//! from the startup parameters, the way a real ASP brings itself up from configuration.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::m3ua::ss7_actions::{self, Role};
use crate::server::m3ua::{codec, ss7};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Defaults for the ASP's addressing when the startup parameters name none.
pub const DEFAULT_OPC: u64 = 1;
pub const DEFAULT_DPC: u64 = 2;
pub const DEFAULT_NI: u64 = 2;
pub const DEFAULT_LOCAL_SSN: u64 = 8;
pub const DEFAULT_REMOTE_SSN: u64 = 6;

#[derive(Default)]
pub struct M3uaClientProtocol;
impl M3uaClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Take the ASP out of service (ASPDN) and close the association.".into(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> M3UA ASPDN and close")),
    }
}

/// Everything the model may do on this client.
pub fn actions() -> Vec<ActionDefinition> {
    let mut a = ss7_actions::all_actions(Role::Asp);
    a.push(disconnect_action());
    a.push(ActionDefinition {
        name: "wait_for_more".into(),
        description: "Send nothing now (for results, reports and dialogue ends that need no \
                      answer)."
            .into(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(LogTemplate::new().with_info("-> M3UA wait for more")),
    });
    a
}

fn with_all(mut e: EventType) -> EventType {
    e.actions = actions();
    e
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_connected",
        "The SGP accepted this ASP (ASPUP ACK, ASPAC ACK): SS7 traffic can flow. Open a MAP \
         dialogue with send_map_request or a CAMEL dialogue with send_cap_operations \
         (initialDP).",
        ss7_actions::send_map_request_action(Role::Asp).example,
    )
    .with_parameters(vec![
        p(
            "routing_context",
            "number",
            "The routing context activated, if any",
            false,
        ),
        p(
            "traffic_mode",
            "string",
            "The traffic mode the SGP acknowledged",
            false,
        ),
        p(
            "notifications",
            "array",
            "NTFY status messages received while coming up",
            false,
        ),
        p(
            "transport",
            "string",
            "sctp, or the non-standard lab tcp transport",
            true,
        ),
    ])
    .with_actions(actions())
    .with_log_template(LogTemplate::new().with_info("M3UA ASP active rc={routing_context}"))
});

pub static MAP_EVENT: LazyLock<EventType> =
    LazyLock::new(|| with_all(ss7_actions::map_event(Role::Asp)));
pub static CAP_EVENT: LazyLock<EventType> =
    LazyLock::new(|| with_all(ss7_actions::cap_event(Role::Asp)));

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_sgp_error",
        "The SGP sent an M3UA ERR, or SS7 traffic NetGet does not decode. Observational.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        p("message", "string", "What arrived: \"err\" for an M3UA ERR, or a description of an MSU with a service indicator NetGet does not decode", true),
        p("error_name", "string", "The M3UA error, for an ERR", false),
    ])
    .with_actions(actions())
    .with_log_template(LogTemplate::new().with_info("M3UA SGP error: {message} {error_name}"))
});

fn param(
    name: &str,
    type_hint: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for M3uaClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "M3UA"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>SCTP>M3UA"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "m3ua client",
            "asp",
            "sigtran",
            "ss7",
            "sccp",
            "tcap",
            "map",
            "gsm map",
            "camel",
            "cap",
            "hlr",
            "ussd",
            "sms",
        ]
    }
    fn description(&self) -> &'static str {
        "M3UA ASP with SCCP, TCAP, MAP and CAMEL: opens MAP and CAP dialogues towards an SGP"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            MAP_EVENT.clone(),
            CAP_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param("transport", "string", "\"sctp\" (default, RFC 4666) or \"tcp\" — NON-STANDARD, for local work only", json!("sctp"), None),
            param("local_port", "number", "Bind the association to this local port (some SGPs accept only a configured peer port); default: any", json!(2906), None),
            param("routing_context", "number", "Routing Context to activate in ASPAC and to put on DATA (default: none)", json!(100), None),
            param("asp_identifier", "number", "ASP Identifier sent in ASPUP (default: none)", json!(1), None),
            param("opc", "number", "This ASP's point code (14-bit ITU), the OPC of every MSU", json!(1), Some(json!(DEFAULT_OPC))),
            param("dpc", "number", "The far end's point code, the DPC of every MSU", json!(2), Some(json!(DEFAULT_DPC))),
            param("network_indicator", "number", "MTP3 network indicator, 0..3 (2 is national)", json!(2), Some(json!(DEFAULT_NI))),
            param("local_ssn", "number", "This end's SCCP subsystem (8 MSC, 6 HLR, 7 VLR, 146 CAP)", json!(8), Some(json!(DEFAULT_LOCAL_SSN))),
            param("remote_ssn", "number", "The far end's SCCP subsystem for dialogues with no called_address", json!(6), Some(json!(DEFAULT_REMOTE_SSN))),
            param("local_gt", "string", "This end's global title digits (E.164); default: none", json!("31600000100"), None),
            param("remote_gt", "string", "The far end's global title digits; default: none", json!("31600000200"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The SGP's M3UA codec and SS7 engine (src/server/m3ua: SCCP UDT/XUDT, ITU TCAP with dialogue portion, hand-rolled bounded BER, MAP and CAP operation mappings) as an ASP: SCTP association (PPID 3, management on stream 0, DATA on stream 1) or the labelled lab TCP transport, ASPUP/ASPAC from the startup parameters, BEAT answered in Rust")
            .llm_control("Which MAP and CAMEL dialogues to open and with what arguments, and how to answer what comes back (results, errors, CAMEL instructions)")
            .e2e_testing("tests/client/m3ua: Restcomm jSS7 8.0.112 as SGW over real SCTP on Linux answers the model's MAP and CAP dialogues, and osmo-stp routes them; a canned SGP over the lab transport for bounds and wiring")
            .notes("Experimental: one independent family of MAP/CAP peer (jSS7), runnable only where SCTP exists. No segmentation, no global title translation, no MAP v1 origination, no sendAuthenticationInfo or insertSubscriberData. Handler chains stop after the follow-up depth bound.")
            .max_inbound_bytes(codec::MAX_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect an ASP to the SGP at 10.0.0.5:2905 and ask the HLR where to deliver an SMS for +31628838002"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "m3ua", "remote_addr": "127.0.0.1:2905",
            "startup_params": {"opc": 1, "dpc": 2, "routing_context": 100, "local_ssn": 8, "remote_ssn": 6},
            "instruction": "Ask the HLR for routing info for SMS to 31628838002 (service centre 31611111111), then deliver 'Hello' to the MSC it names with mt-forwardSM"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "m3ua_connected", "handler": {"type": "static", "actions": [
                ss7_actions::send_map_request_action(Role::Asp).example]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']; t=i['event_type_id']\na=[]\nif t=='m3ua_connected': a=[{'type':'send_map_request','operation':'sendRoutingInfoForSM','argument':{'msisdn':'31628838002','service_centre_address':'31611111111'}}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }
}

impl Client for M3uaClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            n if ss7::INTENTS.contains(&n) => {
                ss7::check_intent(&v).map_err(|e| anyhow!(e))?;
                Ok(ClientActionResult::Custom { name, data: v })
            }
            other => Err(anyhow!("Unknown M3UA client action {other:?}")),
        }
    }
}
