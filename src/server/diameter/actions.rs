use super::codec::{self, Identity, Reply};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType, SpawnContext,
};
use crate::state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct DiameterProtocol;
impl DiameterProtocol {
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
        log_template: Some(crate::protocol::log_template::LogTemplate::new().with_info(
            match name {
                "respond_diameter_aa" => {
                    "Diameter stateless NASREQ authentication/authorization reply"
                }
                "send_diameter_aa" => {
                    "Diameter stateless NASREQ authentication/authorization requested"
                }
                "disconnect" => "Diameter peer disconnect and cancel pending work",
                _ => "Diameter typed action",
            },
        )),
    }
}
fn respond() -> ActionDefinition {
    action("respond_diameter_aa","Choose a stateless NASREQ PAP authentication/authorization verdict. Native transport supplies correlated Session-Id/peer identities and Auth-Session-State=1. No account store or device policy application.",vec![parameter("reply","object","verdict:accept|reject(default)|error; optional reply_messages/filter_ids<=8 each, UTF8<=1024bytes; service_type1..19; session_timeout:u32. Values are reported to the peer, not applied to a NAS.",true)],json!({"type":"respond_diameter_aa","reply":{"verdict":"reject"}}))
}
pub static AA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("diameter_aa_request","Selected RFC7155 stateless NASREQ AAR (application1): PAP authenticate-only1, authorize-only2, authenticate-and-authorize3. Input password intentionally goes to the chosen common handler; incidental diagnostics are private.",respond().example.clone()).with_parameters(vec![parameter("request","object","username,password(if authentication),auth_request_type,nas_identifier,nas_port,session_id,origin_host,origin_realm,source_addr. No asserted earlier authentication binding.",true)]).with_actions(vec![respond()])
});
pub fn duration_parameter(name: &str, default: u64, description: &str) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "number".into(),
        description: description.into(),
        required: false,
        example: json!(default),
        default: Some(json!(default)),
    }
}
pub fn identity_parameters() -> Vec<ParameterDefinition> {
    vec![
        ParameterDefinition {
            name: "origin_host".into(),
            type_hint: "string".into(),
            description:
                "Required local Diameter identity, ASCII letters/digits/dot/hyphen1..255bytes"
                    .into(),
            required: true,
            example: json!("netget.example"),
            default: None,
        },
        ParameterDefinition {
            name: "origin_realm".into(),
            type_hint: "string".into(),
            description: "Required served/local realm, selected ASCII identity1..255bytes".into(),
            required: true,
            example: json!("example"),
            default: None,
        },
    ]
}
pub fn timer_parameters() -> Vec<ParameterDefinition> {
    vec![
        duration_parameter(
            "io_timeout_seconds",
            codec::DEFAULT_IO_SECONDS,
            "Whole frame/connect/read deadline1..300seconds;10s writes",
        ),
        duration_parameter(
            "handler_timeout_seconds",
            codec::DEFAULT_HANDLER_SECONDS,
            "Common handler deadline1..300seconds; base peer traffic remains independent",
        ),
        duration_parameter(
            "watchdog_interval_seconds",
            codec::DEFAULT_WATCHDOG_SECONDS,
            "Native watchdog idle interval1..300seconds; answer deadline uses io_timeout_seconds",
        ),
    ]
}
pub fn identity(params: &crate::protocol::StartupParams) -> Result<Identity> {
    let id = Identity {
        host: params.get_string("origin_host")?,
        realm: params.get_string("origin_realm")?,
    };
    id.validate()?;
    Ok(id)
}
impl Protocol for DiameterProtocol {
    fn protocol_name(&self) -> &'static str {
        "DIAMETER"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DIAMETER"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["diameter", "nasreq"]
    }
    fn description(&self) -> &'static str {
        "Diameter TCP base peers and stateless NASREQ PAP authentication/authorization"
    }
    fn example_prompt(&self) -> &'static str {
        "Run a Diameter NASREQ endpoint with deterministic denial policy"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![respond()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![AA_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = identity_parameters();
        p.extend(timer_parameters());
        p.push(ParameterDefinition{name:"llm_fallback".into(),type_hint:"boolean".into(),description:"Opt unmatched credential events into model calls; explicit handlers always run. Defaultfalse rejects unmatched AAA.".into(),required:false,example:json!(true),default:Some(json!(codec::DEFAULT_LLM_FALLBACK))});
        p
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(3868).answers_on_failure().request_only("Diameter AAA answers and native peer control messages require a negotiated TCP peer; no arbitrary unsolicited payload API").max_inbound_bytes(codec::MAX_FRAME_BYTES).implementation("Native bounded RFC6733 version1 TCP headers/typed AVPs, CER/CEA, DWR/DWA, DPR/DPA; selected RFC7155 stateless NASREQ AAR/AAA application1").llm_control("Common static/script/manual/model typed verdicts, shared memory/access log; native peer lifecycle and safe fail-closed errors").e2e_testing("Required unchanged python-diameter0.9.0 Node and fiorix/go-diameter4.5.0 public SDK peers; literal real wire codec assertions, selected functional exchanges and lifecycle/failure/bounds/cancellation checks").notes("Experimental selected subset, not full RFC compliance. Trusted clear TCP3868 only: no TLS/DTLS/SCTP, peer certificate authentication or integrity. CER advertises only NASREQ application1 and no inband security; identities checked for connection consistency, not cryptographic identity. Auth-Session-State=NO_STATE_MAINTAINED(1) required; no durable account, policy or accounting store. UTF8 PAP authentication-only1, authorization-only2 and combined3; no claimed previous-session authentication binding. No stateful/multiround/CHAP/MSCHAP/EAP, STR/ASR/RAR, accounting, vendor-specific application, grouped policy, agents/proxy/relay/routing/failover or automatic replay. Optional unhandled AVPs ignored; mandatory unhandled AVPs reject with Failed-AVP; typed selected success/rejection/error outputs. Session-Id<=512bytes, username/NAS identity<=255, password<=128,16KiB frames/64AVPs,256connections,one AAA handler per peer; repeated concurrent AAA rejected busy. Handler JSON16KiB/4096nodes/depth16. Shared access record precedes any AAA acceptance. Input passwords intentionally in selected handler event/shared access retention; common incidental diagnostics hide reflections. Service-Type/Filter-Id/Session-Timeout are returned assertions, no device enforcement. Base control remains responsive while a handler is parked; whole-frame/connect and watchdog deadlines90s,handler30s,watchdogidle30s default configurable1..300s;writes10s. No fuzz/production-capture claim.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"diameter","port":3868,"startup_params":{"origin_host":"server.example","origin_realm":"example"}});
        let mut llm = base.clone();
        llm["startup_params"]["llm_fallback"] = json!(true);
        llm["instruction"] = json!("Reject every NASREQ authentication or authorization");
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"diameter_aa_request","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'respond_diameter_aa','reply':{'verdict':'reject'}}]}))"}}]);
        let mut fixed = base;
        fixed["event_handlers"] = json!([{"event_pattern":"diameter_aa_request","handler":{"type":"static","actions":[respond().example]}}]);
        StartupExamples::new(llm, script, fixed)
    }
}
impl Server for DiameterProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::DiameterServer::spawn(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ActionResult> {
        let value = codec::owned_json(value)?;
        ensure!(
            value
                .as_object()
                .is_some_and(|m| m.len() == 2 && m.contains_key("reply")),
            "Diameter action type/reply only"
        );
        if value["type"] != "respond_diameter_aa" {
            bail!("Unknown Diameter server action");
        }
        let reply: Reply = serde_json::from_value(value["reply"].clone())?;
        reply.validate()?;
        Ok(ActionResult::Custom {
            name: "respond_diameter_aa".into(),
            data: serde_json::to_value(reply)?,
        })
    }
}
