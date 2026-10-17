use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::diameter::{
    actions::{action, identity_parameters, parameter, timer_parameters},
    codec::{self, Request},
};
use crate::state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct DiameterClientProtocol;
impl DiameterClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn send() -> ActionDefinition {
    action("send_diameter_aa","Send one stateless NASREQ PAP AAR on the negotiated TCP peer, with fresh correlated IDs and Session-Id. No automatic retry or account fallback.",vec![parameter("username","string","Required nonempty UTF8<=255bytes",true),parameter("password","string","UTF8<=128bytes; required types1/3, excluded type2; redacted in action logs",false),parameter("auth_request_type","number","1authenticate-only,2authorize-only,3combined(default)",false),parameter("nas_identifier","string","Optional NAS identifier, UTF8 at most255bytes without NUL",false),parameter("nas_port","number","Optional NAS port number in the unsigned32bit range",false)],json!({"type":"send_diameter_aa","username":"alice","password":"replace-me","auth_request_type":3}))
}
fn disconnect() -> ActionDefinition {
    action("disconnect","Send bounded native DPR/DPA then close; cancel pending AAA and handlers. Removal closes immediately without waiting for peer.",vec![],json!({"type":"disconnect"}))
}
fn all() -> Vec<ActionDefinition> {
    vec![send(), disconnect()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("diameter_connected","TCP and CER/CEA NASREQ capability exchange completed; peer identity is consistent but unauthenticated clear TCP.",send().example.clone()).with_parameters(vec![parameter("peer","object","origin_host,origin_realm,remote_addr",true)]).with_actions(all())
});
pub static AA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("diameter_aa_result","Correlated stateless NASREQ result; accepted only for2001 with agreed stateless mode and supported mandatory AVPs. Returned attributes are not applied to a device.",disconnect().example.clone()).with_parameters(vec![parameter("request","object","Credential-free username/auth_request_type/NAS fields and Session-Id",true),parameter("reply","object","result_code,accepted,stateless,reply_messages,filter_ids,service_type,session_timeout",true)]).with_actions(all())
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "diameter_error",
        "Peer/session deadline, framing or correlation failed; no implicit replay.",
        disconnect().example.clone(),
    )
    .with_parameters(vec![parameter(
        "error",
        "string",
        "Safe bounded category without credential reflection",
        true,
    )])
    .with_actions(all())
});
pub fn parse_action(value: Value) -> Result<Request> {
    let mut value = codec::owned_json(value)?;
    ensure!(
        value["type"] == "send_diameter_aa",
        "Diameter client request action"
    );
    value
        .as_object_mut()
        .context("Diameter action object")?
        .remove("type");
    let request: Request = serde_json::from_value(value)?;
    request.validate()?;
    Ok(request)
}
use anyhow::Context;
impl Protocol for DiameterClientProtocol {
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
        "Diameter negotiated TCP peer and stateless NASREQ typed client"
    }
    fn example_prompt(&self) -> &'static str {
        "Authenticate alice against a Diameter NASREQ test peer"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        all()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            AA_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = identity_parameters();
        p.extend(timer_parameters());
        p
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(3868).request_only("Native CER/CEA/watchdog/disconnect and typed AAA responses; no arbitrary unsolicited payload action").max_inbound_bytes(codec::MAX_FRAME_BYTES).implementation("Native bounded RFC6733 negotiated TCP peer lifecycle and RFC7155 stateless NASREQ UTF8 PAP requests/typed results").llm_control("Common typed connected/result/error handlers, shared memory/access recording and bounded command injection independent of parked handlers").e2e_testing("Required unchanged python-diameter0.9.0 Node and fiorix/go-diameter4.5.0 public SDK server roles; real codec golden, response correlation/errors/state refusal/bounds/cancellation").notes("Experimental selected stateless NASREQ application1, not full RFC compliance. Trusted clear TCP3868 only; no TLS/DTLS/SCTP, peer certificate authentication or integrity. Connect completes TCP/CER/CEA; negotiated origin host/realm supply direct NASREQ destination; identity consistency is not cryptographic authentication. Native watchdog and DPR/DPA remain responsive while handlers are parked. Auth-Session-State=1 required on successful AAA; only result2001 accepted after header/IDs/session/application/type/origin/mandatory-AVP validation.1authenticate-only,2authorize-only(no password),3combined; no stateful sessions/multiround/CHAP/EAP, prior authentication binding, STR/ASR/RAR/accounting/agents/routing/vendor applications/grouped policy/failover or replay. One pending AAA,16commands,32queued events/actions,followupdepth8;16KiBframe/64AVPs,512byteSession-Id,255byteusername/NAS identity,128bytepassword,1024byte reply text,8reply/filter values. Client result events omit password; original action values remain intact on wire and redacted in injected logs. Service-Type1..19,Filter-Id,Session-Timeout reported without device enforcement. Constructed action JSON16KiB/4096nodes/depth16 preflighted before copying. Whole-frame/connect/watchdog answer90s,handler30s,watchdog idle30s default configurable1..300s;write10s. Caller command timeout alone does not cancel wire operation; disconnect/removal cancels it and handlers. No protocol domain store, durable AAA session, fuzz or production-capture claim.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_client","base_stack":"diameter","remote_addr":"127.0.0.1:3868","startup_params":{"origin_host":"client.example","origin_realm":"example"}});
        let mut llm = base.clone();
        llm["instruction"] = json!("Request one stateless PAP authentication for alice");
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"diameter_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'send_diameter_aa','username':'alice','password':'replace-me'}]}))"}}]);
        let mut fixed = base;
        fixed["event_handlers"] = json!([{"event_pattern":"diameter_connected","handler":{"type":"static","actions":[send().example]}}]);
        StartupExamples::new(llm, script, fixed)
    }
}
impl Client for DiameterClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::DiameterClient::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        let value = codec::owned_json(value)?;
        if value["type"] == "disconnect" {
            ensure!(
                value.as_object().is_some_and(|m| m.len() == 1),
                "Diameter disconnect only type"
            );
            return Ok(ClientActionResult::Disconnect);
        }
        if value["type"] != "send_diameter_aa" {
            bail!("Unknown Diameter client action");
        }
        parse_action(value.clone())?;
        Ok(ClientActionResult::Custom {
            name: "diameter_command".into(),
            data: value,
        })
    }
}
