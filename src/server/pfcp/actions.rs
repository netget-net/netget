//! What the model decides as a UPF: whether to accept an association, and what each session
//! request gets — the cause and the IEs a UPF answers with (Created PDRs with their F-TEIDs,
//! usage reports, …). Rust adds what every response must carry (Node ID, Recovery Time Stamp,
//! the UP F-SEID it allocates) and answers heartbeats, unknown sessions and requests from a
//! node with no association itself.
use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const RESPOND: &str = "pfcp_respond";

#[derive(Default, Clone)]
pub struct PfcpProtocol;

impl PfcpProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
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
    let info = match name {
        RESPOND => "-> PFCP response {cause}".to_string(),
        other => format!("-> PFCP {}", other.trim_start_matches("pfcp_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn ies_param(description: &str) -> Parameter {
    p("ies", "object", description, false)
}

pub fn respond_action() -> ActionDefinition {
    action(
        RESPOND,
        "Answer the request. cause request_accepted (the default) or a rejection such as request_rejected, rule_creation_modification_failure, no_resources_available; ies are added to the response.",
        vec![
            p("cause", "string", "request_accepted, request_rejected, mandatory_ie_incorrect, rule_creation_modification_failure, no_resources_available, system_failure, …", false),
            ies_param("IEs to add, keyed by name, e.g. {\"created_pdr\": [{\"pdr_id\": 1, \"f_teid\": {\"teid\": 4096, \"ipv4\": \"192.0.2.2\"}}]}"),
        ],
        json!({"type":RESPOND,"cause":"request_accepted","ies":{"created_pdr":[{"pdr_id":1,"f_teid":{"teid":4096,"ipv4":"192.0.2.2"}}]}}),
    )
}

fn common() -> Vec<Parameter> {
    vec![
        p("peer", "string", "The SMF's address and port", true),
        p(
            "message",
            "string",
            "The request, e.g. session_establishment_request",
            true,
        ),
        p("sequence", "number", "The request's sequence number", true),
        p(
            "ies",
            "object",
            "The request's IEs keyed by name (grouped IEs nest, repeated IEs are arrays)",
            true,
        ),
    ]
}

fn ev(id: &str, description: &str, extra: Vec<Parameter>) -> EventType {
    let mut params = common();
    params.extend(extra);
    EventType::new(id, description, respond_action().example.clone())
        .with_parameters(params)
        .with_actions(vec![respond_action()])
}

pub static ASSOCIATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_association_setup",
        "An SMF wants a PFCP association. Answer pfcp_respond (request_accepted to associate, a rejection cause otherwise).",
        vec![p("node_id", "object", "The SMF's Node ID", true)],
    )
});

pub static ESTABLISHMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_session_establishment",
        "An SMF asks for a session: Create PDRs (traffic to match), FARs (what to do with it), maybe URRs/QERs. Accept with created_pdr entries giving an F-TEID to each PDR whose PDI asked for one (f_teid with choose: true), or reject.",
        vec![
            p("cp_seid", "number", "The SMF's session id (from its F-SEID)", true),
            p("up_seid", "number", "The UPF session id NetGet allocated for this session", true),
        ],
    )
});

pub static SESSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_session_request",
        "An SMF modifies or deletes a session (session_modification_request / session_deletion_request). Answer pfcp_respond.",
        vec![
            p("cp_seid", "number", "The SMF's session id", true),
            p("up_seid", "number", "This UPF's session id", true),
        ],
    )
});

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_request",
        "Another PFCP request from an associated SMF (association update or release, PFD management, …). Answer pfcp_respond.",
        vec![],
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        RESPOND => {
            if let Some(c) = v.get("cause").and_then(Value::as_str) {
                wire::cause_code(c)?;
            }
            // Encoding is the check: it rejects unknown names and malformed values.
            wire::encode(2, None, 0, v.get("ies").unwrap_or(&Value::Null))?;
            Ok(())
        }
        other => bail!("Unknown PFCP action {other:?}"),
    }
}

impl Protocol for PfcpProtocol {
    fn protocol_name(&self) -> &'static str {
        "PFCP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>PFCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "pfcp",
            "n4",
            "sxb",
            "upf",
            "user plane function",
            "5g core",
            "8805",
        ]
    }
    fn description(&self) -> &'static str {
        "PFCP user plane function (3GPP TS 29.244, the 5G N4 / EPC Sx interface): answers an SMF's association, heartbeat and session establishment, modification and deletion requests"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![respond_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            ASSOCIATION_EVENT.clone(),
            ESTABLISHMENT_EVENT.clone(),
            SESSION_EVENT.clone(),
            REQUEST_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "node_id".into(),
            type_hint: "string".into(),
            description: "This UPF's Node ID: an IPv4 address or an FQDN (default: the address it listens on)".into(),
            required: false,
            example: json!("upf.example.net"),
            default: None,
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(8805)
            .connectionless()
            .answers_on_failure()
            .implementation("Hand-rolled PFCP (src/server/pfcp/wire.rs): the header with and without SEID, and IEs as readable JSON (Node ID, F-SEID, F-TEID with CHOOSE, UE IP, Apply Action flags, interfaces, Outer Header Creation, recovery time, causes; others kept as numbered hex); association and session tables; heartbeats answered in Rust; responses cached by peer and sequence so a retransmitted request gets the identical response")
            .llm_control("Which associations to accept, and each session request's cause and response IEs (Created PDR F-TEIDs, usage reports, failed rules)")
            .e2e_testing("tests/server/pfcp: wmnsk/go-pfcp as the SMF (association, heartbeat, a session established with CHOOSE F-TEIDs, modified, deleted, its retransmission answered identically, and the refusals before association and after deletion); the pcap oracle (tshark's pfcp dissector) over NetGet's responses")
            .notes("Every request gets a response, so a model that says nothing, or fails, answers request_rejected (logged decision=model_silent / fail_closed_*). No user plane: NetGet does not forward GTP-U. UPF-initiated Session Report Requests are not sent.")
            .max_inbound_bytes(wire::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Be a 5G UPF on port 8805 that accepts every SMF and gives each PDR a TEID"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"pfcp","port":0,
            "instruction":"Accept every association; give each PDR that asks for an F-TEID the TEID 4096 + its PDR id on 127.0.0.1"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":RESPOND,"cause":"request_accepted"}]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); e=i['event']\nies={}\nif i['event_type_id']=='pfcp_session_establishment':\n  pdrs=e['ies'].get('create_pdr',[])\n  pdrs=pdrs if isinstance(pdrs,list) else [pdrs]\n  ies={'created_pdr':[{'pdr_id':p['pdr_id'],'f_teid':{'teid':4096+p['pdr_id'],'ipv4':'127.0.0.1'}} for p in pdrs if p.get('pdi',{}).get('f_teid',{}).get('choose')]}\nprint(json.dumps({'actions':[{'type':'pfcp_respond','cause':'request_accepted','ies':ies}]}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Server for PfcpProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(ActionResult::Custom {
            name: RESPOND.into(),
            data: action,
        })
    }
}
