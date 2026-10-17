//! What the model can do as a PFCP control plane (an SMF) towards one UPF: associate,
//! heartbeat, and establish, modify and delete sessions — and answer what the UPF asks.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::pfcp::actions::{action, ies_param, p};
use crate::server::pfcp::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct PfcpClientProtocol;
impl PfcpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn associate() -> ActionDefinition {
    action(
        "pfcp_associate",
        "Send an Association Setup Request (Node ID and Recovery Time Stamp are added); the answer arrives as pfcp_response.",
        vec![ies_param("Extra IEs, e.g. {\"cp_function_features\": {\"hex\": \"0000\"}}")],
        json!({"type":"pfcp_associate"}),
    )
}

fn heartbeat() -> ActionDefinition {
    action(
        "pfcp_heartbeat",
        "Send a Heartbeat Request; the answer arrives as pfcp_response.",
        vec![],
        json!({"type":"pfcp_heartbeat"}),
    )
}

fn establish() -> ActionDefinition {
    action(
        "pfcp_establish_session",
        "Ask the UPF for a session. Node ID and the CP F-SEID (a new session id) are added; give the rules as IEs.",
        vec![ies_param("create_pdr, create_far, create_urr, create_qer …, e.g. {\"create_pdr\": [{\"pdr_id\": 1, \"precedence\": 255, \"pdi\": {\"source_interface\": \"access\", \"f_teid\": {\"choose\": true}}, \"far_id\": 1}], \"create_far\": [{\"far_id\": 1, \"apply_action\": [\"FORW\"], \"forwarding_parameters\": {\"destination_interface\": \"core\"}}]}")],
        json!({"type":"pfcp_establish_session","ies":{"create_pdr":[{"pdr_id":1,"precedence":255,"pdi":{"source_interface":"access","f_teid":{"choose":true}},"far_id":1}],
               "create_far":[{"far_id":1,"apply_action":["FORW"],"forwarding_parameters":{"destination_interface":"core"}}]}}),
    )
}

fn modify() -> ActionDefinition {
    action(
        "pfcp_modify_session",
        "Modify an established session (update_far, update_pdr, create_* / remove_* IEs).",
        vec![
            p(
                "cp_seid",
                "number",
                "The session, by the id this client gave it (pfcp_response's cp_seid)",
                true,
            ),
            ies_param(
                "e.g. {\"update_far\": {\"far_id\": 2, \"apply_action\": [\"BUFF\", \"NOCP\"]}}",
            ),
        ],
        json!({"type":"pfcp_modify_session","cp_seid":1,"ies":{"update_far":{"far_id":1,"apply_action":["DROP"]}}}),
    )
}

fn delete() -> ActionDefinition {
    action(
        "pfcp_delete_session",
        "Delete an established session.",
        vec![p(
            "cp_seid",
            "number",
            "The session, by the id this client gave it",
            true,
        )],
        json!({"type":"pfcp_delete_session","cp_seid":1}),
    )
}

fn release() -> ActionDefinition {
    action(
        "pfcp_release_association",
        "Release the association (Node ID added).",
        vec![],
        json!({"type":"pfcp_release_association"}),
    )
}

fn respond() -> ActionDefinition {
    action(
        "pfcp_respond",
        "Answer a request the UPF sent (pfcp_request), e.g. a Session Report Request.",
        vec![
            p(
                "sequence",
                "number",
                "The request's sequence number, from pfcp_request",
                true,
            ),
            p(
                "cause",
                "string",
                "request_accepted (default) or a rejection cause",
                false,
            ),
            ies_param("IEs to add to the response"),
        ],
        json!({"type":"pfcp_respond","sequence":1,"cause":"request_accepted"}),
    )
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Stop the client (no Association Release is sent).",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        associate(),
        heartbeat(),
        establish(),
        modify(),
        delete(),
        release(),
        respond(),
        disconnect(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(id, description, establish().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_ready",
        "The client is ready to talk to the UPF; associate first.",
        vec![
            p("upf", "string", "The UPF's address and port", true),
            p("node_id", "object", "This SMF's Node ID", true),
        ],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_response",
        "The UPF answered a request.",
        vec![
            p(
                "request",
                "string",
                "The request it answers, e.g. session_establishment_request",
                true,
            ),
            p(
                "message",
                "string",
                "The response, e.g. session_establishment_response",
                true,
            ),
            p(
                "cause",
                "string",
                "The response's cause, e.g. request_accepted",
                false,
            ),
            p(
                "cp_seid",
                "number",
                "The session, for session messages",
                false,
            ),
            p("up_seid", "number", "The UPF's id for that session", false),
            p("ies", "object", "The response's IEs keyed by name", true),
        ],
    )
});

pub static TIMEOUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_timeout",
        "A request went unanswered after its retransmissions.",
        vec![
            p(
                "request",
                "string",
                "The request that went unanswered",
                true,
            ),
            p("sequence", "number", "Its sequence number", true),
        ],
    )
});

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "pfcp_request",
        "The UPF sent a request (other than a heartbeat, which is answered automatically). Answer with pfcp_respond.",
        vec![
            p("message", "string", "The request, e.g. session_report_request", true),
            p("sequence", "number", "Its sequence number, for pfcp_respond", true),
            p("cp_seid", "number", "The session it is about, if any", false),
            p("ies", "object", "Its IEs keyed by name", true),
        ],
    )
});

pub fn cp_seid(v: &Value) -> Result<u64> {
    v["cp_seid"].as_u64().context("cp_seid is required")
}

pub fn check(v: &Value) -> Result<()> {
    let ies = v.get("ies").unwrap_or(&Value::Null);
    match v["type"].as_str().unwrap_or_default() {
        "pfcp_associate" | "pfcp_establish_session" | "pfcp_modify_session" | "pfcp_respond" => {
            wire::encode(5, None, 0, ies)?;
        }
        "pfcp_heartbeat" | "pfcp_delete_session" | "pfcp_release_association" => {}
        other => bail!("Unknown PFCP client action {other:?}"),
    }
    if matches!(
        v["type"].as_str(),
        Some("pfcp_modify_session" | "pfcp_delete_session")
    ) {
        cp_seid(v)?;
    }
    if v["type"] == "pfcp_respond" {
        v["sequence"]
            .as_u64()
            .context("pfcp_respond needs the request's sequence")?;
        if let Some(c) = v["cause"].as_str() {
            wire::cause_code(c)?;
        }
    }
    Ok(())
}

impl Protocol for PfcpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "PFCP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>PFCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "pfcp",
            "pfcp client",
            "smf",
            "n4",
            "session management function",
        ]
    }
    fn description(&self) -> &'static str {
        "PFCP control plane (an SMF on the 5G N4 interface): associates with a UPF and establishes, modifies and deletes sessions"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            TIMEOUT_EVENT.clone(),
            REQUEST_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "node_id".into(),
                type_hint: "string".into(),
                description: "This SMF's Node ID: an IPv4 address or an FQDN (default: the address it sends from)".into(),
                required: false,
                example: json!("smf.example.net"),
                default: None,
            },
            ParameterDefinition {
                name: "local_port".into(),
                type_hint: "number".into(),
                description: "UDP port to send from and listen on (default: an ephemeral port; 8805 to be reachable where a UPF expects an SMF)".into(),
                required: false,
                example: json!(8805),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's PFCP codec (src/server/pfcp/wire.rs) as the CP function: sequence numbers, retransmission (T1 3 s, N1 3), a session table mapping its CP SEIDs to the UPF's SEIDs, heartbeats from the UPF answered in Rust, other UPF requests handed to the model")
            .llm_control("When to associate and heartbeat, which sessions to establish with which PDRs/FARs/URRs/QERs, how to modify and delete them, and how to answer the UPF's requests")
            .e2e_testing("tests/client/pfcp: wmnsk/go-pfcp as the UPF, which decodes every request NetGet sends and heartbeats NetGet back")
            .notes("One UPF per client. The model writes rule IEs as JSON; Node ID, F-SEID and Recovery Time Stamp are added in Rust.")
            .max_inbound_bytes(wire::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Associate with the UPF at 192.0.2.2 and open a session for UE 10.60.0.1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"pfcp","remote_addr":"127.0.0.1:8805",
            "instruction":"Associate, then establish one session with an uplink PDR that asks for an F-TEID"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"pfcp_ready","handler":{"type":"static","actions":[associate().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"pfcp_response","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'pfcp_establish_session','ies':{'create_pdr':{'pdr_id':1,'precedence':255,'pdi':{'source_interface':'access','f_teid':{'choose':True}},'far_id':1},'create_far':{'far_id':1,'apply_action':['FORW'],'forwarding_parameters':{'destination_interface':'core'}}}}] if e['request']=='association_setup_request' else []}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Client for PfcpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
