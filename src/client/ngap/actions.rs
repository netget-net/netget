//! What the model does as a gNB on N2: bring a UE in with an Initial UE Message carrying a NAS
//! Registration Request it describes in fields, answer the AMF's NAS (identity, authentication)
//! with Uplink NAS Transport, release UEs and report errors. NG Setup is performed by Rust on
//! connect from the startup parameters, the way a real gNB does it from its configuration.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::ngap::{codec, nas};
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const INITIAL_UE: &str = "ngap_initial_ue_message";
pub const UPLINK_NAS: &str = "ngap_uplink_nas_transport";
pub const ERROR_INDICATION: &str = "ngap_error_indication";
pub const NG_SETUP: &str = "ngap_ng_setup";

/// Defaults for the gNB's NG Setup, used when the startup parameters name none.
pub const DEFAULT_MCC: &str = "001";
pub const DEFAULT_MNC: &str = "01";
pub const DEFAULT_GNB_ID: u64 = 1;
pub const DEFAULT_GNB_ID_BITS: u64 = 32;
pub const DEFAULT_TAC: u64 = 1;
pub const DEFAULT_SST: u64 = 1;
pub const DEFAULT_NR_CELL_ID: u64 = 0x10;
pub const DEFAULT_RAN_NODE_NAME: &str = "netget-gnb";
pub const DEFAULT_PAGING_DRX: &str = "v128";
pub const DEFAULT_RRC_CAUSE: &str = "mo-Signalling";

#[derive(Default)]
pub struct NgapClientProtocol;
impl NgapClientProtocol {
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

fn action(
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
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("-> NGAP {name}"))
                .with_debug(format!("NGAP client {name}")),
        ),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            INITIAL_UE,
            "Bring a UE onto N2: an Initial UE Message carrying a NAS message Rust builds from \
             fields. A new RAN UE NGAP ID is allocated unless you give one. The UE's location is \
             this gNB's cell and tracking area.",
            vec![
                p(
                    "nas",
                    "object",
                    "Usually {\"message\": \"registration_request\", \"registration_type\": \
                     \"initial\", \"mobile_identity\": {\"type\": \"suci\", \"plmn\": {\"mcc\": \
                     \"001\", \"mnc\": \"01\"}, \"routing_indicator\": \"0000\", \"msin\": \
                     \"0000000001\"}} (null-scheme SUCI), or a 5G-GUTI identity {\"type\": \
                     \"5g_guti\", \"plmn\", \"amf_region_id\", \"amf_set_id\", \"amf_pointer\", \
                     \"tmsi\"}",
                    true,
                ),
                p(
                    "ran_ue_ngap_id",
                    "number",
                    "Default: the next free one",
                    false,
                ),
                p(
                    "rrc_establishment_cause",
                    "string",
                    "mo-Signalling (default), mo-Data, emergency, mt-Access, …",
                    false,
                ),
            ],
            json!({"type": INITIAL_UE, "nas": {"message": "registration_request",
                   "registration_type": "initial",
                   "mobile_identity": {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"},
                                       "routing_indicator": "0000", "msin": "0000000001"}}}),
        ),
        action(
            UPLINK_NAS,
            "Answer the AMF for a UE (Uplink NAS Transport). nas is structured: identity_response \
             {mobile_identity}, authentication_failure {cause: mac_failure | synch_failure | \
             non_5g_authentication_unacceptable}, registration_complete, \
             deregistration_request_ue_originating {mobile_identity, switch_off}, \
             security_mode_reject {cause}, 5gmm_status {cause}.",
            vec![
                p(
                    "amf_ue_ngap_id",
                    "number",
                    "From the AMF's ngap_downlink_nas_transport",
                    true,
                ),
                p("ran_ue_ngap_id", "number", "The UE's RAN UE NGAP ID", true),
                p(
                    "nas",
                    "object",
                    "e.g. {\"message\": \"identity_response\", \"mobile_identity\": {...}}",
                    true,
                ),
            ],
            json!({"type": UPLINK_NAS, "amf_ue_ngap_id": 1, "ran_ue_ngap_id": 1,
                   "nas": {"message": "authentication_failure", "cause": "mac_failure"}}),
        ),
        action(
            ERROR_INDICATION,
            "Report an error to the AMF (Error Indication), optionally for one UE.",
            vec![
                p(
                    "cause",
                    "string",
                    "group/value, e.g. protocol/semantic-error",
                    false,
                ),
                p(
                    "amf_ue_ngap_id",
                    "number",
                    "The UE concerned, if any",
                    false,
                ),
                p(
                    "ran_ue_ngap_id",
                    "number",
                    "The UE concerned, if any",
                    false,
                ),
            ],
            json!({"type": ERROR_INDICATION, "cause": "protocol/semantic-error"}),
        ),
        action(
            NG_SETUP,
            "Repeat NG Setup with this gNB's configuration (it is done on connect already).",
            vec![],
            json!({"type": NG_SETUP}),
        ),
        action(
            "disconnect",
            "Close the association to the AMF.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, actions()[0].example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        ev(
        "ngap_connected",
        "NG Setup succeeded: the AMF admitted this gNB. Its name, GUAMIs and supported PLMNs and \
         slices are given. Bring a UE in with ngap_initial_ue_message.",
        vec![
            p("amf_name", "string", "The name the AMF gave in its NG Setup Response", true),
            p("served_guami", "array", "The AMF's GUAMIs", true),
            p("plmn_support", "array", "PLMNs and slices it supports", true),
            p("transport", "string", "sctp, or the non-standard lab tcp framing", true),
        ],
    )
    });

pub static DOWNLINK_NAS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_downlink_nas_transport",
        "The AMF sent a NAS message to a UE. nas is decoded: identity_request {identity_type}, \
         authentication_request {ngksi, rand, autn}, registration_reject {cause}, …. Answer with \
         ngap_uplink_nas_transport using the ids given.",
        vec![
            p("amf_ue_ngap_id", "number", "The AMF's id for the UE", true),
            p("ran_ue_ngap_id", "number", "This gNB's id for the UE", true),
            p("nas", "object", "The decoded 5GMM message", true),
        ],
    )
});

pub static RELEASE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_ue_context_release",
        "The AMF released a UE (UE Context Release Command). NetGet already answered with UE \
         Context Release Complete; the UE is gone from this gNB.",
        vec![
            p("amf_ue_ngap_id", "number", "The released UE", true),
            p(
                "cause",
                "object",
                "The AMF's NGAP cause for the release, {\"group\", \"value\"}",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_amf_error",
        "The AMF sent an Error Indication or NG Reset, or a PDU NetGet does not implement. \
         Observational.",
        vec![
            p("message", "string", "What arrived: error_indication, ng_reset, or the name of a PDU NetGet does not implement", true),
            p("cause", "object", "The NGAP cause the AMF gave, {\"group\", \"value\"}, when it gave one", false),
        ],
    )
});

pub fn plmn(ctx: &ConnectContext) -> Result<codec::Plmn> {
    let get = |k: &str, d: &str| -> Result<String> {
        Ok(ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| d.to_string()))
    };
    Ok(codec::Plmn::from_json(
        &json!({"mcc": get("mcc", DEFAULT_MCC)?, "mnc": get("mnc", DEFAULT_MNC)?}),
    )?)
}

/// Validate an action without sending it.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        INITIAL_UE => {
            nas::encode(v.get("nas").unwrap_or(&Value::Null), nas::UPLINK_MESSAGES)
                .map_err(|e| anyhow!(e))?;
            codec::json_opt_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        }
        UPLINK_NAS => {
            codec::json_u64(v, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
            codec::json_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
            nas::encode(v.get("nas").unwrap_or(&Value::Null), nas::UPLINK_MESSAGES)
                .map_err(|e| anyhow!(e))?;
        }
        ERROR_INDICATION => {
            if let Some(c) = v.get("cause").filter(|c| !c.is_null()) {
                codec::Cause::from_json(c)?;
            }
        }
        NG_SETUP => {}
        other => bail!("Unknown NGAP client action {other:?}"),
    }
    Ok(())
}

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

impl Protocol for NgapClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NGAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>SCTP>NGAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ngap", "ngap client", "gnb", "n2", "5g ran"]
    }
    fn description(&self) -> &'static str {
        "NGAP gNB (5G N2): sets up N2 with an AMF and brings UEs in with NAS registration"
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
            DOWNLINK_NAS_EVENT.clone(),
            RELEASE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param("transport", "string", "\"sctp\" (default, TS 38.412) or \"tcp\" — NON-STANDARD length-prefixed framing for local work, which no real AMF speaks", json!("sctp"), None),
            param("mcc", "string", "The gNB's PLMN: mobile country code, three digits", json!("001"), Some(json!(DEFAULT_MCC))),
            param("mnc", "string", "The gNB's PLMN: mobile network code, two or three digits", json!("01"), Some(json!(DEFAULT_MNC))),
            param("gnb_id", "number", "The gNB ID sent in NG Setup (its GlobalRANNodeID), gnb_id_bits wide", json!(1), Some(json!(DEFAULT_GNB_ID))),
            param("gnb_id_bits", "number", "Length of the gNB ID in bits, 22-32", json!(32), Some(json!(DEFAULT_GNB_ID_BITS))),
            param("tac", "number", "The tracking area code served (24 bits)", json!(1), Some(json!(DEFAULT_TAC))),
            param("sst", "number", "Slice/service type broadcast (0-255)", json!(1), Some(json!(DEFAULT_SST))),
            param("sd", "string", "Slice differentiator, six hex digits (default: none)", json!("010203"), None),
            param("nr_cell_id", "number", "The NR cell identity UEs are reported in (36 bits)", json!(16), Some(json!(DEFAULT_NR_CELL_ID))),
            param("ran_node_name", "string", "The RAN node name sent in NG Setup", json!("netget-gnb"), Some(json!(DEFAULT_RAN_NODE_NAME))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The AMF role's APER codec and 5GMM subset (src/server/ngap) as a gNB: SCTP association (PPID 60, stream 0/1) or the labelled lab TCP framing, NG Setup from the startup parameters on connect, RAN UE NGAP ID allocation, UE Context Release Complete and NG Reset Acknowledge answered in Rust")
            .llm_control("Which UEs to bring in and with what NAS Registration Request (SUCI or 5G-GUTI, registration type), and how each UE answers the AMF's identity and authentication requests")
            .e2e_testing("tests/client/ngap: Open5GS's AMF (open5gs-amfd) over real SCTP on Linux accepts NG Setup and processes the model's Registration Request; a canned AMF over the lab transport for bounds, follow-up depth and the model's actions")
            .notes("Experimental: one independent AMF (Open5GS), runnable only where SCTP exists. No NAS security: RES* cannot be computed without a subscriber key, so registration ends at authentication. No PDU sessions or user plane. Handler chains stop after 8 follow-ups.")
            .max_inbound_bytes(codec::MAX_PDU_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect a gNB for PLMN 001-01 to the AMF at 127.0.0.5 and register one UE with SUCI MSIN 0000000001"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "ngap", "remote_addr": "127.0.0.5:38412",
            "startup_params": {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1},
            "instruction": "Register one UE with a null-scheme SUCI (MSIN 0000000001) and answer the AMF's identity request with the same SUCI"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "ngap_connected", "handler": {"type": "static", "actions": [actions()[0].example.clone()]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']; t=i['event_type_id']\nsuci={'type':'suci','plmn':{'mcc':'001','mnc':'01'},'routing_indicator':'0000','msin':'0000000001'}\na=[]\nif t=='ngap_connected': a=[{'type':'ngap_initial_ue_message','nas':{'message':'registration_request','mobile_identity':suci}}]\nelif t=='ngap_downlink_nas_transport' and e['nas'].get('message')=='identity_request': a=[{'type':'ngap_uplink_nas_transport','amf_ue_ngap_id':e['amf_ue_ngap_id'],'ran_ue_ngap_id':e['ran_ue_ngap_id'],'nas':{'message':'identity_response','mobile_identity':suci}}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Client for NgapClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
