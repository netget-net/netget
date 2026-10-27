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
pub const PDU_SESSION_REQUEST: &str = "ngap_pdu_session_request";
pub const PDU_SESSION_RELEASE: &str = "ngap_pdu_session_release";
pub const PDU_SESSION_MODIFICATION: &str = "ngap_pdu_session_modification";
pub const UE_CONTEXT_RELEASE_REQUEST: &str = "ngap_ue_context_release_request";
pub const SERVICE_REQUEST: &str = "ngap_service_request";

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
            PDU_SESSION_REQUEST,
            "Ask for a PDU session for a registered UE (one this gNB holds the subscriber's \
             credentials for, after ngap_ue_registered). Rust sends the protected 5GSM PDU \
             Session Establishment Request (SSC mode 1, the PDU session type you name), answers \
             the AMF's PDU Session Resource Setup with a downlink tunnel, and raises \
             ngap_pdu_session_established.",
            vec![
                p(
                    "ran_ue_ngap_id",
                    "number",
                    "The UE, from ngap_ue_registered",
                    true,
                ),
                p(
                    "pdu_session_id",
                    "number",
                    "1-15; default the first free one",
                    false,
                ),
                p("dnn", "string", "The data network, e.g. internet", false),
                p(
                    "s_nssai",
                    "object",
                    "The slice {\"sst\": 1, \"sd\"?: \"010203\"}; default none (the AMF chooses)",
                    false,
                ),
                p(
                    "pdu_session_type",
                    "string",
                    "ipv4 (default), ipv6 or ipv4v6",
                    false,
                ),
            ],
            json!({"type": PDU_SESSION_REQUEST, "ran_ue_ngap_id": 1, "pdu_session_id": 1,
                   "dnn": "internet", "s_nssai": {"sst": 1}, "pdu_session_type": "ipv4"}),
        ),
        action(
            PDU_SESSION_RELEASE,
            "Release one of a registered UE's PDU sessions (UE-requested): Rust sends the \
             protected 5GSM PDU Session Release Request, answers the AMF's PDU Session Resource \
             Release Command and the Release Command it carries, and raises \
             ngap_pdu_session_released (or its rejected form).",
            vec![
                p("ran_ue_ngap_id", "number", "The RAN UE NGAP ID of a registered UE with credentials on this gNB, from its events", true),
                p(
                    "pdu_session_id",
                    "number",
                    "The session to release (1-15)",
                    true,
                ),
                p(
                    "cause",
                    "string",
                    "5GSM cause, default regular_deactivation",
                    false,
                ),
            ],
            json!({"type": PDU_SESSION_RELEASE, "ran_ue_ngap_id": 1, "pdu_session_id": 1,
                   "cause": "regular_deactivation"}),
        ),
        action(
            PDU_SESSION_MODIFICATION,
            "Ask to modify one of a registered UE's PDU sessions: Rust sends the protected 5GSM \
             PDU Session Modification Request (a requested QoS flow description for the default \
             flow carrying five_qi), answers the AMF's PDU Session Resource Modify Request and \
             the Modification Command (Modification Complete), and raises \
             ngap_pdu_session_modified with what the network decided.",
            vec![
                p("ran_ue_ngap_id", "number", "The RAN UE NGAP ID of a registered UE with credentials on this gNB, from its events", true),
                p("pdu_session_id", "number", "The session (1-15)", true),
                p(
                    "five_qi",
                    "number",
                    "The 5QI asked for on the default QoS flow (1-255)",
                    false,
                ),
            ],
            json!({"type": PDU_SESSION_MODIFICATION, "ran_ue_ngap_id": 1, "pdu_session_id": 1,
                   "five_qi": 8}),
        ),
        action(
            UE_CONTEXT_RELEASE_REQUEST,
            "Ask the AMF to release a UE's N2 context (UE Context Release Request), e.g. after \
             inactivity. When the AMF's Release Command comes, Rust completes it and a registered \
             UE goes CM-IDLE, keeping its security context and sessions \
             (ngap_ue_context_release with cm_state idle); bring it back with \
             ngap_service_request.",
            vec![
                p("ran_ue_ngap_id", "number", "The RAN UE NGAP ID of a registered UE with credentials on this gNB, from its events", true),
                p(
                    "cause",
                    "string",
                    "NGAP cause group/value, default radioNetwork/user-inactivity",
                    false,
                ),
            ],
            json!({"type": UE_CONTEXT_RELEASE_REQUEST, "ran_ue_ngap_id": 1,
                   "cause": "radioNetwork/user-inactivity"}),
        ),
        action(
            SERVICE_REQUEST,
            "Bring an idle UE back (CM-IDLE to CM-CONNECTED): Rust gives it a new RAN UE NGAP \
             ID and sends an Initial UE Message with its 5G-S-TMSI and an integrity-protected \
             Service Request, verifies the AMF's K_gNB and Service Accept, sets up the sessions' \
             tunnels and raises ngap_service_accepted (or ngap_service_rejected). An idle UE the \
             AMF pages answers by itself; you are told with trigger paging.",
            vec![
                p("supi", "string", "The idle subscriber, imsi-<digits>", true),
                p(
                    "service_type",
                    "string",
                    "data (default), signalling or mobile_terminated",
                    false,
                ),
                p(
                    "pdu_session_ids",
                    "array",
                    "Sessions with uplink data waiting (Uplink data status); default every \
                     session the UE holds for data, none otherwise",
                    false,
                ),
            ],
            json!({"type": SERVICE_REQUEST, "supi": "imsi-001010000000001",
                   "service_type": "data", "pdu_session_ids": [1]}),
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
        "The AMF released a UE's N2 context (UE Context Release Command). NetGet already \
         answered with UE Context Release Complete. cm_state idle: a registered UE with \
         credentials is CM-IDLE, keeping its security context and pdu_sessions; bring it back \
         with ngap_service_request {supi}, and it answers the AMF's paging by itself. \
         cm_state released: the UE is gone from this gNB.",
        vec![
            p("amf_ue_ngap_id", "number", "The released UE", true),
            p("cm_state", "string", "idle or released", true),
            p("supi", "string", "imsi-<digits>, for an idle UE", false),
            p(
                "cause",
                "object",
                "The AMF's NGAP cause for the release, {\"group\", \"value\"}",
                true,
            ),
        ],
    )
});

pub static REGISTERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_ue_registered",
        "A UE with credentials on this gNB completed 5G-AKA, NAS security and registration: the \
         AMF accepted it and Rust sent Registration Complete. guti, allowed_nssai and tai_list \
         are what the AMF assigned; k_gnb_verified says whether the AMF's K_gNB equals the one \
         this UE derived. Ask for a session with ngap_pdu_session_request.",
        vec![
            p("ran_ue_ngap_id", "number", "This gNB's id for the UE", true),
            p("supi", "string", "The registered subscriber's permanent identity, imsi-<digits> (the one this gNB holds credentials for)", true),
            p("guti", "object", "The 5G-GUTI the AMF assigned", true),
            p("allowed_nssai", "array", "The slices the UE may use", true),
            p(
                "k_gnb_verified",
                "boolean",
                "Whether the AMF's K_gNB matched this UE's",
                true,
            ),
        ],
    )
});

pub static PDU_SESSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_pdu_session_established",
        "The AMF answered a PDU session request: result accepted (with ue_ipv4, dnn, s_nssai, \
         QoS flows, session AMBR and the UPF's uplink tunnel) or rejected (with the 5GSM \
         cause).",
        vec![
            p("ran_ue_ngap_id", "number", "This gNB's id for the UE", true),
            p(
                "pdu_session_id",
                "number",
                "The PDU session identity (1-15) the request asked for, as the AMF answered it",
                true,
            ),
            p("result", "string", "accepted or rejected", true),
            p(
                "ue_ipv4",
                "string",
                "The address the network assigned",
                false,
            ),
        ],
    )
});

pub static PDU_RELEASED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_pdu_session_released",
        "A PDU session ended: result released (Rust answered the network's Release Command \
         with Release Complete and dropped the tunnel; requested_by ue when it answered this \
         UE's request, network otherwise) or rejected (the network refused the UE's release; \
         the session stays). cause is the 5GSM cause.",
        vec![
            p("ran_ue_ngap_id", "number", "This gNB's id for the UE", true),
            p("pdu_session_id", "number", "The session (1-15)", true),
            p("result", "string", "released or rejected", true),
            p("requested_by", "string", "Who asked for the release: \"ue\" (this UE's request, which the model made) or \"network\" (the AMF released it unasked)", true),
            p(
                "cause",
                "object",
                "{\"value\", \"name\"} of the 5GSM cause",
                false,
            ),
        ],
    )
});

pub static PDU_MODIFIED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_pdu_session_modified",
        "The network answered a modification: result modified (Rust answered the \
         Modification Command with Modification Complete and the AMF's Resource Modify \
         Request with the session's QoS flows) with the five_qi and session_ambr_kbps the \
         command carried, if any; or rejected with the 5GSM cause. requested_five_qi is what \
         the UE asked for.",
        vec![
            p("ran_ue_ngap_id", "number", "This gNB's id for the UE", true),
            p("pdu_session_id", "number", "The session (1-15)", true),
            p("result", "string", "modified or rejected", true),
            p(
                "five_qi",
                "number",
                "The default flow's 5QI the command set",
                false,
            ),
            p(
                "session_ambr_kbps",
                "object",
                "{\"uplink\", \"downlink\"} when the command set it",
                false,
            ),
            p(
                "cause",
                "object",
                "{\"value\", \"name\"} of the 5GSM cause",
                false,
            ),
        ],
    )
});

pub static SERVICE_ACCEPTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_service_accepted",
        "An idle UE is back: the AMF verified its Service Request and answered with an Initial \
         Context Setup and a protected Service Accept. trigger is ue (ngap_service_request) or \
         paging (Rust answered the AMF's Paging). pdu_session_status is the sessions the UE \
         still holds (any the network no longer has were released locally, released_locally), \
         user_plane_sessions those whose tunnels the AMF set up again, k_gnb_verified whether \
         the AMF's K_gNB equals the one this UE derived from the Service Request's COUNT. Use \
         the new ran_ue_ngap_id from now on.",
        vec![
            p("ran_ue_ngap_id", "number", "The UE's new RAN UE NGAP ID", true),
            p("supi", "string", "The subscriber whose UE this is, e.g. imsi-001010000000001", true),
            p("service_type", "string", "data, signalling or mobile_terminated", true),
            p("trigger", "string", "What brought the UE back: \"ue\" (an ngap_service_request) or \"paging\" (the AMF paged it and Rust answered)", true),
            p("pdu_session_status", "array", "PDU session ids the UE holds", true),
            p("user_plane_sessions", "array", "PDU session ids whose tunnels are set up", true),
            p("k_gnb_verified", "boolean", "Whether the AMF's K_gNB matched this UE's", true),
        ],
    )
});

pub static SERVICE_REJECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "ngap_service_rejected",
        "The AMF refused an idle UE's Service Request (Service Reject with a 5GMM cause). \
         still_registered is false for #9/#10: the network no longer knows the UE and it must \
         register again (ngap_initial_ue_message).",
        vec![
            p("supi", "string", "The subscriber whose UE this is, e.g. imsi-001010000000001", true),
            p(
                "cause",
                "object",
                "{\"value\", \"name\"} of the 5GMM cause",
                true,
            ),
            p("trigger", "string", "What brought the UE back: \"ue\" (an ngap_service_request) or \"paging\" (the AMF paged it and Rust answered)", true),
            p(
                "still_registered",
                "boolean",
                "Whether the UE stays registered (idle)",
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
        PDU_SESSION_REQUEST => {
            codec::json_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
            if let Some(p) = codec::json_opt_u64(v, "pdu_session_id", 15)? {
                anyhow::ensure!(p >= 1, "pdu_session_id must be 1..15");
            }
            if let Some(s) = v.get("s_nssai").filter(|s| !s.is_null()) {
                nas::Snssai::from_json(s).map_err(|e| anyhow!(e))?;
            }
            if let Some(d) = v.get("dnn").and_then(Value::as_str) {
                crate::server::gtp::codec::encode_apn(d).map_err(|e| anyhow!("dnn: {e}"))?;
            }
            super::ue::session_type_code(v)?;
        }
        PDU_SESSION_RELEASE => {
            codec::json_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
            anyhow::ensure!(
                codec::json_u64(v, "pdu_session_id", 15)? >= 1,
                "pdu_session_id must be 1..15"
            );
            if let Some(c) = v.get("cause").filter(|c| !c.is_null()) {
                crate::server::ngap::sm::parse_cause(c).map_err(|e| anyhow!(e))?;
            }
        }
        PDU_SESSION_MODIFICATION => {
            codec::json_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
            anyhow::ensure!(
                codec::json_u64(v, "pdu_session_id", 15)? >= 1,
                "pdu_session_id must be 1..15"
            );
            if let Some(q) = codec::json_opt_u64(v, "five_qi", 255)? {
                anyhow::ensure!(q >= 1, "five_qi must be 1..255");
            }
        }
        UE_CONTEXT_RELEASE_REQUEST => {
            codec::json_u64(v, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
            if let Some(c) = v.get("cause").filter(|c| !c.is_null()) {
                codec::Cause::from_json(c)?;
            }
        }
        SERVICE_REQUEST => {
            crate::server::ngap::subscribers::supi_digits(
                v.get("supi")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("supi is required"))?,
            )
            .map_err(|e| anyhow!(e))?;
            super::procedures::service_type_code(v)?;
            super::procedures::psi_array(v)?;
        }
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
        "NGAP gNB (5G N2): sets up N2 with an AMF and registers UEs with 5G-AKA, NAS security and PDU sessions"
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
            REGISTERED_EVENT.clone(),
            PDU_SESSION_EVENT.clone(),
            PDU_RELEASED_EVENT.clone(),
            PDU_MODIFIED_EVENT.clone(),
            SERVICE_ACCEPTED_EVENT.clone(),
            SERVICE_REJECTED_EVENT.clone(),
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
            param("supi", "string", "The subscriber whose credentials follow (imsi-<digits>). A UE brought in with a null-scheme SUCI naming it runs 5G-AKA, NAS security, registration and PDU sessions in Rust", json!("imsi-001010000000001"), None),
            param("subscriber_key", "string", "The subscriber's permanent key K, 32 hex digits. Redacted wherever parameters are shown; never in an event", json!("465B5CE8B199B49FAA5F0A2EE238A6BC"), None),
            param("subscriber_opc", "string", "The operator key OPc, 32 hex digits (or give subscriber_op)", json!("E8ED289DEBA952E4283B54E88E6183CA"), None),
            param("subscriber_op", "string", "The operator key OP, 32 hex digits, when OPc is not known", json!("CDC202D5123E20F62B6D676AC72CB318"), None),
            param("sqn", "number", "The USIM's highest accepted SQN at start (48 bits)", json!(0), None),
            param("imeisv", "string", "The IMEISV reported when the AMF asks, 16 digits", json!("4370816125816151"), Some(json!(super::ue::DEFAULT_IMEISV))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The AMF role's APER codec, 5GMM/5GSM and NAS security (src/server/ngap) as a gNB with a UE: SCTP association (PPID 60, stream 0/1) or the labelled lab TCP framing, NG Setup from the startup parameters on connect, RAN UE NGAP ID allocation; for a UE whose SUCI names the configured subscriber, the UE side of 5G-AKA (AUTN verified, RES*, SQN and AUTS), the security mode procedure (128-NIA1/2/3 with NEA0/1/2/3, replayed capabilities checked), Registration Complete, the Initial Context Setup answered with K_gNB compared against the UE's own, PDU Session Establishment (IPv4, IPv6, IPv4v6) with the resource setup answered (a downlink tunnel per session), UE- and network-requested PDU session release (Release Complete, PDU Session Resource Release Response) and modification (Modification Complete, PDU Session Resource Modify Response), CM-IDLE (the UE's security context, sessions and 5G-S-TMSI kept per SUPI when the AMF releases its context), the Service Request (FiveG-S-TMSI in the Initial UE Message, integrity protected with the whole request ciphered in a NAS message container at the same COUNT, K_gNB from its COUNT compared, the Service Accept's PDU session status applied) and the answer to NGAP Paging. UE Context Release Complete and NG Reset Acknowledge answered in Rust")
            .llm_control("Which UEs to bring in and with what Registration Request (SUCI or 5G-GUTI), how a UE without credentials answers identity and authentication requests, when a registered UE asks for a PDU session (DNN, slice, PDU session type), releases or modifies one (5QI), when the gNB asks the AMF to release a UE's context, and when an idle UE comes back with a Service Request (service type, uplink data status). Keys, MACs, COUNTs, the security procedures and the answer to paging are Rust's and never reach the model")
            .e2e_testing("tests/client/ngap: a whole Open5GS 2.8 core (MongoDB, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, SMF, UPF, AMF) over real SCTP on Linux registers the model's UE after 5G-AKA, hands the gNB a K_gNB equal to the UE's own, creates the PDU session the SMF logs, releases the session the model releases (AMF N1/N2-RELEASED, SMF Removed Session), gives an IPv4v6 session whose IPv6 address the SMF logs, releases the UE's context on the gNB's request, takes the model's Service Request back with a K_gNB equal to the UE's, and answers its modification request; Open5GS's AMF alone identifies a UE and refuses a foreign PLMN; NetGet's own AMF over the lab transport (circular) for the whole life including paging, under NIA2/NEA0, NIA1/NEA1 and NIA3/NEA3; a canned AMF over the lab transport for bounds and follow-up depth; tshark's ngap and nas-5gs dissectors read the captures")
            .notes("Beta on the client bar: the peer is a whole Open5GS 2.8 core (a third-party server, not a crate NetGet links), the test fails rather than skips without it, the session is real (5G-AKA verified by Open5GS's AUSF, registration, PDU sessions the SMF allocates and removes, a Service Request Open5GS verifies), and the model's actions are asserted from Open5GS's own logs. The evidence runs only where SCTP exists (Linux, the ngap pair job). Paging is exercised only against NetGet's own AMF (circular). The UE side implements 5G-AKA only and null-scheme SUCI only. The gNB runs no user plane: it answers the resource setup with a downlink tunnel address but carries no packets. Not built: handover, UE context modification, RAN configuration update, Xn, more than one AMF per client, a requested QoS rule (the modification request carries only a QoS flow description). Handler chains stop after 8 follow-ups per UE.")
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
