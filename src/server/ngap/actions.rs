//! NGAP AMF actions, events and metadata.
//!
//! Every `send_*` action validates its fields against the 38.413 constraints and returns the
//! fully encoded PDU as [`ActionResult::Output`]; the session reads the procedure and UE id back
//! off those octets to apply the fail-closed rule. Nothing about the encoding depends on session
//! state, so the same octets come out whether the model, a static handler or the dashboard's
//! "message this peer" asked for them.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::codec::{self, Cause};
use super::nas;

pub struct NgapProtocol;

impl Default for NgapProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl NgapProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn list<'a>(action: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    action
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be a list"))
}

fn cause_field(action: &Value, field: &str, default: Option<&str>) -> Result<Cause> {
    match action.get(field) {
        Some(v) if !v.is_null() => Ok(Cause::from_json(v)?),
        _ => match default {
            Some(d) => Ok(Cause::from_json(&json!(d))?),
            None => Err(anyhow!(
                "{field} is required, e.g. \"misc/unknown-PLMN-or-SNPN\""
            )),
        },
    }
}

/// Encode the `nas` object of a downlink action into a NAS-PDU.
pub fn downlink_nas(action: &Value) -> Result<Vec<u8>> {
    let v = action.get("nas").context(
        "nas is required: {\"message\": \"registration_reject\", \"cause\": \"illegal_ue\"}",
    )?;
    nas::encode(v, nas::DOWNLINK_MESSAGES).map_err(|e| anyhow!(e))
}

impl NgapProtocol {
    fn ng_setup_response(&self, a: &Value) -> Result<ActionResult> {
        let name = a
            .get("amf_name")
            .and_then(Value::as_str)
            .context("amf_name is required")?;
        let capacity = codec::json_opt_u64(a, "relative_amf_capacity", 255)?.unwrap_or(255);
        Ok(ActionResult::Output(codec::ng_setup_response(
            name,
            list(a, "served_guami")?,
            capacity,
            list(a, "plmn_support")?,
        )?))
    }

    fn ng_setup_failure(&self, a: &Value) -> Result<ActionResult> {
        let cause = cause_field(a, "cause", None)?;
        let ttw = a.get("time_to_wait").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });
        Ok(ActionResult::Output(codec::ng_setup_failure(
            &cause,
            ttw.as_deref(),
        )?))
    }

    fn downlink_nas_transport(&self, a: &Value) -> Result<ActionResult> {
        let amf = codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let nas = downlink_nas(a)?;
        Ok(ActionResult::Output(codec::downlink_nas_transport(
            amf, ran, &nas,
        )?))
    }

    fn ue_context_release(&self, a: &Value) -> Result<ActionResult> {
        let amf = codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_opt_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let cause = cause_field(a, "cause", Some("nas/normal-release"))?;
        Ok(ActionResult::Output(codec::ue_context_release_command(
            amf, ran, &cause,
        )?))
    }

    fn error_indication(&self, a: &Value) -> Result<ActionResult> {
        let amf = codec::json_opt_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_opt_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let cause = match a.get("cause") {
            Some(v) if !v.is_null() => Some(Cause::from_json(v)?),
            _ => None,
        };
        Ok(ActionResult::Output(codec::error_indication(
            amf,
            ran,
            cause.as_ref(),
        )?))
    }

    fn ng_reset(&self, a: &Value) -> Result<ActionResult> {
        let cause = cause_field(a, "cause", Some("misc/om-intervention"))?;
        Ok(ActionResult::Output(codec::ng_reset(&cause, None)?))
    }
}

// ============================================================================
// Action definitions
// ============================================================================

const PLMN_HELP: &str = "{\"mcc\": \"001\", \"mnc\": \"01\"} — digits as strings";

fn ng_setup_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_setup_response".into(),
        description: "Admit this gNB: answer its NG Setup Request with an NG Setup Response \
                      naming this AMF, its GUAMIs and the PLMNs and slices it serves. This is the \
                      admission decision for N2 — return send_ng_setup_failure to refuse."
            .into(),
        parameters: vec![
            p("amf_name", "string", "This AMF's name, 1-150 PrintableString characters", true),
            p(
                "served_guami",
                "array",
                &format!("GUAMIs this AMF serves (1-256): [{{\"plmn\": {PLMN_HELP}, \"amf_region_id\": 0-255, \"amf_set_id\": 0-1023, \"amf_pointer\": 0-63}}]"),
                true,
            ),
            p(
                "plmn_support",
                "array",
                "PLMNs and slices supported (1-12): [{\"plmn\": {...}, \"slices\": [{\"sst\": 1, \"sd\": \"010203\"}]}] — sd is optional, six hex digits",
                true,
            ),
            p("relative_amf_capacity", "number", "0-255, default 255", false),
        ],
        example: json!({
            "type": "send_ng_setup_response",
            "amf_name": "netget-amf",
            "served_guami": [{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
            "plmn_support": [{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1}]}],
            "relative_amf_capacity": 255
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Setup Response {amf_name}")
                .with_debug("NGAP send_ng_setup_response {amf_name}"),
        ),
    }
}

fn ng_setup_failure_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_setup_failure".into(),
        description: "Refuse this gNB with an NG Setup Failure carrying a cause. The explicit \
                      refusal of N2 setup."
            .into(),
        parameters: vec![
            p(
                "cause",
                "string",
                "group/value, e.g. misc/unknown-PLMN-or-SNPN, misc/control-processing-overload, \
                 misc/om-intervention, misc/unspecified, protocol/semantic-error",
                true,
            ),
            p(
                "time_to_wait",
                "string",
                "When the gNB may retry: v1s, v2s, v5s, v10s, v20s or v60s",
                false,
            ),
        ],
        example: json!({"type": "send_ng_setup_failure", "cause": "misc/unknown-PLMN-or-SNPN", "time_to_wait": "v10s"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Setup Failure {cause}")
                .with_debug("NGAP send_ng_setup_failure cause={cause}"),
        ),
    }
}

fn downlink_nas_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_downlink_nas_transport".into(),
        description:
            "Send a NAS message to one UE in a Downlink NAS Transport. The NAS message is \
                      structured and Rust encodes it. Only what a UE accepts before NAS security \
                      exists is offered: registration_reject {cause}, identity_request \
                      {identity_type}, authentication_request {ngksi, rand?, autn? — 32 hex digits \
                      each, random when omitted; without the subscriber's key a real UE answers \
                      with authentication_failure mac_failure}, authentication_reject, \
                      service_reject {cause}, 5gmm_status {cause}."
                .into(),
        parameters: vec![
            p(
                "amf_ue_ngap_id",
                "number",
                "The UE's AMF UE NGAP ID, from the event",
                true,
            ),
            p(
                "ran_ue_ngap_id",
                "number",
                "The UE's RAN UE NGAP ID, from the event",
                true,
            ),
            p(
                "nas",
                "object",
                "e.g. {\"message\": \"registration_reject\", \"cause\": \"illegal_ue\"} or \
                 {\"message\": \"identity_request\", \"identity_type\": \"suci\"}. 5GMM causes by \
                 name: illegal_ue, plmn_not_allowed, tracking_area_not_allowed, congestion, \
                 no_network_slices_available, protocol_error_unspecified, …",
                true,
            ),
        ],
        example: json!({
            "type": "send_downlink_nas_transport",
            "amf_ue_ngap_id": 1,
            "ran_ue_ngap_id": 1,
            "nas": {"message": "registration_reject", "cause": "illegal_ue"}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Downlink NAS Transport ue={amf_ue_ngap_id}")
                .with_debug("NGAP send_downlink_nas_transport ue={amf_ue_ngap_id} nas={nas}"),
        ),
    }
}

fn release_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ue_context_release_command".into(),
        description: "Release one UE's N2 context (UE Context Release Command). The gNB answers \
                      with UE Context Release Complete, which NetGet handles."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID", true),
            p(
                "ran_ue_ngap_id",
                "number",
                "The UE's RAN UE NGAP ID (sends the pair form)",
                false,
            ),
            p(
                "cause",
                "string",
                "group/value, default nas/normal-release",
                false,
            ),
        ],
        example: json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": 1, "ran_ue_ngap_id": 1, "cause": "nas/normal-release"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP UE Context Release Command ue={amf_ue_ngap_id}")
                .with_debug("NGAP send_ue_context_release_command cause={cause}"),
        ),
    }
}

fn error_indication_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_error_indication".into(),
        description: "Report an error to the gNB with an Error Indication, optionally naming a UE."
            .into(),
        parameters: vec![
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
        example: json!({"type": "send_error_indication", "cause": "protocol/semantic-error"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Error Indication {cause}")
                .with_debug("NGAP send_error_indication cause={cause}"),
        ),
    }
}

fn ng_reset_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_reset".into(),
        description: "Reset every UE context on this N2 interface (NG Reset, reset-all). The gNB \
                      acknowledges and NetGet clears its UE table."
            .into(),
        parameters: vec![p(
            "cause",
            "string",
            "group/value, default misc/om-intervention",
            false,
        )],
        example: json!({"type": "send_ng_reset", "cause": "misc/om-intervention"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Reset {cause}")
                .with_debug("NGAP send_ng_reset cause={cause}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".into(),
        description: "Send nothing. On an NG Setup Request or Initial UE Message this is NOT an \
                      admission: NetGet answers with a refusal."
            .into(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP wait for more")
                .with_debug("NGAP wait_for_more"),
        ),
    }
}

fn response_actions() -> Vec<ActionDefinition> {
    vec![
        ng_setup_response_action(),
        ng_setup_failure_action(),
        downlink_nas_action(),
        release_action(),
        error_indication_action(),
        ng_reset_action(),
        wait_for_more_action(),
    ]
}

// ============================================================================
// Events
// ============================================================================

pub static NGAP_NG_SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_ng_setup_request",
        "A gNB sent NG Setup Request and wants to set up N2 with this AMF. global_ran_node_id \
         names it (plmn, gnb_id), supported_ta_list lists its tracking areas with the PLMNs and \
         slices broadcast in each. Reply with send_ng_setup_response to admit it, or \
         send_ng_setup_failure to refuse. Anything else — wait_for_more, no answer, a failed \
         model — is answered by NetGet with NG Setup Failure: admitting a gNB is never the \
         default.",
        ng_setup_response_action().example,
    )
    .with_alternative_example(
        json!({"type": "send_ng_setup_failure", "cause": "misc/unknown-PLMN-or-SNPN"}),
    )
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP NG Setup Request from {ran_node_name}")
            .with_debug("NGAP NG Setup Request {global_ran_node_id}")
            .with_trace("NGAP NG Setup Request: {json_pretty(.)}"),
    )
});

pub static NGAP_INITIAL_UE_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_initial_ue_message",
        "A UE's first NAS message arrived through the gNB (Initial UE Message). NetGet allocated \
         amf_ue_ngap_id; ran_ue_ngap_id is the gNB's. nas is the decoded 5GMM message — for a \
         registration_request: registration_type, ngksi and mobile_identity (a SUCI's plmn, \
         routing_indicator, protection_scheme and, for the null scheme, msin; or a 5G-GUTI). \
         Answer with send_downlink_nas_transport carrying identity_request, \
         authentication_request or registration_reject, optionally followed by \
         send_ue_context_release_command. Saying nothing makes NetGet reject the UE \
         (registration_reject protocol_error_unspecified) and release it.",
        downlink_nas_action().example,
    )
    .with_alternative_example(json!({
        "type": "send_downlink_nas_transport",
        "amf_ue_ngap_id": 1,
        "ran_ue_ngap_id": 1,
        "nas": {"message": "authentication_request", "ngksi": 0}
    }))
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Initial UE Message ue={amf_ue_ngap_id}")
            .with_debug("NGAP Initial UE Message ue={amf_ue_ngap_id} nas={nas}")
            .with_trace("NGAP Initial UE Message: {json_pretty(.)}"),
    )
});

pub static NGAP_UPLINK_NAS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_uplink_nas_transport",
        "A UE answered through the gNB (Uplink NAS Transport). nas is the decoded 5GMM message — \
         e.g. identity_response with its mobile_identity, or authentication_failure with its \
         cause (mac_failure means the UE did not accept the AUTN). Answer with \
         send_downlink_nas_transport, send_ue_context_release_command, or wait_for_more.",
        json!({
            "type": "send_downlink_nas_transport",
            "amf_ue_ngap_id": 1,
            "ran_ue_ngap_id": 1,
            "nas": {"message": "registration_reject", "cause": "illegal_ue"}
        }),
    )
    .with_alternative_example(json!({"type": "wait_for_more"}))
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Uplink NAS Transport ue={amf_ue_ngap_id}")
            .with_debug("NGAP Uplink NAS Transport ue={amf_ue_ngap_id} nas={nas}")
            .with_trace("NGAP Uplink NAS Transport: {json_pretty(.)}"),
    )
});

pub static NGAP_ERROR_INDICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_error_indication",
        "The gNB reported an error (Error Indication), with an optional cause and UE ids. \
         Observational: no answer is required. Release the UE with \
         send_ue_context_release_command if it names one, or wait_for_more.",
        json!({"type": "wait_for_more"}),
    )
    .with_alternative_example(
        json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": 1}),
    )
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Error Indication {cause}")
            .with_debug("NGAP Error Indication {cause} ue={amf_ue_ngap_id}")
            .with_trace("NGAP Error Indication: {json_pretty(.)}"),
    )
});

// ============================================================================

impl Protocol for NgapProtocol {
    /// Every NGAP verb is addressed to one association, so there are no async actions; the
    /// dashboard's "message this peer" runs the sync actions through the peer command channel.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        response_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "NGAP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NGAP_NG_SETUP_EVENT.clone(),
            NGAP_INITIAL_UE_MESSAGE_EVENT.clone(),
            NGAP_UPLINK_NAS_EVENT.clone(),
            NGAP_ERROR_INDICATION_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>SCTP>NGAP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ngap", "n2", "amf", "5g core", "5gc", "38.413"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // 38412 is above 1023 and SCTP is an ordinary kernel transport, not a raw socket.
            .privilege_requirement(PrivilegeRequirement::None)
            // TS 38.412 section 7; the same number as `codec::SCTP_PORT`, written as a literal so
            // the well-known-port ratchet can read it from source.
            .well_known_sctp_port(38412)
            .implementation(
                "TS 38.413 ALIGNED PER hand-written for the procedures implemented (NG Setup, \
                 Initial UE Message, Downlink/Uplink NAS Transport, Error Indication, NG Reset, \
                 UE Context Release), other IEs framed and skipped by length; plain 5GMM (TS \
                 24.501) decoded and the pre-security downlink messages encoded; SCTP via a \
                 socket2 one-to-one socket with PPID 60 and stream 0/1 selection, plus a \
                 non-standard length-prefixed TCP transport for lab use",
            )
            .llm_control(
                "The model admits or refuses gNBs (NG Setup Response/Failure with a cause) and \
                 decides what each UE is told (Identity Request, Authentication Request, \
                 Registration Reject with a 5GMM cause, UE Context Release). Decoding, ID \
                 allocation, NG Reset and every protocol-validity refusal are Rust's",
            )
            .e2e_testing(
                "UERANSIM's nr-gnb and nr-ue (asn1c APER) set up N2 and register against it over \
                 real SCTP on Linux, with tshark's ngap dissector reading a live capture; over \
                 the lab TCP transport with a mocked model on any host, including the \
                 fail-closed paths, the decode bounds and the pcap oracle on NetGet's own PDUs",
            )
            .notes(
                "EXPERIMENTAL: one independent peer (UERANSIM), and its evidence runs only where \
                 SCTP exists (Linux, the ngap pair job). macOS has no SCTP stack, so there the \
                 default transport refuses to start by name and only the non-standard \
                 transport=\"tcp\" framing runs. NAS security is not implemented: no 5G-AKA \
                 derivation, no Security Mode Command, no integrity or ciphering — a real UE \
                 answers NetGet's Authentication Request with MAC failure, and Registration \
                 Accept cannot be sent. No PDU sessions, handover, paging or AMF \
                 configuration update.",
            )
            .max_inbound_bytes(codec::MAX_PDU_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NGAP (5G N2) AMF: NG Setup and initial UE registration signalling with gNBs"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a 5G AMF for PLMN 001-01 that admits gNBs and rejects every UE as illegal"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "transport".into(),
            type_hint: "string".into(),
            description: "\"sctp\" (default — TS 38.412, PPID 60) or \"tcp\". TCP IS \
                          NON-STANDARD: a NetGet length-prefixed framing that no real gNB speaks, \
                          for local protocol work on hosts with no SCTP (macOS has none). A host \
                          without SCTP refuses \"sctp\" rather than falling back."
                .into(),
            required: false,
            example: json!("sctp"),
            default: None,
        }]
    }

    fn group_name(&self) -> &'static str {
        "Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ngap_ng_setup_request":
    plmn = event["global_ran_node_id"]["plmn"]
    actions = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
                "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
                "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif data["event_type_id"] == "ngap_initial_ue_message":
    actions = [{"type": "send_downlink_nas_transport", "amf_ue_ngap_id": event["amf_ue_ngap_id"],
                "ran_ue_ngap_id": event["ran_ue_ngap_id"],
                "nas": {"message": "registration_reject", "cause": "illegal_ue"}}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;
        crate::llm::actions::StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "instruction": "Act as a 5G AMF for PLMN 001-01, slice SST 1. Admit gNBs that \
                                broadcast that PLMN; ask every registering UE for its identity, \
                                then reject it with illegal_ue.",
                "startup_params": {"transport": "sctp"}
            }),
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "startup_params": {"transport": "sctp"},
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {"type": "script", "language": "python", "code": script}
                }]
            }),
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "startup_params": {"transport": "sctp"},
                "event_handlers": [{
                    "event_pattern": "ngap_ng_setup_request",
                    "handler": {"type": "static", "actions": [{
                        "type": "send_ng_setup_failure",
                        "cause": "misc/om-intervention",
                        "time_to_wait": "v60s"
                    }]}
                }]
            }),
        )
    }
}

impl Server for NgapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            super::NgapServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let t = action
            .get("type")
            .and_then(Value::as_str)
            .context("Missing action type")?;
        match t {
            "send_ng_setup_response" => self.ng_setup_response(&action),
            "send_ng_setup_failure" => self.ng_setup_failure(&action),
            "send_downlink_nas_transport" => self.downlink_nas_transport(&action),
            "send_ue_context_release_command" => self.ue_context_release(&action),
            "send_error_indication" => self.error_indication(&action),
            "send_ng_reset" => self.ng_reset(&action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // Not offered to the model; the dashboard's "disconnect this peer" injects it.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown NGAP action type: {t}")),
        }
    }
}
