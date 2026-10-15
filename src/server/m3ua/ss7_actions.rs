//! The model's vocabulary for the SS7 upper stack, shared by the SGP and the ASP client: MAP and
//! CAP dialogue actions and the two events that carry decoded TCAP messages.
//!
//! Every action here is an *intent*: `execute_action` validates its fields against the MAP / CAP
//! encoders (so a malformed answer fails where the model can see it) and hands it to the session
//! as `ActionResult::Custom { name: ss7::SS7_INTENT }`. Only the session knows the dialogue's
//! transaction ids, AARE state and route, so only it can produce the octets.

use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use serde_json::json;
use std::sync::LazyLock;

/// Which side of the association the vocabulary is for; only examples and wording differ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sgp,
    Asp,
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn def(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: serde_json::Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("-> SS7 {name} dialogue={{dialogue_id}}"))
                .with_debug(format!("SS7 {name}: {{json(.)}}")),
        ),
    }
}

const MAP_RESULTS: &str = "Result fields by operation: sendRoutingInfoForSM {imsi, \
     network_node_number, lmsi (8 hex digits, optional)}; anyTimeInterrogation {subscriber_state: \
     assumedIdle | camelBusy | notProvidedFromVLR | netDetNotReachable (with not_reachable_reason \
     msPurged | imsiDetached | restrictedArea | notRegistered), location_information: \
     {age_of_location_information, vlr_number, cell_global_id: {mcc, mnc, lac, cell_id}}}; \
     processUnstructuredSS-Request and unstructuredSS-Request {ussd_text}; sendRoutingInfo \
     {imsi, roaming_number}; updateLocation {hlr_number}; mo-forwardSM, mt-forwardSM and \
     unstructuredSS-Notify {} (an empty result). Numbers are digit strings (international, ISDN) \
     or {digits, nature, plan}.";

const MAP_ARGUMENTS: &str = "Argument fields by operation: sendRoutingInfoForSM {msisdn, \
     service_centre_address, sm_rp_pri (default true)}; anyTimeInterrogation {subscriber: \
     {msisdn} or {imsi}, requested_info: [location_information, subscriber_state, \
     current_location, imei, ms_classmark], gsm_scf_address}; processUnstructuredSS-Request, \
     unstructuredSS-Request and unstructuredSS-Notify {ussd_text, msisdn (optional)}; \
     mo-forwardSM {sm_rp_da: {service_centre_address}, sm_rp_oa: {msisdn}, sms: {destination, \
     text}}; mt-forwardSM {sm_rp_da: {imsi}, sm_rp_oa: {service_centre_address}, sms: \
     {originator, text}, more_messages_to_send}; sendRoutingInfo {msisdn, \
     gmsc_or_gsm_scf_address, interrogation_type: basicCall | forwarding}; updateLocation {imsi, \
     msc_number, vlr_number}. SMS text is encoded GSM 7-bit (or UCS2 if it needs to be), USSD \
     text likewise.";

const CAP_OPERATIONS: &str = "Each entry is {\"operation\": name, ...fields}. As the gsmSCF: \
     connect {destination_routing_address: digits, suppression_of_announcement}, continue {}, \
     releaseCall {cause: a Q.850 name such as call_rejected or normal_unspecified, or a number}, \
     requestReportBCSMEvent {bcsm_events: [{event_type_bcsm: oAnswer | oDisconnect | \
     oCalledPartyBusy | oNoAnswer | routeSelectFailure | oAbandon | tAnswer | ..., monitor_mode: \
     interrupted | notifyAndContinue | transparent, leg: 1 | 2}]}. As the gsmSSF: initialDP \
     {service_key, called_party_number, calling_party_number, event_type_bcsm (default \
     collectedInfo), imsi, msc_address, called_party_bcd_number, calling_partys_category}, \
     eventReportBCSM {event_type_bcsm, message_type: request | notification, leg}.";

pub fn send_map_result_action() -> ActionDefinition {
    def(
        "send_map_result",
        &format!(
            "Answer a MAP invoke with its result (TCAP ReturnResultLast). The dialogue ends \
             (TC-END) once every invoke in it is answered, unless end_dialogue is false. \
             {MAP_RESULTS}"
        ),
        vec![
            p("dialogue_id", "number", "dialogue_id from the event", true),
            p(
                "invoke_id",
                "number",
                "The invoke answered (from awaiting_answer_to); defaults to the oldest",
                false,
            ),
            p(
                "operation",
                "string",
                "The operation answered, e.g. sendRoutingInfoForSM (lets NetGet check the \
                 result fields before sending)",
                false,
            ),
            p("result", "object", "The result's fields (see above)", true),
            p(
                "end_dialogue",
                "boolean",
                "TC-END (true) or TC-CONTINUE (false); default ends once nothing else is pending",
                false,
            ),
        ],
        json!({
            "type": "send_map_result",
            "dialogue_id": 16777217,
            "invoke_id": 1,
            "operation": "sendRoutingInfoForSM",
            "result": {"imsi": "001010123456789", "network_node_number": "31600000001"}
        }),
    )
}

pub fn send_map_error_action() -> ActionDefinition {
    def(
        "send_map_error",
        "Answer a MAP invoke with an error (TCAP ReturnError): unknownSubscriber, \
         absentSubscriberSM (optional absent_subscriber_diagnostic), absentSubscriber, \
         unidentifiedSubscriber, teleserviceNotProvisioned, callBarred, facilityNotSupported, \
         subscriberBusyForMT-SMS, sm-DeliveryFailure (delivery_failure_cause: \
         memoryCapacityExceeded, equipmentProtocolError, equipmentNotSM-Equipped, \
         unknownServiceCentre, sc-Congestion, invalidSME-Address, subscriberNotSC-Subscriber), \
         systemFailure, dataMissing, unexpectedDataValue, ati-NotAllowed, unknownAlphabet, \
         ussd-Busy, …",
        vec![
            p("dialogue_id", "number", "dialogue_id from the event", true),
            p(
                "invoke_id",
                "number",
                "The invoke answered; defaults to the oldest awaiting an answer",
                false,
            ),
            p(
                "error",
                "string",
                "The MAP error's name (or its code)",
                true,
            ),
            p(
                "delivery_failure_cause",
                "string",
                "sm-DeliveryFailure only",
                false,
            ),
            p(
                "absent_subscriber_diagnostic",
                "number",
                "absentSubscriberSM only, 0..255",
                false,
            ),
            p(
                "end_dialogue",
                "boolean",
                "Default ends once nothing else is pending",
                false,
            ),
        ],
        json!({
            "type": "send_map_error",
            "dialogue_id": 16777217,
            "invoke_id": 1,
            "error": "unknownSubscriber"
        }),
    )
}

pub fn send_map_request_action(role: Role) -> ActionDefinition {
    let (description, example) = match role {
        Role::Asp => (
            format!(
                "Invoke a MAP operation. Without dialogue_id this opens a new dialogue \
                 (TC-BEGIN with the operation's application context) towards called_address, or \
                 the default far end from the startup parameters; with dialogue_id it is sent \
                 inside that open dialogue. The answer arrives as m3ua_map_received. \
                 {MAP_ARGUMENTS}"
            ),
            json!({
                "type": "send_map_request",
                "operation": "sendRoutingInfoForSM",
                "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}
            }),
        ),
        Role::Sgp => (
            format!(
                "Invoke a MAP operation towards the ASP: inside an open dialogue with \
                 dialogue_id (for example unstructuredSS-Request to continue a USSD menu), or a \
                 new dialogue to called_address. {MAP_ARGUMENTS}"
            ),
            json!({
                "type": "send_map_request",
                "dialogue_id": 16777217,
                "operation": "unstructuredSS-Request",
                "argument": {"ussd_text": "1 Balance 2 Top up"}
            }),
        ),
    };
    def(
        "send_map_request",
        &description,
        vec![
            p(
                "operation",
                "string",
                "updateLocation, sendRoutingInfo, sendRoutingInfoForSM, mo-forwardSM, \
                 mt-forwardSM, processUnstructuredSS-Request, unstructuredSS-Request, \
                 unstructuredSS-Notify, anyTimeInterrogation",
                true,
            ),
            p(
                "argument",
                "object",
                "The operation's fields (see above)",
                true,
            ),
            p(
                "dialogue_id",
                "number",
                "An open dialogue to send in; omit to open a new one",
                false,
            ),
            p(
                "called_address",
                "object",
                "SCCP Called Party Address for a new dialogue: {route_on: gt | ssn, pc, ssn, gt: \
                 digits}",
                false,
            ),
            p(
                "context_version",
                "number",
                "Application context version (default: the version NetGet implements, 2 or 3)",
                false,
            ),
        ],
        example,
    )
}

pub fn send_cap_operations_action(role: Role) -> ActionDefinition {
    let (description, example) = match role {
        Role::Sgp => (
            format!(
                "Instruct a gsmSSF in a CAMEL dialogue: TCAP invokes in one message. The dialogue \
                 ends (TC-END) unless the list arms an event with requestReportBCSMEvent (then it \
                 stays open for eventReportBCSM) or end_dialogue says otherwise. {CAP_OPERATIONS}"
            ),
            json!({
                "type": "send_cap_operations",
                "dialogue_id": 16777217,
                "operations": [{"operation": "connect", "destination_routing_address": "31677777777"}]
            }),
        ),
        Role::Asp => (
            format!(
                "Act as a gsmSSF: without dialogue_id, open a CAMEL dialogue (TC-BEGIN, cap_phase \
                 2 by default) carrying initialDP; with dialogue_id, report armed events with \
                 eventReportBCSM in the open dialogue. The gsmSCF's instructions arrive as \
                 m3ua_cap_received. {CAP_OPERATIONS}"
            ),
            json!({
                "type": "send_cap_operations",
                "operations": [{
                    "operation": "initialDP",
                    "service_key": 100,
                    "called_party_number": "31644444444",
                    "calling_party_number": "31655555555",
                    "event_type_bcsm": "collectedInfo"
                }]
            }),
        ),
    };
    def(
        "send_cap_operations",
        &description,
        vec![
            p("operations", "array", "The invokes, in order", true),
            p(
                "dialogue_id",
                "number",
                "The open CAMEL dialogue; omit only to start one with initialDP",
                false,
            ),
            p(
                "end_dialogue",
                "boolean",
                "TC-END (true) or TC-CONTINUE (false)",
                false,
            ),
            p(
                "cap_phase",
                "number",
                "New dialogue only: CAP phase 2, 3 or 4",
                false,
            ),
            p(
                "called_address",
                "object",
                "New dialogue only: the gsmSCF's SCCP address",
                false,
            ),
        ],
        example,
    )
}

pub fn send_tcap_end_action() -> ActionDefinition {
    def(
        "send_tcap_end",
        "Close a dialogue normally with an empty TC-END (for one left open with end_dialogue \
         false, or a CAMEL dialogue whose events have all been reported).",
        vec![p(
            "dialogue_id",
            "number",
            "dialogue_id from the event",
            true,
        )],
        json!({"type": "send_tcap_end", "dialogue_id": 16777217}),
    )
}

pub fn send_tcap_abort_action() -> ActionDefinition {
    def(
        "send_tcap_abort",
        "Refuse or abandon a dialogue (TC-U-ABORT). Before the dialogue is accepted this is an \
         AARE reject; reason application_context_not_supported or no_reason_given (default).",
        vec![
            p("dialogue_id", "number", "dialogue_id from the event", true),
            p(
                "reason",
                "string",
                "no_reason_given (default) or application_context_not_supported",
                false,
            ),
        ],
        json!({"type": "send_tcap_abort", "dialogue_id": 16777217}),
    )
}

fn wait_for_more() -> ActionDefinition {
    def(
        "wait_for_more",
        "Send nothing now. A MAP invoke or a CAMEL initialDP left unanswered is aborted \
         (TC-U-ABORT), so use this only for messages that need no answer (results, reports in \
         notify mode, End, Abort).",
        vec![],
        json!({"type": "wait_for_more"}),
    )
}

/// The MAP vocabulary.
pub fn map_actions(role: Role) -> Vec<ActionDefinition> {
    vec![
        send_map_result_action(),
        send_map_error_action(),
        send_map_request_action(role),
        send_tcap_end_action(),
        send_tcap_abort_action(),
        wait_for_more(),
    ]
}

/// The CAP vocabulary.
pub fn cap_actions(role: Role) -> Vec<ActionDefinition> {
    vec![
        send_cap_operations_action(role),
        send_tcap_end_action(),
        send_tcap_abort_action(),
        wait_for_more(),
    ]
}

/// Every SS7 action, without duplicates (for get_sync_actions / get_async_actions).
pub fn all_actions(role: Role) -> Vec<ActionDefinition> {
    vec![
        send_map_result_action(),
        send_map_error_action(),
        send_map_request_action(role),
        send_cap_operations_action(role),
        send_tcap_end_action(),
        send_tcap_abort_action(),
    ]
}

const MAP_EVENT_TEXT: &str = "A MAP message arrived on a TCAP dialogue, decoded: tcap is \
     begin / continue / end / abort, application_context names the MAP context, and each \
     component is an invoke (operation and its decoded argument), a result, an error or a \
     reject. Every invoke listed in awaiting_answer_to needs send_map_result or send_map_error \
     with this dialogue_id and its invoke_id. A dialogue left unanswered is aborted; if NetGet \
     cannot reach you at all it answers systemFailure. A message with tcap end or abort has \
     already closed the dialogue.";

const CAP_EVENT_TEXT: &str = "A CAMEL (CAP) message arrived on a TCAP dialogue, decoded: \
     initialDP from a gsmSSF reporting a call (service_key, called and calling numbers, event \
     type, IMSI), eventReportBCSM for an armed detection point (message_type request needs an \
     instruction, notification does not), or the gsmSCF's instructions to NetGet as gsmSSF \
     (connect, continue, releaseCall, requestReportBCSMEvent). Answer with send_cap_operations \
     using this dialogue_id. An initialDP or a request-mode report left unanswered is aborted.";

pub fn map_event(role: Role) -> EventType {
    let example = match role {
        Role::Sgp => send_map_result_action().example,
        Role::Asp => json!({"type": "wait_for_more"}),
    };
    EventType::new("m3ua_map_received", MAP_EVENT_TEXT, example)
        .with_alternative_example(send_map_error_action().example)
        .with_actions(map_actions(role))
        .with_log_template(
            LogTemplate::new()
                .with_info("MAP {tcap} dialogue={dialogue_id} {application_context.name}")
                .with_debug("MAP {tcap} dialogue={dialogue_id}: {json(components)}")
                .with_trace("MAP: {json_pretty(.)}"),
        )
}

pub fn cap_event(role: Role) -> EventType {
    let example = match role {
        Role::Sgp => send_cap_operations_action(Role::Sgp).example,
        Role::Asp => send_tcap_end_action().example,
    };
    EventType::new("m3ua_cap_received", CAP_EVENT_TEXT, example)
        .with_alternative_example(json!({
            "type": "send_cap_operations",
            "dialogue_id": 16777217,
            "operations": [{"operation": "releaseCall", "cause": "call_rejected"}]
        }))
        .with_actions(cap_actions(role))
        .with_log_template(
            LogTemplate::new()
                .with_info("CAP {tcap} dialogue={dialogue_id}")
                .with_debug("CAP {tcap} dialogue={dialogue_id}: {json(components)}")
                .with_trace("CAP: {json_pretty(.)}"),
        )
}

pub static SGP_MAP_EVENT: LazyLock<EventType> = LazyLock::new(|| map_event(Role::Sgp));
pub static SGP_CAP_EVENT: LazyLock<EventType> = LazyLock::new(|| cap_event(Role::Sgp));
