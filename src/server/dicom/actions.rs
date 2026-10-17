use super::pdu;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct DicomProtocol;
impl DicomProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> DICOM {name}"))),
    }
}

/// Handler-facing C-STORE outcomes and their PS3.4 status codes.
pub const STORE_STATUS: &[(&str, u16)] = &[
    ("success", 0x0000),
    ("warning_coercion", 0xB000),
    ("warning_elements_discarded", 0xB006),
    ("out_of_resources", 0xA700),
    ("dataset_does_not_match_sop_class", 0xA900),
    ("cannot_understand", 0xC000),
];

fn accept() -> ActionDefinition {
    action("dicom_accept", "Accept the association. Rust negotiates each presentation context (Verification, Patient/Study Root C-FIND, Storage SOP classes; Explicit or Implicit VR Little Endian) and answers A-ASSOCIATE-AC.", vec![], json!({"type":"dicom_accept"}))
}
fn reject() -> ActionDefinition {
    action(
        "dicom_reject",
        "Refuse the association with A-ASSOCIATE-RJ",
        vec![parameter(
            "reason",
            "string",
            "calling_ae_not_recognized (default), called_ae_not_recognized or no_reason",
            false,
        )],
        json!({"type":"dicom_reject","reason":"calling_ae_not_recognized"}),
    )
}
fn store_status() -> ActionDefinition {
    action(
        "dicom_store_status",
        "Answer a C-STORE: Rust sends C-STORE-RSP with the matching status code",
        vec![
            parameter("status", "string", "success, warning_coercion, warning_elements_discarded, out_of_resources, dataset_does_not_match_sop_class or cannot_understand", true),
            parameter("comment", "string", "Optional ErrorComment for a failure (up to 64 characters)", false),
        ],
        json!({"type":"dicom_store_status","status":"success"}),
    )
}
fn find_matches() -> ActionDefinition {
    action(
        "dicom_find_matches",
        "Answer a C-FIND with candidate records at the requested level as DICOM JSON. Rust applies the identifier's matching keys (universal, single value, wildcard, date/time range, UID list), returns only the requested attributes, and sends one pending response per match and a final success.",
        vec![parameter("matches", "array", "Records as DICOM JSON objects, e.g. [{\"00100010\": {\"vr\": \"PN\", \"Value\": [{\"Alphabetic\": \"Doe^Jane\"}]}, \"0020000D\": {\"vr\": \"UI\", \"Value\": [\"1.2.3\"]}}]", true)],
        json!({"type":"dicom_find_matches","matches":[{"00100010":{"vr":"PN","Value":[{"Alphabetic":"Doe^Jane"}]},"00100020":{"vr":"LO","Value":["P001"]},"0020000D":{"vr":"UI","Value":["1.2.826.0.1.3680043.10.1408.7"]}}]}),
    )
}
fn find_failed() -> ActionDefinition {
    action(
        "dicom_find_failed",
        "Refuse the C-FIND: Rust sends a failure status",
        vec![parameter(
            "status",
            "string",
            "out_of_resources (A700) or unable_to_process (C000)",
            true,
        )],
        json!({"type":"dicom_find_failed","status":"unable_to_process"}),
    )
}

pub static ASSOCIATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("dicom_associate", "An application entity asks to associate. Called AE title and application context were checked by Rust.", accept().example.clone())
        .with_parameters(vec![
            parameter("calling_ae", "string", "The requester's AE title", true),
            parameter("called_ae", "string", "The AE title it asked for (this server's)", true),
            parameter("contexts", "array", "Proposed presentation contexts: [{id, abstract_syntax, service, transfer_syntaxes}]", true),
            parameter("implementation", "string", "The requester's implementation class UID", false),
        ])
        .with_actions(vec![accept(), reject()])
});
pub static STORE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("dicom_store", "A C-STORE request: an instance to keep. The dataset is DICOM JSON with bulk data given by length only.", store_status().example.clone())
        .with_parameters(vec![
            parameter("calling_ae", "string", "The sending AE title", true),
            parameter("sop_class_uid", "string", "Affected SOP Class UID (e.g. CT Image Storage)", true),
            parameter("sop_instance_uid", "string", "Affected SOP Instance UID", true),
            parameter("dataset", "object", "The instance as DICOM JSON; OB/OW and other bulk values appear as {vr, length}", true),
            parameter("bytes", "number", "Encoded dataset size", true),
        ])
        .with_actions(vec![store_status()])
});
pub static FIND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("dicom_find", "A C-FIND query. Return candidate records at the level; Rust does the matching and returns only requested keys.", find_matches().example.clone())
        .with_parameters(vec![
            parameter("calling_ae", "string", "The querying AE title", true),
            parameter("model", "string", "patient_root or study_root", true),
            parameter("level", "string", "QueryRetrieveLevel: PATIENT, STUDY, SERIES or IMAGE", true),
            parameter("identifier", "object", "The query keys as DICOM JSON (empty values are return keys)", true),
        ])
        .with_actions(vec![find_matches(), find_failed()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Value,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default: Some(default),
    }
}

impl Protocol for DicomProtocol {
    fn protocol_name(&self) -> &'static str {
        "DICOM"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DICOM"
    }
    fn description(&self) -> &'static str {
        "DICOM DIMSE service provider (SCP): association negotiation, C-ECHO, C-STORE and C-FIND"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "dicom",
            "dimse",
            "pacs",
            "c-store",
            "c-find",
            "c-echo",
            "medical imaging",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept(),
            reject(),
            store_status(),
            find_matches(),
            find_failed(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            ASSOCIATE_EVENT.clone(),
            STORE_EVENT.clone(),
            FIND_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("ae_title", "string", "This server's AE title; associations calling another title are rejected (1 to 16 characters)", json!("PACS"), json!(super::DEFAULT_AE_TITLE)),
            startup("idle_timeout_secs", "integer", "Seconds an association may be idle before A-ABORT", json!(120), json!(super::IDLE_TIMEOUT.as_secs())),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(104)
            .implementation("Hand-written PS3.8 upper layer (A-ASSOCIATE, P-DATA with fragmentation, A-RELEASE, A-ABORT) and PS3.7 DIMSE; Implicit and Explicit VR Little Endian dataset codec with DICOM JSON; C-FIND matching per PS3.4 C.2.2.2 in Rust")
            .llm_control("Which associations to accept, what to do with each stored instance, and which records exist for queries")
            .e2e_testing("tests/server/dicom: pynetdicom 3.0.4 (independent) associates, runs C-ECHO, C-STORE of Secondary Capture instances (one refused) and Study Root / Patient Root C-FIND with wildcard and date-range keys, and is rejected for a wrong called AE title, a refused calling AE and an undecided association; NetGet's SCU against pynetdicom as SCP")
            .notes("Services: Verification, Storage (any SOP class under 1.2.840.10008.5.1.4.1.1), Patient and Study Root C-FIND. No C-MOVE, C-GET, C-CANCEL handling, compressed or Big Endian transfer syntaxes, TLS or extended negotiation. Bulk data is never given to the handler. No storage: the handler owns every record.")
            .answers_on_failure()
            .max_inbound_bytes(pdu::MAX_PDU as usize)
            .request_only("The SCP answers each DIMSE request on an association; it initiates no operation")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "DICOM PACS on port 11112 that accepts CT images and answers study queries for two patients"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"dicom","port":11112,"instruction":"A small PACS with two CT studies","startup_params":{"ae_title":"PACS"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"dicom_associate","handler":{"type":"static","actions":[{"type":"dicom_accept"}]}},
            {"event_pattern":"dicom_store","handler":{"type":"static","actions":[{"type":"dicom_store_status","status":"success"}]}},
            {"event_pattern":"dicom_find","handler":{"type":"static","actions":[{"type":"dicom_find_matches","matches":[]}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][2]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'dicom_find_matches','matches':[]}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for DicomProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 4 * 1024 * 1024, 200_000, 24),
        "answer exceeds the DICOM bounds"
    );
    match v["type"].as_str() {
        Some("dicom_accept") => {}
        Some("dicom_reject") => {
            if let Some(r) = v.get("reason").filter(|r| !r.is_null()) {
                ensure!(
                    matches!(
                        r.as_str(),
                        Some(
                            "calling_ae_not_recognized" | "called_ae_not_recognized" | "no_reason"
                        )
                    ),
                    "unknown reject reason"
                );
            }
        }
        Some("dicom_store_status") => {
            let s = v["status"].as_str().context("status is required")?;
            ensure!(
                STORE_STATUS.iter().any(|(n, _)| *n == s),
                "unknown store status {s}"
            );
            if let Some(c) = v.get("comment").filter(|c| !c.is_null()) {
                ensure!(
                    c.as_str()
                        .is_some_and(|c| c.len() <= 64 && !crate::utils::sanitize::has_controls(&c)),
                    "comment is up to 64 printable characters"
                );
            }
        }
        Some("dicom_find_matches") => ensure!(
            v["matches"]
                .as_array()
                .is_some_and(|m| m.len() <= 1000 && m.iter().all(Value::is_object)),
            "matches is an array of at most 1000 DICOM JSON objects"
        ),
        Some("dicom_find_failed") => ensure!(
            matches!(
                v["status"].as_str(),
                Some("out_of_resources" | "unable_to_process")
            ),
            "status is out_of_resources or unable_to_process"
        ),
        _ => bail!("Unknown DICOM server action"),
    }
    Ok(())
}
