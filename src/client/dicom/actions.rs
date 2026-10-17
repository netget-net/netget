use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::dicom::actions::{action, parameter};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct DicomClientProtocol;
impl DicomClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn echo() -> ActionDefinition {
    action(
        "dicom_echo",
        "Verify the association with C-ECHO",
        vec![],
        json!({"type":"dicom_echo"}),
    )
}
fn store() -> ActionDefinition {
    action(
        "dicom_store",
        "Send an instance with C-STORE. Rust encodes the DICOM JSON dataset in the negotiated transfer syntax; binary values may be given as {\"vr\": \"OB\", \"hex\": \"...\"} (64 KiB at most).",
        vec![
            parameter("sop_class_uid", "string", "Storage SOP Class UID, e.g. 1.2.840.10008.5.1.4.1.1.7 (Secondary Capture); it must have been proposed (see storage_classes)", true),
            parameter("sop_instance_uid", "string", "The instance's UID (also written as SOPInstanceUID)", true),
            parameter("dataset", "object", "DICOM JSON attributes, e.g. {\"00100010\": {\"vr\": \"PN\", \"Value\": [{\"Alphabetic\": \"Doe^Jane\"}]}}", true),
        ],
        json!({"type":"dicom_store","sop_class_uid":"1.2.840.10008.5.1.4.1.1.7","sop_instance_uid":"1.2.826.0.1.3680043.10.1408.99","dataset":{"00100010":{"vr":"PN","Value":[{"Alphabetic":"Doe^Jane"}]},"00100020":{"vr":"LO","Value":["P001"]}}}),
    )
}
fn find() -> ActionDefinition {
    action(
        "dicom_find",
        "Query with C-FIND; every pending response is collected into one result",
        vec![
            parameter("model", "string", "study_root (default) or patient_root", false),
            parameter("level", "string", "PATIENT, STUDY, SERIES or IMAGE", true),
            parameter("identifier", "object", "Matching and return keys as DICOM JSON; give an empty value ({\"vr\": \"PN\"}) to ask for an attribute", true),
        ],
        json!({"type":"dicom_find","level":"STUDY","identifier":{"00100010":{"vr":"PN","Value":[{"Alphabetic":"Doe*"}]},"0020000D":{"vr":"UI"},"00080020":{"vr":"DA"}}}),
    )
}
fn release() -> ActionDefinition {
    action(
        "disconnect",
        "Release the association (A-RELEASE) and stop this client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![echo(), store(), find(), release()]
}

pub static ASSOCIATED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dicom_associated",
        "The association was accepted",
        echo().example.clone(),
    )
    .with_parameters(vec![
        parameter("called_ae", "string", "The peer's AE title", true),
        parameter(
            "accepted",
            "array",
            "Accepted presentation contexts: [{abstract_syntax, transfer_syntax}]",
            true,
        ),
        parameter(
            "refused",
            "array",
            "Abstract syntaxes the peer did not accept",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dicom_response",
        "The peer's answer to the last request",
        release().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "echo, store or find", true),
        parameter(
            "status",
            "string",
            "Final DIMSE status as four hex digits, e.g. 0000 (success), A700, C000",
            true,
        ),
        parameter(
            "meaning",
            "string",
            "success, warning, pending, cancel or failure",
            true,
        ),
        parameter(
            "matches",
            "array",
            "For find: each pending response's identifier as DICOM JSON",
            false,
        ),
        parameter(
            "comment",
            "string",
            "ErrorComment, when the peer sent one",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for DicomClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "DICOM"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DICOM"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dicom", "dimse", "scu", "pacs client"]
    }
    fn description(&self) -> &'static str {
        "DICOM DIMSE service user (SCU): associate, then C-ECHO, C-STORE and C-FIND"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![ASSOCIATED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "called_ae",
                "string",
                "The peer's AE title (1 to 16 characters)",
                json!("PACS"),
                Some(json!(super::DEFAULT_CALLED)),
            ),
            p(
                "calling_ae",
                "string",
                "This client's AE title",
                json!("MODALITY"),
                Some(json!(super::DEFAULT_CALLING)),
            ),
            p(
                "storage_classes",
                "array",
                "Storage SOP Class UIDs to propose (CT, MR and Secondary Capture by default)",
                json!(["1.2.840.10008.5.1.4.1.1.2"]),
                Some(json!(super::DEFAULT_STORAGE)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared PS3.8 upper layer and dataset codec; proposes Verification, Study and Patient Root C-FIND and storage classes with Explicit then Implicit VR Little Endian")
            .llm_control("Which instances to send and which queries to run, and what to do with each answer")
            .e2e_testing("tests/client/dicom: pynetdicom 3.0.4 (independent) as SCP answers C-ECHO, stores an instance and answers C-FIND; a wrong called AE title is rejected")
            .notes("No C-MOVE, C-GET or C-CANCEL, no compressed transfer syntaxes. 16 MiB datasets.")
            .max_inbound_bytes(crate::server::dicom::pdu::MAX_PDU as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the PACS at 127.0.0.1:11112 for every study of patient Doe"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"dicom","remote_addr":"127.0.0.1:11112","instruction":"Find the studies of patient Doe","startup_params":{"called_ae":"PACS"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"dicom_associated","handler":{"type":"static","actions":[find().example]}},
            {"event_pattern":"dicom_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

fn uid_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl Client for DicomClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 4 * 1024 * 1024, 100_000, 24),
            "action exceeds the DICOM bounds"
        );
        match v["type"].as_str() {
            Some("dicom_echo") => {}
            Some("dicom_store") => {
                ensure!(
                    v["sop_class_uid"].as_str().is_some_and(uid_ok)
                        && v["sop_instance_uid"].as_str().is_some_and(uid_ok),
                    "sop_class_uid and sop_instance_uid are UIDs"
                );
                let ds = v["dataset"]
                    .as_object()
                    .context("dataset is a DICOM JSON object")?;
                crate::server::dicom::dataset::encode(
                    ds,
                    crate::server::dicom::dataset::EXPLICIT_LE,
                )?;
            }
            Some("dicom_find") => {
                ensure!(
                    matches!(
                        v["level"].as_str(),
                        Some("PATIENT" | "STUDY" | "SERIES" | "IMAGE")
                    ),
                    "level is PATIENT, STUDY, SERIES or IMAGE"
                );
                if let Some(m) = v.get("model").filter(|m| !m.is_null()) {
                    ensure!(
                        matches!(m.as_str(), Some("study_root" | "patient_root")),
                        "model is study_root or patient_root"
                    );
                }
                let ds = v["identifier"]
                    .as_object()
                    .context("identifier is a DICOM JSON object")?;
                crate::server::dicom::dataset::encode(
                    ds,
                    crate::server::dicom::dataset::EXPLICIT_LE,
                )?;
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown DICOM client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
