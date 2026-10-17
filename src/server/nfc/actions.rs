//! NFC (Near Field Communication) server protocol actions.
//!
//! The server emulates an NFC Forum Type 4 tag over a bound TCP socket using
//! the vsmartcard `vpcd` framing; see `src/server/nfc/mod.rs` and
//! `src/server/nfc/CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Set the virtual tag's Answer to Reset
pub static SET_ATR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(set_atr_action);
/// Set the virtual tag's NDEF message
pub static SET_NDEF_MESSAGE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(set_ndef_message_action);
/// Answer an APDU command sent to the virtual tag
pub static RESPOND_TO_APDU_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(respond_to_apdu_action);

/// Emitted once, after the socket is bound and before the first reader is
/// accepted, so the tag is fully configured by the time a reader can talk to it.
pub static NFC_SERVER_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_server_started",
        "Virtual NFC tag bound and ready; configure the tag before readers connect",
        json!({
            "type": "set_ndef_message",
            "records": [{"type": "text", "language": "en", "text": "Hello NFC!"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "tag_type".to_string(),
            type_hint: "string".to_string(),
            description: "Tag type this server was started with".to_string(),
            required: true,
        },
        Parameter {
            name: "uid".to_string(),
            type_hint: "string".to_string(),
            description: "Tag UID (hex), supplied at startup or generated".to_string(),
            required: true,
        },
        Parameter {
            name: "listen_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address the virtual tag is listening on".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SET_ATR_ACTION.clone(),
        SET_NDEF_MESSAGE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NFC virtual tag ready on {listen_addr} (type={tag_type})")
            .with_debug("NFC started: type={tag_type} uid={uid} addr={listen_addr}"),
    )
});

/// Emitted when a reader sends `SELECT` by DF name (INS `A4`, P1 `04`) — the
/// command that picks an application on the tag. Every other APDU, including
/// `SELECT` by file identifier, raises `nfc_apdu_received` instead, so exactly
/// one event (and one handler call) happens per command.
pub static NFC_TAG_SELECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_tag_selected",
        "Reader selected an application on the virtual tag (SELECT by AID)",
        json!({
            "type": "respond_to_apdu",
            "sw1": "90",
            "sw2": "00"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "application_id".to_string(),
            type_hint: "string".to_string(),
            description:
                "Application ID (AID) the reader selected, as uppercase hex (e.g. D2760000850101 \
                 for the NDEF application)"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "cla".to_string(),
            type_hint: "string".to_string(),
            description: "Class byte as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "p1".to_string(),
            type_hint: "string".to_string(),
            description: "Parameter 1 as two hex digits (always 04 for select by AID)".to_string(),
            required: true,
        },
        Parameter {
            name: "p2".to_string(),
            type_hint: "string".to_string(),
            description: "Parameter 2 as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "le".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum response length the reader will accept, null if absent"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "tag_type".to_string(),
            type_hint: "string".to_string(),
            description: "Tag type this server was started with".to_string(),
            required: true,
        },
        Parameter {
            name: "uid".to_string(),
            type_hint: "string".to_string(),
            description: "Tag UID (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "ndef_records".to_string(),
            type_hint: "array".to_string(),
            description: "NDEF records configured by set_ndef_message, so they can be served \
                          from this handler"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![RESPOND_TO_APDU_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("NFC SELECT AID {application_id}")
            .with_debug("NFC tag_selected: aid={application_id} cla={cla} p2={p2}"),
    )
});

/// Emitted for every command APDU that is not a SELECT-by-AID.
pub static NFC_APDU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_apdu_received",
        "Command APDU received by the virtual NFC tag",
        json!({
            "type": "respond_to_apdu",
            "data_text": "Hello NFC!",
            "sw1": "90",
            "sw2": "00"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "ins_name".to_string(),
            type_hint: "string".to_string(),
            description: "Decoded instruction name: SELECT, READ_BINARY, UPDATE_BINARY, VERIFY, \
                 GET_DATA, ... or UNKNOWN"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "cla".to_string(),
            type_hint: "string".to_string(),
            description: "Class byte as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "ins".to_string(),
            type_hint: "string".to_string(),
            description: "Instruction byte as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "p1".to_string(),
            type_hint: "string".to_string(),
            description: "Parameter 1 as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "p2".to_string(),
            type_hint: "string".to_string(),
            description: "Parameter 2 as two hex digits".to_string(),
            required: true,
        },
        Parameter {
            name: "lc".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes in the command data field".to_string(),
            required: true,
        },
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description:
                "Command data field as uppercase hex. Hex is used because this field is opaque \
                 bytes chosen by the reader; prefer data_text when it is present."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "data_text".to_string(),
            type_hint: "string".to_string(),
            description: "Command data as text, present only when every byte is printable ASCII"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "le".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum response length the reader will accept, null if absent"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "tag_type".to_string(),
            type_hint: "string".to_string(),
            description: "Tag type this server was started with".to_string(),
            required: true,
        },
        Parameter {
            name: "uid".to_string(),
            type_hint: "string".to_string(),
            description: "Tag UID (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "ndef_records".to_string(),
            type_hint: "array".to_string(),
            description: "NDEF records configured by set_ndef_message, so they can be served \
                          from this handler"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![RESPOND_TO_APDU_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("NFC APDU {ins_name} (Lc={lc})")
            .with_debug(
                "NFC apdu_received: {ins_name} cla={cla} ins={ins} p1={p1} p2={p2} lc={lc}",
            ),
    )
});

/// Action definition for set_atr (async)
fn set_atr_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_atr".to_string(),
        description: "Set the Answer to Reset (ATR) the virtual tag returns when a reader powers \
                      it up"
            .to_string(),
        parameters: vec![Parameter {
            name: "atr_hex".to_string(),
            type_hint: "string".to_string(),
            description: "ATR bytes as a hex string (ISO 7816-3 defines this as raw bytes, so hex \
                          is the only faithful form)"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "set_atr",
            "atr_hex": "3B8F8001804F0CA0000003060300030000000068"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFC set ATR")
                .with_debug("NFC set_atr: atr={atr_hex}"),
        ),
    }
}

/// Action definition for set_ndef_message (async)
fn set_ndef_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_ndef_message".to_string(),
        description: "Store the NDEF records this tag carries. They are handed back to you in \
                      every nfc_apdu_received / nfc_tag_selected event so you can serve them."
            .to_string(),
        parameters: vec![Parameter {
            name: "records".to_string(),
            type_hint: "array".to_string(),
            description:
                "Array of NDEF records, each an object such as {\"type\": \"text\", \"language\": \"en\", \"text\": \"...\"} or {\"type\": \"uri\", \"uri\": \"...\"}"
                    .to_string(),
            required: true,
        }],
        example: json!({
            "type": "set_ndef_message",
            "records": [
                {
                    "type": "text",
                    "language": "en",
                    "text": "Hello NFC!"
                },
                {
                    "type": "uri",
                    "uri": "https://example.com"
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFC set NDEF ({records_len} records)")
                .with_debug("NFC set_ndef_message: records={records_len}"),
        ),
    }
}

/// Action definition for respond_to_apdu (sync)
fn respond_to_apdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "respond_to_apdu".to_string(),
        description: "Answer the command APDU with an optional response body and a REQUIRED \
                      two-byte status word. This is the only way to reply; if you do not use \
                      it, or you use it without naming sw1 and sw2, the tag answers 6F00 \
                      (card error)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data_text".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as text; sent as its UTF-8 bytes. Use this whenever \
                              the answer is text. Mutually exclusive with data_hex."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "data_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as a hex string, for genuinely binary answers such as \
                              a capability container. Mutually exclusive with data_text."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "sw1".to_string(),
                type_hint: "string".to_string(),
                description: "Status byte 1 as two hex digits. REQUIRED - there is no default, \
                              because the only plausible default is success. Approve with '90'; \
                              refuse with '69' (security), '6A' (wrong parameters) or '6D' \
                              (unsupported)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "sw2".to_string(),
                type_hint: "string".to_string(),
                description: "Status byte 2 as two hex digits. REQUIRED. '90' '00' together mean \
                              success; naming both bytes is what makes approving a command a \
                              deliberate act rather than an omission."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "respond_to_apdu",
            "data_text": "Hello NFC!",
            "sw1": "90",
            "sw2": "00"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFC APDU response SW={sw1}{sw2}")
                .with_debug("NFC respond_to_apdu: data={data_hex} sw1={sw1} sw2={sw2}"),
        ),
    }
}

/// Parse a hex string, rejecting anything that is not an even run of hex digits
/// so a malformed value fails where it is produced instead of being logged as if
/// it had been accepted.
fn parse_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|e| anyhow!("Invalid hex in '{field}' ({value}): {e}"))
}

/// Parse a single-byte hex field such as `sw1`.
fn parse_status_byte(field: &str, value: &str) -> Result<u8> {
    match parse_hex(field, value)?.as_slice() {
        [byte] => Ok(*byte),
        other => Err(anyhow!(
            "'{field}' must be exactly one hex byte (two digits), got {} byte(s)",
            other.len()
        )),
    }
}

/// NFC server protocol implementation
pub struct NfcServerProtocol;

impl Protocol for NfcServerProtocol {
    fn protocol_name(&self) -> &'static str {
        "nfc"
    }

    fn stack_name(&self) -> &'static str {
        "application"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Virtual NFC Forum Type 4 tag: ISO 7816-4 command APDUs over a bound TCP socket \
                 using the vsmartcard vpcd framing (u16-BE length prefix; 1-byte frames are vpcd \
                 control codes, 04 requesting the ATR). No PC/SC call is made and no reader \
                 hardware is used.",
            )
            .llm_control(
                "ATR and NDEF records at startup; the response body and ISO 7816-4 status word \
                 for every command APDU. Nothing is answered by built-in card logic, and a \
                 handler that produces no respond_to_apdu gets 6F00 rather than a success.",
            )
            .e2e_testing(
                "Mocked E2E drives the bound socket with a real vpcd-framed client and asserts \
                 the response APDU bytes (tests/server/nfc/e2e_test.rs). No hardware needed. \
                 Interop with pcscd via a real vpcd in client mode is untested.",
            )
            .notes(
                "Card emulation over RF is impossible with a normal PC/SC reader, so the tag is \
                 exposed over TCP instead. All three events fire: nfc_server_started at bind, \
                 nfc_tag_selected on SELECT by AID (INS A4 / P1 04), nfc_apdu_received on every \
                 other APDU. A real reader reaches it only through vpcd configured as a TCP \
                 client (DEVICENAME /dev/null:<host>:<port>), which has not been tested against \
                 hardware. Frames are capped at 4096 bytes and malformed APDUs are answered 6700.",
            )
            .max_inbound_bytes(crate::server::nfc::MAX_FRAME_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Virtual NFC Type 4 tag answering ISO 7816-4 APDUs over TCP (vpcd framing)"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*NFC_SERVER_STARTED_EVENT).clone(),
            (*NFC_TAG_SELECTED_EVENT).clone(),
            (*NFC_APDU_RECEIVED_EVENT).clone(),
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![SET_ATR_ACTION.clone(), SET_NDEF_MESSAGE_ACTION.clone()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![RESPOND_TO_APDU_ACTION.clone()]
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "nfc",
            "smart card",
            "apdu",
            "iso7816",
            "tag",
            "ndef",
            "card emulation",
        ]
    }

    fn example_prompt(&self) -> &'static str {
        "Create a virtual NFC tag on port {AVAILABLE_PORT} that responds to APDU commands"
    }

    fn group_name(&self) -> &'static str {
        "NFC & Smart Cards"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every APDU with a text NDEF payload and a 90 00
        // success status, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "nfc_apdu_received":
    actions = [{"type": "respond_to_apdu",
                "data_text": "Hello NFC!", "sw1": "90", "sw2": "00"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles NFC tag emulation
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "nfc",
                "instruction": "Act as a virtual NFC Type 4 tag that responds to APDU commands",
                "startup_params": {
                    "tag_type": "type4",
                    "uid": "04A1B2C3D4E5F6"
                }
            }),
            // Script mode: Code-based NFC handling
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "nfc",
                "startup_params": {
                    "tag_type": "type4"
                },
                "event_handlers": [{
                    "event_pattern": "nfc_apdu_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed NFC tag responses
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "nfc",
                "startup_params": {
                    "tag_type": "type4"
                },
                "event_handlers": [
                    {
                        "event_pattern": "nfc_server_started",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "set_ndef_message",
                                "records": [{"type": "text", "language": "en", "text": "Hello NFC!"}]
                            }]
                        }
                    },
                    {
                        "event_pattern": "nfc_tag_selected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "respond_to_apdu",
                                "sw1": "90",
                                "sw2": "00"
                            }]
                        }
                    },
                    {
                        "event_pattern": "nfc_apdu_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "respond_to_apdu",
                                "data_text": "Hello NFC!",
                                "sw1": "90",
                                "sw2": "00"
                            }]
                        }
                    }
                ]
            }),
        )
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "tag_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Virtual tag type, reported to the handler in every APDU event: 'type2' \
                     (MIFARE), 'type4' (ISO 14443-4, default), 'generic'"
                        .to_string(),
                required: false,

                example: json!("type4"),
                default: None,
            },
            ParameterDefinition {
                name: "uid".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Tag UID (hex), reported to the handler in every APDU event; a random 7-byte \
                     UID is generated when omitted"
                        .to_string(),
                required: false,

                example: json!("04A1B2C3D4E5F6"),
                default: None,
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a connected reader may send no frame at all before the tag closes \
                     it. Default 30: vpcd is reader-driven, so every peer this socket can have \
                     speaks first, and NetGet's own NFC client talks to a PC/SC reader rather \
                     than to this socket, so no peer here is ever waiting on a person."
                        .to_string(),
                required: false,

                example: json!(30),
                default: Some(serde_json::json!(super::FIRST_FRAME_READ_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds an established reader may send no further frame before the tag \
                     closes it. Default 300. A reader goes quiet whenever no application is \
                     watching it, so raise this rather than lower it if pcscd hosts mount this \
                     card and use it rarely."
                        .to_string(),
                required: false,

                example: json!(300),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_FRAMES_TIMEOUT.as_secs()
                )),
            },
        ]
    }
}

// Implement Server trait
impl Server for NfcServerProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::nfc::NfcServer;

            // Build startup params JSON manually since StartupParams doesn't expose to_json
            let startup_params_json = if let Some(ref params) = ctx.startup_params {
                serde_json::json!({
                    "tag_type": params.get_optional_string("tag_type")?,
                    "uid": params.get_optional_string("uid")?,
                    "first_byte_timeout_secs": params.get_optional_u64("first_byte_timeout_secs")?,
                    "idle_timeout_secs": params.get_optional_u64("idle_timeout_secs")?,
                })
            } else {
                serde_json::json!({})
            };

            NfcServer::start(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                startup_params_json,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "set_atr" => {
                let atr_hex = action
                    .get("atr_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'atr_hex' parameter")?;
                let atr = parse_hex("atr_hex", atr_hex)?;
                if atr.is_empty() {
                    return Err(anyhow!("'atr_hex' must not be empty"));
                }
                Ok(ActionResult::Custom {
                    name: "set_atr".to_string(),
                    data: json!({ "atr_hex": atr_hex }),
                })
            }
            "set_ndef_message" => {
                let records = action
                    .get("records")
                    .and_then(|v| v.as_array())
                    .context("Missing 'records' parameter")?;
                Ok(ActionResult::Custom {
                    name: "set_ndef_message".to_string(),
                    data: json!({ "records": records }),
                })
            }
            "respond_to_apdu" => {
                let data_hex = action.get("data_hex").and_then(|v| v.as_str());
                let data_text = action.get("data_text").and_then(|v| v.as_str());

                // Normalise both spellings of the body to hex so the server has
                // exactly one form to decode. Refusing the ambiguous case is the
                // point: "48656c6c6f" is simultaneously valid text and valid hex
                // and only the sender knows which it meant.
                let body_hex = match (data_text, data_hex) {
                    (Some(text), None) => hex::encode_upper(text.as_bytes()),
                    (None, Some(hex_str)) => {
                        parse_hex("data_hex", hex_str)?;
                        hex_str.to_string()
                    }
                    (None, None) => String::new(),
                    (Some(_), Some(_)) => {
                        return Err(anyhow!(
                            "respond_to_apdu accepts 'data_text' or 'data_hex', not both"
                        ))
                    }
                };

                // No default, deliberately. A tag is an access-control device and the
                // only status word a default could reasonably be is 9000 - success. That
                // would mean the most degenerate thing a model can emit, a bare
                // `{"type": "respond_to_apdu"}`, approves a VERIFY. Success has to be
                // named, the same way `eapol` gives EAP-Success its own eight literal
                // octets rather than a boolean anything could flip. A missing status word
                // is an error here, and reaches the wire as 6F00 through
                // `decision=fail_closed_no_action`.
                let sw1 = action.get("sw1").and_then(|v| v.as_str()).ok_or_else(|| {
                    anyhow!(
                        "respond_to_apdu requires an explicit 'sw1' (two hex digits): there is \
                         no default, because the default would be success"
                    )
                })?;
                let sw2 = action.get("sw2").and_then(|v| v.as_str()).ok_or_else(|| {
                    anyhow!(
                        "respond_to_apdu requires an explicit 'sw2' (two hex digits): there is \
                         no default, because the default would be success"
                    )
                })?;
                parse_status_byte("sw1", sw1)?;
                parse_status_byte("sw2", sw2)?;

                Ok(ActionResult::Custom {
                    name: "respond_to_apdu".to_string(),
                    data: json!({
                        "data_hex": body_hex,
                        "sw1": sw1,
                        "sw2": sw2,
                    }),
                })
            }
            _ => Err(anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
