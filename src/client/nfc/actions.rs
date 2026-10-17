//! NFC (Near Field Communication) client protocol actions implementation
//! Uses PC/SC API for cross-platform smart card/NFC reader support

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::ConnectContext;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

/// NFC reader list event - triggered after listing available PC/SC readers
pub static NFC_READERS_LISTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_readers_listed",
        "Available NFC/smart card readers enumerated via PC/SC",
        json!({
            "type": "send_apdu",
            "cla": "00",
            "ins": "A4",
            "p1": "04",
            "p2": "00",
            "data": "D2760000850101",
            "le": "00"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "readers".to_string(),
        type_hint: "array".to_string(),
        description: "List of reader names (strings)".to_string(),
        required: true,
    }])
});

/// NFC card detected event - triggered when a card/tag is detected in reader
pub static NFC_CARD_DETECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_card_detected",
        "NFC card/tag detected in reader",
        json!({
            "type": "read_ndef"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "atr".to_string(),
            type_hint: "string".to_string(),
            description: "Answer to Reset (ATR) hex string".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Active protocol (T0, T1, etc.)".to_string(),
            required: false,
        },
    ])
});

/// NFC APDU response event - triggered after sending APDU command
pub static NFC_APDU_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_apdu_response",
        "APDU response received from card/tag",
        json!({
            "type": "send_apdu_raw",
            "apdu_hex": "00B0000010"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Response APDU as hex string (includes SW1 SW2 status bytes)".to_string(),
            required: true,
        },
        Parameter {
            name: "sw1".to_string(),
            type_hint: "string".to_string(),
            description: "Status byte 1 (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "sw2".to_string(),
            type_hint: "string".to_string(),
            description: "Status byte 2 (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Response data (without status bytes) as hex string".to_string(),
            required: false,
        },
    ])
});

/// NFC NDEF data read event - triggered after successfully reading NDEF message
///
/// `records` is the decoded form and used to be declared here while the emit site sent only
/// `length` / `message_hex` / `message_text` — the model was promised typed records and given
/// none. All four fields are declared now and all four are emitted.
pub static NFC_NDEF_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_ndef_read",
        "NDEF message read from NFC tag",
        json!({
            "type": "write_ndef",
            "records": [
                {
                    "type": "text",
                    "language": "en",
                    "text": "Response message"
                }
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "records".to_string(),
            type_hint: "array".to_string(),
            description:
                "Decoded NDEF records: 'text' (with language), 'uri', 'mime', 'external', or \
                 'chunked'/'undecodable'/'other' where the tag's bytes could not be read as a \
                 typed record. A record flagged unsafe_characters_removed carried control or \
                 bidirectional-override characters, which were replaced with U+FFFD - treat \
                 that tag as hostile."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of the raw NDEF message in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "message_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The raw NDEF message as uppercase hex. Authoritative: 'records' is a \
                          best-effort decode of these bytes."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "message_text".to_string(),
            type_hint: "string".to_string(),
            description: "Lossy text view of the raw bytes, present only when every byte is \
                          printable ASCII. Prefer 'records'."
                .to_string(),
            required: false,
        },
    ])
});

/// NFC card disconnected event
pub static NFC_CARD_DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfc_card_disconnected",
        "NFC card/tag disconnected from reader",
        json!({
            "type": "wait_for_more"
        }),
    )
});

/// The `file_id` both NDEF verbs accept. Shared so the two descriptions cannot drift.
static NDEF_FILE_ID_PARAMETER: LazyLock<Parameter> = LazyLock::new(|| Parameter {
    name: "file_id".to_string(),
    type_hint: "string".to_string(),
    description: "NDEF file identifier as four hex digits, default 'E104'. This is the file \
                  nearly every Type 4 tag's Capability Container points at; NetGet does not \
                  read the CC, so a tag that puts its NDEF file elsewhere needs this."
        .to_string(),
    required: false,
});

/// CLA INS P1 P2 — the shortest thing that can be a command APDU (ISO 7816-4 case 1).
const APDU_HEADER_LEN: usize = 4;

/// Largest `Lc` a short-form APDU can express. The extended form reaches 65535 but needs a
/// three-byte `Lc` and a two-byte `Le`, which `send_apdu` does not build.
const MAX_SHORT_LC: usize = 255;

/// Read one two-hex-digit field, refusing anything that is not exactly one byte.
///
/// The check that matters is the *length*: "4" and "004" both decode or fail in ways that
/// used to slide silently into the APDU and displace every byte after them.
fn one_hex_byte(action: &serde_json::Value, field: &str) -> Result<u8> {
    let raw = action[field]
        .as_str()
        .ok_or_else(|| anyhow!("Missing '{field}' field"))?
        .trim();
    let bytes =
        hex::decode(raw).map_err(|e| anyhow!("'{field}' must be two hex digits ('{raw}'): {e}"))?;
    match bytes.as_slice() {
        [byte] => Ok(*byte),
        other => Err(anyhow!(
            "'{field}' must be exactly one byte (two hex digits), got {} byte(s) from '{raw}'",
            other.len()
        )),
    }
}

/// Validate the optional `file_id` of `read_ndef` / `write_ndef`, defaulting to `E104`.
///
/// E104 is the NDEF file identifier nearly every Type 4 tag uses and the one its Capability
/// Container normally points at. NetGet does not read the CC, so a tag that put its NDEF file
/// somewhere else needs this parameter — which is why it is declared rather than assumed.
fn ndef_file_id_param(action: &serde_json::Value) -> Result<String> {
    let Some(raw) = action["file_id"].as_str().map(str::trim) else {
        return Ok("E104".to_string());
    };
    let bytes = hex::decode(raw)
        .map_err(|e| anyhow!("'file_id' must be four hex digits ('{raw}'): {e}"))?;
    if bytes.len() != 2 {
        return Err(anyhow!(
            "'file_id' must be exactly two bytes (four hex digits), got {} byte(s) from '{raw}'",
            bytes.len()
        ));
    }
    Ok(hex::encode_upper(&bytes))
}

/// NFC client protocol implementation
pub struct NfcClientProtocol;

impl Protocol for NfcClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "nfc"
    }

    fn stack_name(&self) -> &'static str {
        "application"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        // Was `Incomplete`, which means `is_available_to_llm()` returns false — the model
        // could not see this client at all, while the root CLAUDE.md said no Incomplete
        // protocol remained. That was a leftover from when the NDEF verbs did nothing;
        // hiding a protocol is not how an unfinished one is reported (the
        // `bluetooth_ble_beacon` precedent), and the client is reachable, drivable from the
        // dashboard, and has a working vocabulary. `Experimental` with the untested part
        // named is the honest rating.
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "PC/SC (pcsc 2.9) for reader access: SCardListReaders picks a reader, and every \
                 command is SCardConnect + SCardTransmit on a blocking thread, with the card \
                 handle opened and dropped per command so a re-presented card still works. \
                 read_ndef/write_ndef are the NFC Forum Type 4 APDU sequence over that same \
                 path; NDEF records are encoded and decoded in src/client/nfc/ndef.rs.",
            )
            .llm_control(
                "Raw and structured APDUs, NDEF read and write as typed records, and \
                 disconnect. Every card answer raises nfc_apdu_response and every NDEF read \
                 raises nfc_ndef_read, so the model drives the whole conversation, bounded by \
                 MAX_FOLLOWUP_DEPTH.",
            )
            .e2e_testing(
                "The NDEF codec and the APDU builder are unit-tested against literal spec bytes \
                 and need no hardware (tests/client/nfc/). Everything that touches a card is \
                 NOT tested: this machine has no PC/SC reader, a contactless card cannot be \
                 emulated through PC/SC (SCardConnect needs a card in the field), and those \
                 tests are #[ignore]d - which is not evidence. Treat the wire behaviour as \
                 unverified.",
            )
            .notes(
                "Cross-platform via PC/SC (Windows/macOS native, Linux via pcscd). The Type 4 \
                 read/write sequence does NOT consult the Capability Container: it selects the \
                 NDEF file by the file_id parameter, default E104, and ignores the CC's MLe/MLc \
                 read and write limits. Chunked NDEF records are reported, not reassembled, and \
                 nested messages (smart poster, handover) are returned as hex rather than \
                 decoded - deliberately, since a recursive NDEF decoder is the stack-overflow \
                 class the root CLAUDE.md describes.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*NFC_READERS_LISTED_EVENT).clone(),
            (*NFC_CARD_DETECTED_EVENT).clone(),
            (*NFC_APDU_RESPONSE_EVENT).clone(),
            (*NFC_NDEF_READ_EVENT).clone(),
            (*NFC_CARD_DISCONNECTED_EVENT).clone(),
        ]
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["nfc", "smart card", "pcsc", "reader", "apdu", "ndef"]
    }

    fn description(&self) -> &'static str {
        "NFC/Smart card reader client using PC/SC API"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to NFC reader and read tag UID"
    }

    fn group_name(&self) -> &'static str {
        "NFC & Smart Cards"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "reader_index".to_string(),
                type_hint: "number".to_string(),
                description: "Index of PC/SC reader to use (0-based, default: 0)".to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "reader_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name of specific reader to use (optional, overrides reader_index)"
                    .to_string(),
                required: false,
                example: json!("reader_name"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // `list_readers` and `connect_card` used to be advertised here and neither could run:
        // `execute_action` below has no arm for either name, so both came back
        // "Unknown action type" and cost the model a retry. Reader enumeration and explicit
        // card connection are real capabilities worth adding — `connect()` currently picks a
        // reader and waits for a card on its own — but they need PC/SC work in `mod.rs`, not
        // an action declaration on its own.
        vec![ActionDefinition {
            name: "disconnect_card".to_string(),
            description: "Disconnect from current card/tag".to_string(),
            parameters: vec![],
            example: json!({
                "type": "disconnect_card"
            }),
            log_template: None,
        }]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_apdu".to_string(),
                description: "Send APDU command to card/tag (structured format)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "cla".to_string(),
                        type_hint: "string".to_string(),
                        description: "Class byte (hex, e.g., '00')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "ins".to_string(),
                        type_hint: "string".to_string(),
                        description: "Instruction byte (hex, e.g., 'A4' for SELECT)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "p1".to_string(),
                        type_hint: "string".to_string(),
                        description: "Parameter 1 byte (hex)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "p2".to_string(),
                        type_hint: "string".to_string(),
                        description: "Parameter 2 byte (hex)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "Command data (hex string, optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "le".to_string(),
                        type_hint: "string".to_string(),
                        description: "Expected response length (hex, optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_apdu",
                    "cla": "00",
                    "ins": "A4",
                    "p1": "04",
                    "p2": "00",
                    "data": "D2760000850101",
                    "le": "00"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_apdu_raw".to_string(),
                description: "Send raw APDU command (hex string)".to_string(),
                parameters: vec![Parameter {
                    name: "apdu_hex".to_string(),
                    type_hint: "string".to_string(),
                    description: "Raw APDU command as hex string".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_apdu_raw",
                    "apdu_hex": "00A4040007D276000085010100"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "read_ndef".to_string(),
                description: "Read the NDEF message from an NFC Forum Type 4 tag: SELECT the \
                              NDEF application, SELECT the NDEF file, then READ BINARY. The \
                              decoded records arrive as an nfc_ndef_read event."
                    .to_string(),
                parameters: vec![NDEF_FILE_ID_PARAMETER.clone()],
                example: json!({
                    "type": "read_ndef"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "write_ndef".to_string(),
                description: "Write an NDEF message to an NFC Forum Type 4 tag. Records are \
                              typed, never raw bytes: 'text' (with 'language'), 'uri', 'mime' \
                              (with 'mime_type') and 'external' (with 'domain_type'). A URI \
                              must be printable US-ASCII as RFC 3986 requires, and text \
                              carrying control or bidirectional-override characters is \
                              refused - an NDEF URI record is what a phone offers to open. \
                              Nested records (smart poster, handover) are not supported."
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "records".to_string(),
                        type_hint: "array".to_string(),
                        description:
                            "Array of NDEF records: {\"type\": \"text\", \"language\": \"en\", \
                             \"text\": \"...\"}, {\"type\": \"uri\", \"uri\": \"https://...\"}, \
                             {\"type\": \"mime\", \"mime_type\": \"text/plain\", \
                             \"payload_text\": \"...\"} or {\"type\": \"external\", \
                             \"domain_type\": \"example.com:mytype\", \"payload_text\": \"...\"}"
                                .to_string(),
                        required: true,
                    },
                    NDEF_FILE_ID_PARAMETER.clone(),
                ],
                example: json!({
                    "type": "write_ndef",
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
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more events without taking action".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: LLM handles NFC reader operations
            json!({
                "type": "open_client",
                "remote_addr": "nfc:0",
                "base_stack": "nfc",
                "instruction": "Connect to NFC reader and read NDEF data from tag",
                "startup_params": {
                    "reader_index": 0
                }
            }),
            // Script mode: Code-based NFC handling
            json!({
                "type": "open_client",
                "remote_addr": "nfc:0",
                "base_stack": "nfc",
                "startup_params": {
                    "reader_index": 0
                },
                "event_handlers": [{
                    "event_pattern": "nfc_card_detected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<nfc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed NFC action
            json!({
                "type": "open_client",
                "remote_addr": "nfc:0",
                "base_stack": "nfc",
                "startup_params": {
                    "reader_index": 0
                },
                "event_handlers": [{
                    "event_pattern": "nfc_card_detected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "read_ndef"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Client for NfcClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            // NFC client uses PC/SC, not socket addresses
            // Remote addr is ignored, we use reader_index from startup params

            // Build startup params JSON manually since StartupParams doesn't expose to_json
            let startup_params_json = if let Some(ref params) = ctx.startup_params {
                serde_json::json!({
                    "reader_index": params.get_optional_u64("reader_index")?,
                    "reader_name": params.get_optional_string("reader_name")?,
                })
            } else {
                serde_json::json!({})
            };

            crate::client::nfc::NfcClient::connect_with_llm_actions(
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                startup_params_json,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action["type"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;

        match action_type {
            "send_apdu" => {
                // Every field is range-checked *before* it becomes a byte. The previous
                // version interpolated the model's strings straight into a hex string and
                // derived Lc as `data.len() / 2`, so an odd-length `data` floored the
                // length, a `p1` of "4" instead of "04" shifted every byte after it, and
                // more than 255 data bytes made `{:02X}` print three digits - each of
                // which puts a *different, valid-looking* command on the card. A shifted
                // APDU is not a malformed one: it is a command the model did not choose.
                let cla = one_hex_byte(&action, "cla")?;
                let ins = one_hex_byte(&action, "ins")?;
                let p1 = one_hex_byte(&action, "p1")?;
                let p2 = one_hex_byte(&action, "p2")?;

                let mut apdu = vec![cla, ins, p1, p2];

                let data = match action["data"].as_str().map(str::trim).unwrap_or("") {
                    "" => Vec::new(),
                    raw => hex::decode(raw).map_err(|e| {
                        anyhow!("'data' must be an even number of hex digits ('{raw}'): {e}")
                    })?,
                };
                if !data.is_empty() {
                    if data.len() > MAX_SHORT_LC {
                        return Err(anyhow!(
                            "'data' is {} bytes; a short-form APDU carries at most {MAX_SHORT_LC}. \
                             Use send_apdu_raw to build an extended-length APDU, which needs a \
                             three-byte Lc and a two-byte Le",
                            data.len()
                        ));
                    }
                    // Bounds-checked immediately above, so the cast cannot lose a digit.
                    apdu.push(data.len() as u8);
                    apdu.extend_from_slice(&data);
                }

                match action["le"].as_str().map(str::trim).unwrap_or("") {
                    "" => {}
                    raw => {
                        let le = hex::decode(raw)
                            .map_err(|e| anyhow!("'le' must be two hex digits ('{raw}'): {e}"))?;
                        match le.as_slice() {
                            // '00' is the short-form "as much as you have" (256 bytes),
                            // which is why it is not the same as omitting Le entirely.
                            [byte] => apdu.push(*byte),
                            other => {
                                return Err(anyhow!(
                                    "'le' must be exactly one byte (two hex digits) in a \
                                     short-form APDU, got {} byte(s); use send_apdu_raw for the \
                                     extended form",
                                    other.len()
                                ))
                            }
                        }
                    }
                }

                Ok(ClientActionResult::Custom {
                    name: "send_apdu".to_string(),
                    data: json!({ "apdu_hex": hex::encode_upper(&apdu) }),
                })
            }
            "send_apdu_raw" => {
                let raw = action["apdu_hex"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing 'apdu_hex' field"))?
                    .trim();
                // Decoded here rather than only in `mod.rs` so a static handler carrying a
                // bad APDU fails where it is written, not one card exchange later.
                let apdu = hex::decode(raw)
                    .map_err(|e| anyhow!("'apdu_hex' is not valid hexadecimal ('{raw}'): {e}"))?;
                if apdu.len() < APDU_HEADER_LEN {
                    return Err(anyhow!(
                        "'apdu_hex' is {} byte(s); an ISO 7816-4 command APDU is at least the \
                         {APDU_HEADER_LEN}-byte CLA INS P1 P2 header",
                        apdu.len()
                    ));
                }

                Ok(ClientActionResult::Custom {
                    name: "send_apdu".to_string(),
                    data: json!({ "apdu_hex": hex::encode_upper(&apdu) }),
                })
            }
            "read_ndef" => Ok(ClientActionResult::Custom {
                name: "read_ndef".to_string(),
                // `file_id` used to be dropped here while `mod.rs` looked for it, so the
                // parameter could not do anything and every read went to E104.
                data: json!({ "file_id": ndef_file_id_param(&action)? }),
            }),
            "write_ndef" => {
                let records = action["records"]
                    .as_array()
                    .ok_or_else(|| anyhow!("Missing 'records' array"))?;
                // Encode here, so a record the model cannot express is refused at the point
                // it is written rather than becoming a half-written tag. `mod.rs` receives
                // bytes it can put on the wire unchanged.
                let message = crate::client::nfc::ndef::encode_message(records)?;

                Ok(ClientActionResult::Custom {
                    name: "write_ndef".to_string(),
                    data: json!({
                        "file_id": ndef_file_id_param(&action)?,
                        "records": records,
                        "message_hex": hex::encode_upper(&message),
                    }),
                })
            }
            "disconnect_card" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
