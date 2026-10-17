//! USB Smart Card (CCID) protocol actions and events.
//!
//! The server exports a real USB CCID class device over USB/IP; see
//! `src/server/usb/smartcard/mod.rs` and `src/server/usb/smartcard/CLAUDE.md`.
//!
//! NetGet owns the CCID framing and the ISO 7816-4 parsing. The handler owns everything the
//! *card* says: the ATR, whether a card is in the slot, and every response APDU.

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

/// Configure the Answer To Reset the card returns when the host powers it up.
pub static SET_ATR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(set_atr_action);
/// Insert or remove the virtual card.
pub static SET_CARD_PRESENT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(set_card_present_action);
/// Answer a command APDU.
pub static RESPOND_TO_APDU_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(respond_to_apdu_action);

/// Emitted once, after the USB/IP socket is bound and before the first host is accepted, so
/// the card is fully configured by the time anything can power it up.
pub static USB_SMARTCARD_READER_READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_smartcard_reader_ready",
        "Virtual CCID reader bound and ready; configure the card before a host attaches",
        json!({
            "type": "set_atr",
            "atr_hex": "3B901100"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "listen_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address the USB/IP reader is listening on".to_string(),
            required: true,
        },
        Parameter {
            name: "card_type".to_string(),
            type_hint: "string".to_string(),
            description: "Card type this server was started with".to_string(),
            required: true,
        },
        Parameter {
            name: "atr_hex".to_string(),
            type_hint: "string".to_string(),
            description: "ATR currently configured, as uppercase hex".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SET_ATR_ACTION.clone(),
        SET_CARD_PRESENT_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("USB smart card reader ready on {listen_addr} (card={card_type})")
            .with_debug("USB-SmartCard reader_ready: addr={listen_addr} type={card_type}"),
    )
});

/// Emitted when a host completes a USB/IP import of the reader.
pub static USB_SMARTCARD_ATTACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_smartcard_attached",
        "A host attached to the virtual CCID reader over USB/IP",
        json!({
            "type": "set_card_present",
            "present": true
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID of the attached host".to_string(),
            required: true,
        },
        Parameter {
            name: "card_type".to_string(),
            type_hint: "string".to_string(),
            description: "Card type this server was started with".to_string(),
            required: true,
        },
        Parameter {
            name: "card_present".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether a card is currently in the slot".to_string(),
            required: true,
        },
        Parameter {
            name: "atr_hex".to_string(),
            type_hint: "string".to_string(),
            description: "ATR currently configured, as uppercase hex".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SET_ATR_ACTION.clone(),
        SET_CARD_PRESENT_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("USB smart card host attached ({connection_id})")
            .with_debug("USB-SmartCard attached: connection_id={connection_id}"),
    )
});

/// Emitted for every command APDU the host sends in a `PC_to_RDR_XfrBlock`.
pub static USB_SMARTCARD_APDU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_smartcard_apdu_received",
        "Command APDU received by the virtual smart card",
        json!({
            "type": "respond_to_apdu",
            "sw1": "90",
            "sw2": "00"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID of the host that sent the APDU".to_string(),
            required: true,
        },
        Parameter {
            name: "ins_name".to_string(),
            type_hint: "string".to_string(),
            description: "Decoded instruction name: SELECT_BY_AID, SELECT, READ_BINARY, VERIFY, \
                          GET_DATA, INTERNAL_AUTHENTICATE, ... or UNKNOWN"
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
            description: "Command data field as uppercase hex. Hex is used because this field is \
                          opaque bytes chosen by the host; prefer data_text when it is present."
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
            name: "application_id".to_string(),
            type_hint: "string".to_string(),
            description: "For SELECT_BY_AID only: the application identifier the host selected, \
                          as uppercase hex"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "le".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum response length the host will accept, null if absent".to_string(),
            required: false,
        },
        Parameter {
            name: "card_type".to_string(),
            type_hint: "string".to_string(),
            description: "Card type this server was started with".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![RESPOND_TO_APDU_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("USB smart card APDU {ins_name} (Lc={lc})")
            .with_debug(
                "USB-SmartCard apdu_received: {ins_name} cla={cla} ins={ins} p1={p1} p2={p2} \
                 lc={lc}",
            ),
    )
});

/// Emitted when a host's USB/IP session ends.
pub static USB_SMARTCARD_DETACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_smartcard_detached",
        "The host detached from the virtual CCID reader. Nothing can be written to a reader no \
         host is attached to, so this is informational: note it in the log or in memory.",
        // Must be one of the *common* actions. The event is `with_no_actions()`, so
        // `call_llm` offers the model nothing but the common set — an example naming
        // `wait_for_more` (which this protocol neither declares nor executes) told the
        // model to answer with an action that would be rejected as unknown.
        json!({
            "type": "append_to_log",
            "message": "smart card host conn-2 detached"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID of the host that detached".to_string(),
        required: true,
    }])
    // Nothing can be written to a reader no host is attached to.
    .with_no_actions()
    .with_log_template(
        LogTemplate::new()
            .with_info("USB smart card host detached ({connection_id})")
            .with_debug("USB-SmartCard detached: connection_id={connection_id}"),
    )
});

fn set_atr_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_atr".to_string(),
        description: "Set the Answer To Reset (ATR) the card returns when the host powers it up \
                      (CCID PC_to_RDR_IccPowerOn). The ATR is how a host identifies the card."
            .to_string(),
        parameters: vec![Parameter {
            name: "atr_hex".to_string(),
            type_hint: "string".to_string(),
            description: "ATR bytes as a hex string, at most 261 bytes. ISO 7816-3 defines the \
                          ATR as raw bytes, so hex is the only faithful form. Example: \
                          '3B901100' is a minimal valid T=0 ATR."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "set_atr",
            "atr_hex": "3B901100"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB smart card set ATR")
                .with_debug("USB-SmartCard set_atr: atr={atr_hex}"),
        ),
    }
}

fn set_card_present_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_card_present".to_string(),
        description: "Insert or remove the virtual card. With no card in the slot the reader \
                      refuses power-on and APDU transfers, and reports the change to the host \
                      on the interrupt endpoint. A card is present by default."
            .to_string(),
        parameters: vec![Parameter {
            name: "present".to_string(),
            type_hint: "boolean".to_string(),
            description: "true to insert the card, false to remove it".to_string(),
            required: true,
        }],
        example: json!({
            "type": "set_card_present",
            "present": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB smart card present={present}")
                .with_debug("USB-SmartCard set_card_present: present={present}"),
        ),
    }
}

fn respond_to_apdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "respond_to_apdu".to_string(),
        description: "Answer the command APDU with an optional response body and a REQUIRED \
                      two-byte status word. This is the only way to reply; if you do not use \
                      it, or you use it without naming sw1 and sw2, the card answers 6F00 \
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
                description: "Response body as a hex string, for genuinely binary answers such \
                              as a certificate or a TLV object. Mutually exclusive with data_text."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "sw1".to_string(),
                type_hint: "string".to_string(),
                description: "Status byte 1 as two hex digits. REQUIRED - there is no default, \
                              because the only plausible default is success. Approve with '90'; \
                              refuse with '69' (security status not satisfied), '6A' (wrong \
                              parameters) or '6D' (instruction not supported)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "sw2".to_string(),
                type_hint: "string".to_string(),
                description: "Status byte 2 as two hex digits. REQUIRED. '90' '00' together \
                              mean success; naming both bytes is what makes approving a \
                              command a deliberate act rather than an omission."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "respond_to_apdu",
            "data_hex": "6F0A8408A000000308000010",
            "sw1": "90",
            "sw2": "00"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB smart card APDU response SW={sw1}{sw2}")
                .with_debug("USB-SmartCard respond_to_apdu: data={data_hex} sw1={sw1} sw2={sw2}"),
        ),
    }
}

/// Parse a hex string, tolerating the spaces a model naturally writes between bytes, and
/// rejecting anything else so a malformed value fails where it is produced rather than being
/// logged as if it had been accepted.
pub fn parse_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&compact).map_err(|e| anyhow!("Invalid hex in '{field}' ({value}): {e}"))
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

/// USB Smart Card (CCID) protocol.
pub struct UsbSmartCardProtocol;

impl UsbSmartCardProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UsbSmartCardProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for UsbSmartCardProtocol {
    fn protocol_name(&self) -> &'static str {
        "usb-smartcard"
    }

    fn stack_name(&self) -> &'static str {
        "USB Smart Card Reader (CCID)"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "card_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Card type, reported back to you in every smart card event so a handler \
                          can branch on it: 'piv', 'openpgp', 'generic' (default). The server \
                          does not interpret it — nothing is answered by built-in card logic."
                        .to_string(),
                required: false,
                example: json!("generic"),
                default: None,
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a peer that has only connected may send no USB/IP message at \
                          all before the server closes it. Default 30. USB/IP is \
                          client-speaks-first and nothing here answers a peer that has not \
                          asked - `usbip attach` and `usbip list -r` both write their request \
                          as soon as the socket is up - so a short bound is the honest one. \
                          Raise it only if your host is reached over a link where a handshake \
                          can take that long."
                        .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_FIRST_MESSAGE_TIMEOUT.as_secs()
                )),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an attached host may go without sending a further USB/IP \
                          message before the server closes the session. Default 1800. USB/IP \
                          has no keepalive and nothing obliges an attached host to speak - a \
                          reader a host has imported and is asking nothing of is idle by design \
                          - so this is deliberately long and exists to reap a peer that is gone \
                          rather than to police one that is here. Lower it if you are exporting \
                          to strangers."
                    .to_string(),
                required: false,
                example: json!(1800),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_IDLE_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![SET_ATR_ACTION.clone(), SET_CARD_PRESENT_ACTION.clone()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![RESPOND_TO_APDU_ACTION.clone()]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*USB_SMARTCARD_READER_READY_EVENT).clone(),
            (*USB_SMARTCARD_ATTACHED_EVENT).clone(),
            (*USB_SMARTCARD_APDU_RECEIVED_EVENT).clone(),
            (*USB_SMARTCARD_DETACHED_EVENT).clone(),
        ]
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "usb",
            "smartcard",
            "smart card",
            "ccid",
            "apdu",
            "iso7816",
            "piv",
            "pcsc",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Real USB CCID class device (interface class 0x0B) exported over USB/IP, with a \
                 hand-written usbip::UsbInterfaceHandler: CCID rev 1.1 class descriptor, bulk \
                 IN/OUT and interrupt IN endpoints, and the IccPowerOn / IccPowerOff / \
                 GetSlotStatus / XfrBlock / Get-Set-ResetParameters / Escape / Abort / IccClock \
                 message set, each answered by the matching RDR_to_PC_* with bSeq echoed. No \
                 external daemon: vpcd and vpicc are gone.",
            )
            .llm_control(
                "The ATR and card presence at startup and on attach; the response body and \
                 ISO 7816-4 status word for every command APDU. Nothing is answered by built-in \
                 card logic — there is no file system, PIN store or key store — and a handler \
                 that produces no respond_to_apdu gets 6F00 rather than a success.",
            )
            .e2e_testing(
                "Mocked E2E drives a real USB/IP client over TCP (OP_REQ_IMPORT then bulk \
                 transfers) and asserts the CCID response bytes, including the ATR returned by \
                 IccPowerOn and the response APDU returned by XfrBlock \
                 (tests/server/usb_smartcard/e2e_test.rs). No hardware, no kernel module, no root.",
            )
            .notes(
                "All four events fire: usb_smartcard_reader_ready at bind, usb_smartcard_attached \
                 on USB/IP import, usb_smartcard_apdu_received per XfrBlock, \
                 usb_smartcard_detached when the session ends. XfrBlock before IccPowerOn, or \
                 with no card in the slot, is refused by the reader without an LLM call. \
                 Attaching from a real Linux host (usbip attach + pcscd) needs vhci-hcd and root \
                 and has not been tested. Short APDU level of exchange only: CCID messages are \
                 capped at the advertised dwMaxCCIDMessageLength of 271 bytes, so extended APDUs \
                 beyond that are refused. No T=0/T=1 transmission layer, no PPS, no time \
                 extension while the handler thinks.",
            )
            // The USB/IP screen in `src/server/usb/guard.rs` refuses a `USBIP_CMD_SUBMIT`
            // declaring more than this, before the crate allocates from the number.
            .max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Virtual USB CCID smart card reader answering ISO 7816-4 APDUs over USB/IP"
    }

    fn example_prompt(&self) -> &'static str {
        "Create a virtual USB smart card reader on port {AVAILABLE_PORT} that answers APDU commands"
    }

    fn group_name(&self) -> &'static str {
        "USB Devices"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every APDU with a 90 00 success status, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "usb_smartcard_apdu_received":
    actions = [{"type": "respond_to_apdu", "sw1": "90", "sw2": "00"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model answers every APDU.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-smartcard",
                "instruction": "Act as a PIV smart card: answer SELECT for the PIV AID and refuse \
                                everything else with 6A82",
                "startup_params": {
                    "card_type": "piv"
                }
            }),
            // Script mode: deterministic APDU handling, no LLM round-trip per command.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-smartcard",
                "startup_params": {
                    "card_type": "generic"
                },
                "event_handlers": [{
                    "event_pattern": "usb_smartcard_apdu_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: one fixed ATR and one fixed answer.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-smartcard",
                "startup_params": {
                    "card_type": "generic"
                },
                "event_handlers": [
                    {
                        "event_pattern": "usb_smartcard_reader_ready",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "set_atr",
                                "atr_hex": "3B901100"
                            }]
                        }
                    },
                    {
                        "event_pattern": "usb_smartcard_apdu_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "respond_to_apdu",
                                "sw1": "90",
                                "sw2": "00"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for UsbSmartCardProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let card_type = match ctx.startup_params {
                Some(ref params) => params.get_optional_string("card_type")?,
                None => None,
            };

            // Read here rather than through a shared helper so the parameter names appear
            // in this protocol's own source: `tests/startup_param_drift_test.rs` proves a
            // declared knob is wired by finding its name outside the declaration, and a read
            // one directory up is invisible to it — and to the next person reading this file.
            // The numbers and the argument for them are in `src/server/usb/guard.rs`.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            crate::server::usb::smartcard::UsbSmartCardServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                card_type,
                first_byte_timeout_secs,
                idle_timeout_secs,
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
                if atr.len() > super::ccid::MAX_PAYLOAD_LEN {
                    return Err(anyhow!(
                        "'atr_hex' is {} bytes; a CCID data block carries at most {}",
                        atr.len(),
                        super::ccid::MAX_PAYLOAD_LEN
                    ));
                }
                Ok(ActionResult::Custom {
                    name: "set_atr".to_string(),
                    data: json!({ "atr_hex": hex::encode_upper(&atr) }),
                })
            }
            "set_card_present" => {
                let present = action
                    .get("present")
                    .and_then(|v| v.as_bool())
                    .context("Missing or non-boolean 'present' parameter")?;
                Ok(ActionResult::Custom {
                    name: "set_card_present".to_string(),
                    data: json!({ "present": present }),
                })
            }
            "respond_to_apdu" => {
                let data_hex = action.get("data_hex").and_then(|v| v.as_str());
                let data_text = action.get("data_text").and_then(|v| v.as_str());

                // Normalise both spellings of the body to hex so the server has exactly one
                // form to decode. Refusing the ambiguous case is the point: "48656c6c6f" is
                // simultaneously valid text and valid hex and only the sender knows which it
                // meant.
                let body = match (data_text, data_hex) {
                    (Some(text), None) => text.as_bytes().to_vec(),
                    (None, Some(hex_str)) => parse_hex("data_hex", hex_str)?,
                    (None, None) => Vec::new(),
                    (Some(_), Some(_)) => {
                        return Err(anyhow!(
                            "respond_to_apdu accepts 'data_text' or 'data_hex', not both"
                        ))
                    }
                };

                // No default, deliberately. The only status word a default could reasonably
                // be is 9000 - success - so the most degenerate thing a model can emit, a bare
                // `{"type": "respond_to_apdu"}`, completed a VERIFY or an INTERNAL
                // AUTHENTICATE. That is an *omission* approving an authentication, which is
                // the OAuth2 fail-open shape the root CLAUDE.md calls the most dangerous
                // pattern in this codebase.
                //
                // It matters more here than the shape alone suggests, and for the opposite
                // reason to the obvious one. This server holds no PIN and no key - `crypto.rs`
                // was deleted precisely because a protocol must not implement storage - so the
                // model *is* the access control. There is no second gate behind it to catch a
                // status word nobody chose.
                //
                // Success has to be named, the way `eapol` gives EAP-Success its own eight
                // literal octets rather than a boolean anything could flip. `src/server/nfc/`
                // had the identical defect in the identical two layers and was fixed the same
                // way.
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
                let sw1 = parse_status_byte("sw1", sw1)?;
                let sw2 = parse_status_byte("sw2", sw2)?;

                Ok(ActionResult::Custom {
                    name: "respond_to_apdu".to_string(),
                    data: json!({
                        "data_hex": hex::encode_upper(&body),
                        "sw1": format!("{:02X}", sw1),
                        "sw2": format!("{:02X}", sw2),
                    }),
                })
            }
            other => Err(anyhow!("Unknown action type: {}", other)),
        }
    }
}
