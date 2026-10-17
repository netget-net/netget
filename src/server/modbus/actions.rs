//! Modbus TCP protocol actions.
//!
//! The model plays the PLC. It is asked what a bank of coils or registers *reads as*, and
//! whether a write is accepted — not how to frame a reply. Transaction id, unit id,
//! function code, byte counts and the write echo are all reconstructed by
//! `src/server/modbus/mod.rs` from the request it parsed, so the model cannot break
//! framing and never has to echo an identifier back.
//!
//! Every action therefore returns [`ActionResult::Custom`] carrying structured data
//! (booleans, integers, an exception code) rather than bytes.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::codec;

/// Name carried by the [`ActionResult::Custom`] results this protocol produces.
pub const RESULT_BITS: &str = "modbus_bits";
pub const RESULT_REGISTERS: &str = "modbus_registers";
pub const RESULT_WRITE_ACK: &str = "modbus_write_ack";
pub const RESULT_EXCEPTION: &str = "modbus_exception";

/// Modbus TCP server protocol handler.
#[derive(Default)]
pub struct ModbusProtocol;

impl ModbusProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for ModbusProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "unit_id".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Modbus unit (slave) identifier this device answers for, 0-255. When set, a \
                 request addressed to any other unit id is answered with exception 0x0B \
                 (gateway target device failed to respond), which is how a real Modbus/TCP \
                 gateway behaves. When omitted the server answers on every unit id, which is \
                 what most Modbus/TCP devices do."
                        .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Seconds a newly connected peer may send nothing before the server \
                              closes it, silently. Default 30: a Modbus client sends its first \
                              request as soon as it connects."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Seconds a peer that has already sent a request may then send \
                              nothing before the server closes it. Default 600, twice the window \
                              a `manual` rule gives a human to answer; a SCADA master polls every \
                              few seconds, so lower it (real gateways use ~60) when no human is \
                              answering."
                    .to_string(),
                required: false,
                example: json!(600),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // A Modbus server never speaks unprompted: every frame on the wire is a response
        // to a request. There is nothing meaningful to trigger from user input.
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_modbus_bits_action(),
            send_modbus_registers_action(),
            send_modbus_write_ack_action(),
            send_modbus_exception_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Modbus"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_modbus_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MODBUS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately distinctive: no bare "plc", "industrial" or "register", which would
        // collide with unrelated requests the way the BLE profiles collided with FTP/NFS.
        vec![
            "modbus",
            "modbus tcp",
            "modbus/tcp",
            "plc simulator",
            "scada device",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // STABLE against the six conditions in the root CLAUDE.md, re-derived from source on
            // 26 September 2026. Read `.e2e_testing` and `.notes`, and "Maturity: the six
            // conditions" in src/server/modbus/CLAUDE.md, before quoting it: the rating covers
            // the evidence for the surface this server implements, which is Modbus TCP with
            // eight function codes.
            .state(DevelopmentState::Stable)
            // 502 is below 1024 so this requirement genuinely fires; server_startup only
            // enforces it when the port actually requested is privileged, so running on a
            // high port as an unprivileged user still works.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(502))
            .well_known_port(502)
            .implementation(
                "Hand-rolled MBAP + PDU codec (src/server/modbus/codec.rs); function codes \
                 1/2/3/4/5/6/15/16 with spec-mandated exception responses",
            )
            .llm_control(
                "Coil and register values, whether a write is accepted, and which Modbus \
                 exception to raise. Framing (transaction id, unit id, byte counts, write \
                 echo) is server-side",
            )
            .e2e_testing(
                "STABLE rests on all six conditions, each checked against source and by running \
                 it on 26 September 2026. (1) TWO independent clients, neither #[ignore]d and \
                 neither able to skip, each driving ALL EIGHT function codes this server \
                 implements with every answer asserted on what the client decoded: tokio-modbus \
                 0.17 (e2e_test.rs::test_modbus_reads_writes_and_exceptions_against_tokio_modbus \
                 -- the server does not link it) and mbpoll on libmodbus, a C implementation \
                 (real_client_test.rs::test_modbus_reads_writes_and_exceptions_against_mbpoll, \
                 which FAILS when mbpoll is absent). Register values and coil/discrete-input \
                 bits are asserted in order, ten bits across a byte boundary; FC 5/6/15/16 are \
                 accepted only if the values each client packed reached the model as sent, and \
                 each client validates the echo; each has an exception path decoded as an \
                 exception, not data. (2) pcap_oracle_test.rs runs Wireshark's mbtcp dissector \
                 over one session of all eight function codes and an exception, both \
                 directions. (3) fuzz/fuzz_targets/modbus_adu.rs: 226,125 runs in 61s, clean. \
                 Modbus does not nest, so the corpus seeds every declared length instead of a \
                 depth bomb (max_adu, over_max_adu, declared_longer_than_sent, each quantity \
                 limit), and the target asserts framing round-trips and that every accepted \
                 read can be answered. (4) bounds_test.rs and connection_bounds_test.rs drive \
                 every declared bound from the wire -- MAX_ADU_LEN (inbound, via the MBAP \
                 length field: 260 octets answered, 261 closed), MAX_BUFFERED (2080 queued \
                 tolerated, 2081 closed), MAX_CONNECTIONS (256 admitted, 257th closed \
                 silently, the slot returned after both kinds of close), both read deadlines, \
                 the four quantity limits and the unit_id filter -- each verified by REMOVING \
                 the bound and watching its test fail. (5) Both CLAUDE.md files were re-read \
                 against source; the false claims are corrected in them. (6) No #[ignore] and \
                 no skip gate in tests/server/modbus/. UNPROVEN, because none of it is \
                 implemented: Modbus RTU/ASCII, function codes outside 1/2/3/4/5/6/15/16, \
                 Modbus Security; and no real PLC has been pointed at it.",
            )
            .notes(
                "The rating covers Modbus TCP with function codes 1/2/3/4/5/6/15/16 and nothing \
                 else; any other function code is answered with exception 0x01. A connection \
                 the server closes (framing error, queue overrun) stops its reader and returns \
                 its connection-cap slot at once, even while the peer holds its end open. A \
                 model answering with an action the event does \
                 not offer (bits for a register read) is refused by the LLM layer as an unknown \
                 action and logged decision=fail_closed_llm_error; the wire answer is exception \
                 0x04 either way. Untested: any real PLC, and pymodbus",
            )
            .max_inbound_bytes(crate::server::modbus::codec::MAX_ADU_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Modbus TCP server impersonating a PLC or industrial sensor"
    }

    fn example_prompt(&self) -> &'static str {
        "Pretend to be a water treatment PLC via modbus on port 5020; holding register 0 is \
         tank level in cm around 180, register 1 is pump speed in RPM"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every read with a zero-filled register bank of
        // the requested width, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "modbus_read_registers":
    qty = event.get("quantity") or 1
    start = event.get("start_address") or 0
    actions = [{"type": "send_modbus_registers",
                "registers": {str(a): 0 for a in range(start, start + qty)}}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model invents self-consistent telemetry per request.
            json!({
                "type": "open_server",
                "port": 5020,
                "base_stack": "modbus",
                "instruction": "Act as a water treatment PLC. Holding register 0 is the tank \
                                level in cm (drifts around 180), register 1 is pump speed in \
                                RPM. Coil 0 is the pump run command. Reject writes to \
                                registers above 9 with illegal_data_address."
            }),
            // Script mode: deterministic register bank held by the script.
            json!({
                "type": "open_server",
                "port": 5020,
                "base_stack": "modbus",
                "event_handlers": [{
                    "event_pattern": "modbus_read_registers",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: a fixed answer for every read of the same width.
            json!({
                "type": "open_server",
                "port": 5020,
                "base_stack": "modbus",
                "event_handlers": [
                    {
                        "event_pattern": "modbus_read_registers",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_modbus_exception",
                                "exception_code": 2
                            }]
                        }
                    },
                    {
                        "event_pattern": "modbus_write_request",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_modbus_exception",
                                "exception_code": 2
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for ModbusProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Propagate, never unwrap: these values come from the model or an MCP caller.
            let unit_id = match ctx.startup_params.as_ref() {
                Some(p) => p.get_optional_u64("unit_id")?,
                None => None,
            };
            let unit_id = match unit_id {
                Some(v) if v > 255 => {
                    anyhow::bail!("unit_id must be between 0 and 255, got {v}");
                }
                Some(v) => Some(v as u8),
                None => None,
            };

            // A zero deadline would close every connection before it could speak, so it is
            // refused rather than honoured.
            let secs = |name: &str, default: std::time::Duration| -> Result<std::time::Duration> {
                let value = match ctx.startup_params.as_ref() {
                    Some(p) => p.get_optional_u64(name)?,
                    None => None,
                };
                match value {
                    None => Ok(default),
                    Some(0) => anyhow::bail!("{name} must be at least 1 second, got 0"),
                    Some(n) => Ok(std::time::Duration::from_secs(n)),
                }
            };
            let first_byte_timeout =
                secs("first_byte_timeout_secs", super::FIRST_BYTE_READ_TIMEOUT)?;
            let idle_timeout = secs("idle_timeout_secs", super::IDLE_BETWEEN_REQUESTS_TIMEOUT)?;

            let listen_addr = ctx.legacy_listen_addr();
            super::ModbusServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                unit_id,
                ctx.server_id,
                first_byte_timeout,
                idle_timeout,
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
            "send_modbus_bits" => {
                if let Some(map) = action.get("bits") {
                    let bits = address_map(map, "send_modbus_bits", "bits", |v| {
                        v.as_bool().map(serde_json::Value::Bool).ok_or_else(|| {
                            format!(
                                "must be true or false, got {v}. Coils and discrete inputs \
                                 are single bits; use send_modbus_registers for 16-bit values."
                            )
                        })
                    })?;
                    return Ok(ActionResult::Custom {
                        name: RESULT_BITS.to_string(),
                        data: json!({ "bits": bits }),
                    });
                }
                // The positional form, one value per requested address starting at
                // `start_address`: still accepted, so handlers written against it keep working.
                let values = action.get("values").and_then(|v| v.as_array()).context(
                    "send_modbus_bits requires 'bits', an object of address -> true/false",
                )?;

                let bits: Vec<bool> = values
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        v.as_bool().ok_or_else(|| {
                            anyhow::anyhow!(
                                "send_modbus_bits 'values'[{i}] must be true or false, got {v}. \
                                 Coils and discrete inputs are single bits; use \
                                 send_modbus_registers for 16-bit values."
                            )
                        })
                    })
                    .collect::<Result<_>>()?;

                if bits.is_empty() {
                    anyhow::bail!(
                        "send_modbus_bits 'values' must not be empty; return one boolean per \
                         coil requested"
                    );
                }

                Ok(ActionResult::Custom {
                    name: RESULT_BITS.to_string(),
                    data: json!({ "values": bits }),
                })
            }
            "send_modbus_registers" => {
                if let Some(map) = action.get("registers") {
                    let registers = address_map(map, "send_modbus_registers", "registers", |v| {
                        match v.as_u64() {
                            Some(n) if n <= u64::from(u16::MAX) => Ok(json!(n)),
                            _ => Err(format!(
                                "must be a whole number between 0 and 65535, got {v}. Modbus \
                                 registers are unsigned 16-bit; encode signed or floating point \
                                 values yourself (two's complement, or two registers for a \
                                 32-bit float)."
                            )),
                        }
                    })?;
                    return Ok(ActionResult::Custom {
                        name: RESULT_REGISTERS.to_string(),
                        data: json!({ "registers": registers }),
                    });
                }
                // The positional form, one value per requested register starting at
                // `start_address`: still accepted, so handlers written against it keep working.
                let values = action.get("values").and_then(|v| v.as_array()).context(
                    "send_modbus_registers requires 'registers', an object of address -> \
                         value 0-65535",
                )?;

                let registers: Vec<u16> = values
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let n = v.as_u64().ok_or_else(|| {
                            anyhow::anyhow!(
                                "send_modbus_registers 'values'[{i}] must be a whole number \
                                 between 0 and 65535, got {v}. Modbus registers are unsigned \
                                 16-bit; encode signed or floating point values yourself \
                                 (e.g. two's complement, or two registers for a 32-bit float)."
                            )
                        })?;
                        if n > 65535 {
                            anyhow::bail!(
                                "send_modbus_registers 'values'[{i}] = {n} exceeds 65535; a \
                                 Modbus register holds 16 bits"
                            );
                        }
                        Ok(n as u16)
                    })
                    .collect::<Result<_>>()?;

                if registers.is_empty() {
                    anyhow::bail!(
                        "send_modbus_registers 'values' must not be empty; return one number \
                         per register requested"
                    );
                }

                Ok(ActionResult::Custom {
                    name: RESULT_REGISTERS.to_string(),
                    data: json!({ "values": registers }),
                })
            }
            "send_modbus_write_ack" => Ok(ActionResult::Custom {
                name: RESULT_WRITE_ACK.to_string(),
                data: json!({}),
            }),
            "send_modbus_exception" => {
                let raw = action
                    .get("exception_code")
                    .context("send_modbus_exception requires an 'exception_code'")?;

                let code = if let Some(n) = raw.as_u64() {
                    // Checked against the codes the specification actually defines, not
                    // against `u8`. A bare range check plus `n as u8` would have put 0x104
                    // on the wire as 0x04 (server device failure) and 0x07 as an exception
                    // no client can interpret.
                    if n > u8::MAX as u64
                        || codec::exception_name(n as u8) == codec::UNKNOWN_EXCEPTION
                    {
                        anyhow::bail!(
                            "send_modbus_exception 'exception_code' {n} is not a Modbus \
                             exception code. The specification defines 1 (illegal function), \
                             2 (illegal data address), 3 (illegal data value), 4 (server \
                             device failure), 5 (acknowledge), 6 (server device busy), \
                             8 (memory parity error), 10 (gateway path unavailable) and \
                             11 (gateway target device failed to respond)."
                        );
                    }
                    n as u8
                } else if let Some(s) = raw.as_str() {
                    codec::exception_code_from_name(s).ok_or_else(|| {
                        anyhow::anyhow!(
                            "send_modbus_exception 'exception_code' {s:?} is not a known \
                             exception name. Use a number (1-4) or one of \
                             \"illegal_function\", \"illegal_data_address\", \
                             \"illegal_data_value\", \"server_device_failure\"."
                        )
                    })?
                } else {
                    anyhow::bail!(
                        "send_modbus_exception 'exception_code' must be a number (1-4) or a \
                         name such as \"illegal_data_address\", got {raw}"
                    );
                };

                Ok(ActionResult::Custom {
                    name: RESULT_EXCEPTION.to_string(),
                    data: json!({
                        "exception_code": code,
                        "exception_name": codec::exception_name(code),
                    }),
                })
            }
            // Not offered to the model (a Modbus server answers requests, it does not hang
            // up on its own), but the dashboard's "disconnect this peer" injects it through
            // the peer command task, which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Modbus action: {action_type}")),
        }
    }
}

/// Validate an address-keyed answer (`{"500": 0, "501": 0}`) and normalise its keys.
///
/// Every key must be a Modbus address, 0-65535, written in decimal; it is re-keyed in canonical
/// form (`"007"` becomes `"7"`) so the connection loop can look each requested address up by
/// its plain decimal spelling. Each value goes through `value` and is refused with the address
/// named. An empty object is a valid answer: the device has none of the addresses asked for,
/// which the connection loop answers as exception 2.
fn address_map(
    map: &serde_json::Value,
    action: &str,
    field: &str,
    value: impl Fn(&serde_json::Value) -> std::result::Result<serde_json::Value, String>,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let object = map.as_object().with_context(|| {
        format!(
            "{action} '{field}' must be an object keyed by address, e.g. {{\"40\": ...}}, got \
             {map}"
        )
    })?;
    let mut out = serde_json::Map::new();
    for (key, raw) in object {
        let address: u16 = key.trim().parse().map_err(|_| {
            anyhow::anyhow!(
                "{action} '{field}' key {key:?} is not a Modbus address; keys are the decimal \
                 addresses 0-65535 the values belong to"
            )
        })?;
        let checked = value(raw)
            .map_err(|reason| anyhow::anyhow!("{action} '{field}'[{address}] {reason}"))?;
        out.insert(address.to_string(), checked);
    }
    Ok(out)
}

// ===========================================================================
// Action definitions
// ===========================================================================

fn send_modbus_bits_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_modbus_bits".to_string(),
        description:
            "Answer a coil or discrete-input read (function code 1 or 2) with the bits this \
             device has, as an object keyed by address. Include only addresses the \
             instructions give this device. NetGet answers the read from your entries, and \
             any requested address missing from them is answered as exception 2 (illegal data \
             address) - so never add an entry for an address the device does not have. Where \
             the instructions leave a value open, you decide what the device reads as - \
             invent plausible, self-consistent state and use set_memory/append_memory to keep \
             it consistent across requests."
                .to_string(),
        parameters: vec![Parameter {
            name: "bits".to_string(),
            type_hint: "object".to_string(),
            description: "Address (as a string) -> true or false, one entry per coil or \
                 discrete input this device has."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_modbus_bits",
            "bits": {"40": true, "41": false}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {output_bytes}B coils")
                .with_debug("Modbus bits response")
                .with_trace("Modbus bits: {json_pretty(.)}"),
        ),
    }
}

fn send_modbus_registers_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_modbus_registers".to_string(),
        description:
            "Answer a holding-register or input-register read (function code 3 or 4) with the \
             registers this device has, as an object keyed by register address. Include only \
             addresses the instructions give this device. NetGet answers the read from your \
             entries, and any requested address missing from them is answered as exception 2 \
             (illegal data address) - so never add an entry for an address the device does \
             not have. Values are whole numbers 0-65535. Where the instructions leave a value \
             open, you decide what the device reads as: a tank level, a motor current, a fault \
             word."
                .to_string(),
        parameters: vec![Parameter {
            name: "registers".to_string(),
            type_hint: "object".to_string(),
            description: "Register address (as a string) -> value 0-65535, one entry per \
                 register this device has."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_modbus_registers",
            "registers": {"40": 1834, "41": 1450}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {output_bytes}B registers")
                .with_debug("Modbus register response")
                .with_trace("Modbus registers: {json_pretty(.)}"),
        ),
    }
}

fn send_modbus_write_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_modbus_write_ack".to_string(),
        description:
            "Accept a write (function code 5, 6, 15 or 16) and confirm it. Modbus confirms a \
             write by echoing it, which is built for you from the request - this action takes \
             no parameters. Use it when the device would allow the write; use \
             send_modbus_exception when it would not (a read-only address, a value outside \
             the range the equipment accepts, an interlock)."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "send_modbus_write_ack" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> write accepted")
                .with_debug("Modbus write acknowledged"),
        ),
    }
}

fn send_modbus_exception_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_modbus_exception".to_string(),
        description: "Refuse the request with a Modbus exception response. This is the explicit \
             refusal path and is structurally distinct from answering with values - use it \
             whenever the device would not or could not serve the request."
            .to_string(),
        parameters: vec![Parameter {
            name: "exception_code".to_string(),
            type_hint: "integer or string".to_string(),
            description: "1 / \"illegal_function\" - this device does not implement the function. \
                 2 / \"illegal_data_address\" - the address or range does not exist on this \
                 device (the most common refusal). \
                 3 / \"illegal_data_value\" - the value is outside what the equipment \
                 accepts. \
                 4 / \"server_device_failure\" - an unrecoverable fault occurred while \
                 handling the request. \
                 6 / \"server_device_busy\" - the device is busy; the client should retry."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_modbus_exception",
            "exception_code": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> exception {exception_code}")
                .with_debug("Modbus exception {exception_code}"),
        ),
    }
}

pub static SEND_MODBUS_BITS_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_modbus_bits_action);
pub static SEND_MODBUS_REGISTERS_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_modbus_registers_action);
pub static SEND_MODBUS_WRITE_ACK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_modbus_write_ack_action);
pub static SEND_MODBUS_EXCEPTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_modbus_exception_action);

// ===========================================================================
// Event types
// ===========================================================================

/// Parameters shared by every Modbus event.
fn common_event_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "unit_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Modbus unit (slave) identifier the request was addressed to".to_string(),
            required: true,
        },
        Parameter {
            name: "function_code".to_string(),
            type_hint: "integer".to_string(),
            description: "Numeric Modbus function code of the request".to_string(),
            required: true,
        },
        Parameter {
            name: "function".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the function, e.g. read_holding_registers".to_string(),
            required: true,
        },
        Parameter {
            name: "start_address".to_string(),
            type_hint: "integer".to_string(),
            description:
                "First address requested, 0-65535. This is the raw protocol address: a client \
                 asking for '40001' in the classic data-model numbering sends 0 here."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "quantity".to_string(),
            type_hint: "integer".to_string(),
            description: "How many coils or registers the request covers".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which answer this request takes, naming the addresses it covers"
                .to_string(),
            required: true,
        },
    ]
}

/// The `answer_with` event field: the answer this request takes, naming the exact addresses.
///
/// **A read is answered from an address-keyed map, and NetGet does the comparison.** Told "ten
/// holding registers at addresses 0 to 9, all zero. There is nothing at any other address",
/// llama3.1:8b answered a read of 500-501 by describing the whole device - ten zeros - under
/// every wording that asked it to compare 500 against 0-9 first (0/5 to 3/5 across five
/// wordings, recorded in `src/server/modbus/CLAUDE.md`). Its reasoning said the device "has
/// only holding registers 0 to 9, which is exactly what the client is asking for": it restates
/// the instruction rather than comparing addresses. Keyed by address, that same answer is a
/// correct one - `{"0": 0, ..., "9": 0}` has no entry for 500, and a missing entry is exception
/// 2 - so the hint asks for the device's registers and says what a missing one means, and asks
/// for no comparison at all.
///
/// A write carries no values to key, so it keeps the check-first wording: the addresses, a
/// worked comparison computed from the request itself, and the literal exception-2 action.
pub fn answer_with_for_request(request: &codec::ModbusRequest) -> String {
    use codec::ModbusRequest as R;
    let start = u32::from(request.start_address());
    let quantity = u32::from(request.quantity());
    let (singular, plural) = match request {
        R::ReadCoils { .. } | R::WriteSingleCoil { .. } | R::WriteMultipleCoils { .. } => {
            ("coil", "coils")
        }
        R::ReadDiscreteInputs { .. } => ("discrete input", "discrete inputs"),
        R::ReadHoldingRegisters { .. }
        | R::WriteSingleRegister { .. }
        | R::WriteMultipleRegisters { .. } => ("holding register", "holding registers"),
        R::ReadInputRegisters { .. } => ("input register", "input registers"),
    };
    let addresses = if quantity <= 1 {
        format!("{singular} {start}")
    } else {
        format!("{plural} {start} to {}", start + quantity - 1)
    };
    let keyed = match request {
        R::ReadCoils { .. } | R::ReadDiscreteInputs { .. } => Some(("send_modbus_bits", "bits")),
        R::ReadHoldingRegisters { .. } | R::ReadInputRegisters { .. } => {
            Some(("send_modbus_registers", "registers"))
        }
        _ => None,
    };
    if let Some((action, field)) = keyed {
        return format!(
            "{action} with a {field} object holding every {singular} your instructions give \
             this device, keyed by address. The client asked for {addresses}; NetGet answers \
             exception 2 if any of them is not in your object"
        );
    }
    // A worked comparison computed from this request, never from any particular instruction:
    // a range that stops just short of the first address asked for.
    let illustration = if start > 0 {
        format!(
            "one whose {plural} are 0 to {} has no {singular} {start}",
            start - 1
        )
    } else {
        format!(
            "one whose {plural} start at {} has no {singular} 0",
            start + quantity
        )
    };
    format!(
        "first check whether your instructions give this device {addresses}. A device has \
         only the addresses its instructions give it - {illustration}. If any of those \
         addresses is outside what they describe, answer exactly {{\"type\": \
         \"send_modbus_exception\", \"exception_code\": 2}} and nothing else. If every one \
         of them exists, send_modbus_write_ack, or send_modbus_exception with exception_code 3 \
         when the value is one the equipment would refuse"
    )
}

/// Read of coils (FC 1) or discrete inputs (FC 2).
pub static MODBUS_READ_BITS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_event_parameters();
    params.push(Parameter {
        name: "bit_type".to_string(),
        type_hint: "string".to_string(),
        description:
            "\"coil\" for function code 1 (read/write outputs, e.g. a pump run command) or \
             \"discrete_input\" for function code 2 (read-only inputs, e.g. a limit switch)"
                .to_string(),
        required: true,
    });

    EventType::new(
        "modbus_read_bits",
        "A Modbus client is reading coils (FC 1) or discrete inputs (FC 2). Answer with the \
         bits this device has, keyed by address; NetGet serves the read from them and answers \
         exception 2 for any requested address you did not give.",
        json!({
            "type": "send_modbus_bits",
            "bits": {"40": true, "41": false}
        }),
    )
    .with_parameters(params)
    .with_actions(vec![
        SEND_MODBUS_BITS_ACTION.clone(),
        SEND_MODBUS_EXCEPTION_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_modbus_exception",
        "exception_code": 2
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip}:{client_port} {function} @{start_address} x{quantity}")
            .with_debug("Modbus {function} unit={unit_id} start={start_address} qty={quantity}")
            .with_trace("Modbus read bits: {json_pretty(.)}"),
    )
});

/// Read of holding registers (FC 3) or input registers (FC 4).
pub static MODBUS_READ_REGISTERS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_event_parameters();
    params.push(Parameter {
        name: "register_type".to_string(),
        type_hint: "string".to_string(),
        description: "\"holding\" for function code 3 (read/write registers, e.g. a setpoint) or \
             \"input\" for function code 4 (read-only measurements, e.g. a sensor reading)"
            .to_string(),
        required: true,
    });

    EventType::new(
        "modbus_read_registers",
        "A Modbus client is reading holding registers (FC 3) or input registers (FC 4). \
         Answer with the registers this device has, keyed by address; NetGet serves the read \
         from them and answers exception 2 for any requested address you did not give.",
        json!({
            "type": "send_modbus_registers",
            "registers": {"40": 1834, "41": 1450}
        }),
    )
    .with_parameters(params)
    .with_actions(vec![
        SEND_MODBUS_REGISTERS_ACTION.clone(),
        SEND_MODBUS_EXCEPTION_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_modbus_exception",
        "exception_code": 2
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip}:{client_port} {function} @{start_address} x{quantity}")
            .with_debug("Modbus {function} unit={unit_id} start={start_address} qty={quantity}")
            .with_trace("Modbus read registers: {json_pretty(.)}"),
    )
});

/// Write of coils or registers (FC 5, 6, 15, 16).
pub static MODBUS_WRITE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_event_parameters();
    params.push(Parameter {
        name: "coil_values".to_string(),
        type_hint: "array of booleans".to_string(),
        description:
            "Present for function codes 5 and 15: the bit values the client is trying to write"
                .to_string(),
        required: false,
    });
    params.push(Parameter {
        name: "register_values".to_string(),
        type_hint: "array of integers".to_string(),
        description:
            "Present for function codes 6 and 16: the register values the client is trying to \
             write"
                .to_string(),
        required: false,
    });

    EventType::new(
        "modbus_write_request",
        "A Modbus client is writing coils or registers (FC 5, 6, 15 or 16). Decide whether \
         this device accepts the write - consider whether the address is writable on the \
         equipment you are impersonating and whether the value is in range - then acknowledge \
         it or refuse with an exception. Record accepted writes with set_memory so later \
         reads reflect them.",
        json!({ "type": "send_modbus_write_ack" }),
    )
    .with_parameters(params)
    .with_actions(vec![
        SEND_MODBUS_WRITE_ACK_ACTION.clone(),
        SEND_MODBUS_EXCEPTION_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_modbus_exception",
        "exception_code": 2
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip}:{client_port} {function} @{start_address} x{quantity}")
            .with_debug("Modbus {function} unit={unit_id} start={start_address} qty={quantity}")
            .with_trace("Modbus write: {json_pretty(.)}"),
    )
});

/// All Modbus event types. Each one is emitted by `src/server/modbus/mod.rs`.
pub fn get_modbus_event_types() -> Vec<EventType> {
    vec![
        MODBUS_READ_BITS_EVENT.clone(),
        MODBUS_READ_REGISTERS_EVENT.clone(),
        MODBUS_WRITE_REQUEST_EVENT.clone(),
    ]
}
