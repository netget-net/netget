//! Modbus/TCP client actions, events and metadata.
//!
//! NetGet is the master: it dials a Modbus/TCP device and the model decides which coils and
//! registers to read and what to write. The framing — MBAP header, transaction ids, byte
//! counts, bit packing — is the shared codec's (`src/server/modbus/codec.rs`), so the model
//! works in addresses, quantities and values, never bytes.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::modbus::codec::{encode_request, ModbusRequest};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every request travels as.
pub const REQUEST_RESULT: &str = "modbus_request";

/// The unit id requests use when neither the action nor the `unit_id` startup parameter names
/// one. 1 is what most Modbus/TCP devices answer on, and what `mbpoll` defaults to.
pub const DEFAULT_UNIT_ID: u8 = 1;

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn function_param() -> Parameter {
    param(
        "function",
        "string",
        "read_coils, read_discrete_inputs, read_holding_registers, read_input_registers, \
         write_single_coil, write_single_register, write_multiple_coils or \
         write_multiple_registers",
        true,
    )
}

fn unit_param() -> Parameter {
    param(
        "unit_id",
        "number",
        "The unit (slave) id the request was addressed to",
        true,
    )
}

pub static MODBUS_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "modbus_connected",
        "Connected to a Modbus/TCP device",
        json!({"type": "modbus_read_holding_registers", "address": 0, "quantity": 2}),
    )
    .with_parameters(vec![
        param(
            "remote_addr",
            "string",
            "The device this client is connected to",
            true,
        ),
        param(
            "unit_id",
            "number",
            "The unit id requests use unless an action names another",
            true,
        ),
    ])
});

pub static MODBUS_READ_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "modbus_read_response",
        "The device answered a read with the values requested",
        json!({"type": "modbus_write_single_register", "address": 10, "value": 1}),
    )
    .with_parameters(vec![
        function_param(),
        unit_param(),
        param(
            "address",
            "number",
            "First address read (protocol address, 0-based)",
            true,
        ),
        param("quantity", "number", "How many items were read", true),
        param(
            "values",
            "array",
            "One entry per item from address upward: booleans for coils and discrete inputs, \
             integers 0-65535 for registers",
            true,
        ),
    ])
});

pub static MODBUS_WRITE_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "modbus_write_response",
        "The device acknowledged a write (its echo matched what was written)",
        json!({"type": "modbus_read_holding_registers", "address": 0, "quantity": 1}),
    )
    .with_parameters(vec![
        function_param(),
        unit_param(),
        param("address", "number", "First address written", true),
        param("quantity", "number", "How many items were written", true),
        param(
            "values",
            "array",
            "What was written, from address upward",
            true,
        ),
    ])
});

pub static MODBUS_EXCEPTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "modbus_exception",
        "The device refused a request with a Modbus exception",
        json!({"type": "modbus_read_holding_registers", "address": 0, "quantity": 1}),
    )
    .with_parameters(vec![
        function_param(),
        unit_param(),
        param(
            "address",
            "number",
            "First address of the refused request",
            true,
        ),
        param(
            "code",
            "number",
            "The exception code (1-6, 8, 10, 11)",
            true,
        ),
        param(
            "name",
            "string",
            "The exception's name, e.g. illegal_data_address or illegal_function",
            true,
        ),
    ])
});

pub static MODBUS_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "modbus_error",
        "A request got no usable answer: the device did not reply in time, or replied with a \
         frame that does not answer the request",
        json!({"type": "modbus_read_holding_registers", "address": 0, "quantity": 1}),
    )
    .with_parameters(vec![
        param(
            "kind",
            "string",
            "timeout (no reply in time), bad_response (a reply that does not match the \
             request), or unit_mismatch (a reply from a different unit id)",
            true,
        ),
        param("message", "string", "What went wrong", true),
        function_param(),
        param("address", "number", "First address of the request", true),
    ])
});

/// Modbus/TCP client protocol.
pub struct ModbusClientProtocol;

impl ModbusClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ModbusClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn unit_id_param() -> Parameter {
    param(
        "unit_id",
        "number",
        "Unit (slave) id 0-255; defaults to the client's unit_id startup parameter",
        false,
    )
}

fn read_action(name: &str, what: &str, max: u16) -> ActionDefinition {
    ActionDefinition {
        name: name.to_string(),
        description: format!("Read {what}"),
        parameters: vec![
            param(
                "address",
                "number",
                "First address, 0-based protocol address",
                true,
            ),
            param(
                "quantity",
                "number",
                &format!("How many to read, 1-{max}"),
                true,
            ),
            unit_id_param(),
        ],
        example: json!({"type": name, "address": 0, "quantity": 2}),
        log_template: Some(LogTemplate::new().with_info(format!(
            "-> {name} {{address}}+{{quantity}} unit={{unit_id}}"
        ))),
    }
}

fn all_actions() -> Vec<ActionDefinition> {
    vec![
        read_action("modbus_read_coils", "coils (FC 1)", 2000),
        read_action(
            "modbus_read_discrete_inputs",
            "discrete inputs (FC 2)",
            2000,
        ),
        read_action(
            "modbus_read_holding_registers",
            "holding registers (FC 3)",
            125,
        ),
        read_action("modbus_read_input_registers", "input registers (FC 4)", 125),
        ActionDefinition {
            name: "modbus_write_single_coil".to_string(),
            description: "Turn one coil on or off (FC 5)".to_string(),
            parameters: vec![
                param("address", "number", "The coil's address", true),
                param("value", "boolean", "true = on, false = off", true),
                unit_id_param(),
            ],
            example: json!({"type": "modbus_write_single_coil", "address": 3, "value": true}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> modbus_write_single_coil {address}={value} unit={unit_id}"),
            ),
        },
        ActionDefinition {
            name: "modbus_write_single_register".to_string(),
            description: "Write one holding register (FC 6)".to_string(),
            parameters: vec![
                param("address", "number", "The register's address", true),
                param(
                    "value",
                    "number",
                    "The register's new value, an integer 0-65535",
                    true,
                ),
                unit_id_param(),
            ],
            example: json!({"type": "modbus_write_single_register", "address": 5, "value": 1234}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> modbus_write_single_register {address}={value} unit={unit_id}"),
            ),
        },
        ActionDefinition {
            name: "modbus_write_multiple_coils".to_string(),
            description: "Write consecutive coils (FC 15)".to_string(),
            parameters: vec![
                param("address", "number", "First coil's address", true),
                param(
                    "values",
                    "array",
                    "1-1968 booleans, from address upward",
                    true,
                ),
                unit_id_param(),
            ],
            example: json!({
                "type": "modbus_write_multiple_coils",
                "address": 0,
                "values": [true, false, true]
            }),
            log_template: Some(LogTemplate::new().with_info(
                "-> modbus_write_multiple_coils {address} {json(values)} unit={unit_id}",
            )),
        },
        ActionDefinition {
            name: "modbus_write_multiple_registers".to_string(),
            description: "Write consecutive holding registers (FC 16)".to_string(),
            parameters: vec![
                param("address", "number", "First register's address", true),
                param(
                    "values",
                    "array",
                    "1-123 integers 0-65535, from address upward",
                    true,
                ),
                unit_id_param(),
            ],
            example: json!({
                "type": "modbus_write_multiple_registers",
                "address": 10,
                "values": [1, 2, 3]
            }),
            log_template: Some(LogTemplate::new().with_info(
                "-> modbus_write_multiple_registers {address} {json(values)} unit={unit_id}",
            )),
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Close the connection to the Modbus device".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: Some(LogTemplate::new().with_info("-> modbus disconnect")),
        },
    ]
}

fn u16_field(action: &Value, name: &str) -> Result<u16> {
    let v = action
        .get(name)
        .with_context(|| format!("missing number field '{name}'"))?;
    let n = v
        .as_u64()
        .with_context(|| format!("'{name}' must be a non-negative integer, got {v}"))?;
    u16::try_from(n).map_err(|_| anyhow!("'{name}' is {n}; Modbus fields are 0-65535"))
}

/// One validated request, with the unit id the action named (if any).
pub struct ClientRequest {
    pub unit_id: Option<u8>,
    pub request: ModbusRequest,
}

/// Parse one model action into a request. `Ok(None)` is `disconnect`.
///
/// Numbers are refused rather than narrowed: `65536` is not register value `0`, and a unit id
/// of `257` is not unit `1`. The finished request is then run through the shared codec's
/// encoder, which refuses anything the specification would answer with an exception.
pub fn request_from_action(action: &Value) -> Result<Option<ClientRequest>> {
    let action_type = action
        .get("type")
        .and_then(Value::as_str)
        .context("missing 'type'")?;
    let unit_id = match action.get("unit_id") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("'unit_id' must be an integer 0-255, got {v}"))?;
            Some(u8::try_from(n).map_err(|_| anyhow!("unit_id {n} is outside 0-255"))?)
        }
    };
    let request = match action_type {
        "modbus_read_coils"
        | "modbus_read_discrete_inputs"
        | "modbus_read_holding_registers"
        | "modbus_read_input_registers" => {
            let start = u16_field(action, "address")?;
            let quantity = u16_field(action, "quantity")?;
            match action_type {
                "modbus_read_coils" => ModbusRequest::ReadCoils { start, quantity },
                "modbus_read_discrete_inputs" => {
                    ModbusRequest::ReadDiscreteInputs { start, quantity }
                }
                "modbus_read_holding_registers" => {
                    ModbusRequest::ReadHoldingRegisters { start, quantity }
                }
                _ => ModbusRequest::ReadInputRegisters { start, quantity },
            }
        }
        "modbus_write_single_coil" => ModbusRequest::WriteSingleCoil {
            address: u16_field(action, "address")?,
            value: action
                .get("value")
                .and_then(Value::as_bool)
                .context("'value' must be true or false")?,
        },
        "modbus_write_single_register" => ModbusRequest::WriteSingleRegister {
            address: u16_field(action, "address")?,
            value: u16_field(action, "value")?,
        },
        "modbus_write_multiple_coils" => ModbusRequest::WriteMultipleCoils {
            start: u16_field(action, "address")?,
            values: action
                .get("values")
                .and_then(Value::as_array)
                .context("'values' must be an array of booleans")?
                .iter()
                .map(|v| {
                    v.as_bool()
                        .with_context(|| format!("every coil value must be a boolean, got {v}"))
                })
                .collect::<Result<_>>()?,
        },
        "modbus_write_multiple_registers" => ModbusRequest::WriteMultipleRegisters {
            start: u16_field(action, "address")?,
            values: action
                .get("values")
                .and_then(Value::as_array)
                .context("'values' must be an array of integers")?
                .iter()
                .map(|v| {
                    let n = v
                        .as_u64()
                        .with_context(|| format!("register values are integers, got {v}"))?;
                    u16::try_from(n).map_err(|_| anyhow!("register value {n} is outside 0-65535"))
                })
                .collect::<Result<_>>()?,
        },
        "disconnect" => return Ok(None),
        other => return Err(anyhow!("Unknown Modbus client action: {other}")),
    };
    encode_request(&request).map_err(|e| anyhow!(e))?;
    Ok(Some(ClientRequest { unit_id, request }))
}

impl Protocol for ModbusClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "unit_id".to_string(),
            type_hint: "number".to_string(),
            description: "Unit (slave) id 0-255 requests are addressed to unless an action \
                          names another (default 1)"
                .to_string(),
            required: false,
            example: json!(1),
            default: Some(json!(DEFAULT_UNIT_ID)),
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "Modbus"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            MODBUS_CONNECTED_EVENT.clone(),
            MODBUS_READ_RESPONSE_EVENT.clone(),
            MODBUS_WRITE_RESPONSE_EVENT.clone(),
            MODBUS_EXCEPTION_EVENT.clone(),
            MODBUS_ERROR_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Modbus"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["modbus", "modbus client", "modbus master", "plc", "scada"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // 502 is a destination here, never a bind.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Modbus/TCP master on tokio, framing with the server's own codec \
                 (src/server/modbus/codec.rs: encode_request, parse_response, try_parse_adu) \
                 rather than a second copy of it, and not tokio-modbus. One transport task owns \
                 the socket, matches responses to requests by transaction id and times out \
                 unanswered requests; the model is asked from a separate turn task.",
            )
            .llm_control(
                "Which coils, discrete inputs and registers to read (FC 1-4) and what to write \
                 (FC 5, 6, 15, 16), on which unit id. Every response arrives as a structured \
                 event with values, an exception name, or an error kind.",
            )
            .e2e_testing(
                "tests/client/modbus/real_server_test.rs, 7 LLM calls, against a pymodbus 3.15 \
                 device (Python: its own framer and datastore) read back with mbpoll (C, \
                 libmodbus). The model reads input registers (FC 4), writes values computed \
                 from them to holding registers (FC 16), turns a coil on (FC 5), and in one \
                 turn reads discrete inputs (FC 2) and a register that does not exist (FC 3), \
                 which pymodbus refuses with exception 2; mbpoll reads back the registers and \
                 the coil. A second test injects FC 6 and FC 15 through the command channel and \
                 mbpoll reads them back. Not #[ignore]d; a missing python3, pymodbus or mbpoll \
                 fails the test. unanswered_test.rs covers a wrong response, a timeout and the \
                 request queue bound; codec_test.rs the shared codec's client half.",
            )
            .notes(
                "TCP only (no RTU/ASCII). Eight function codes. Each response is checked \
                 against its request: function code, byte count, and a write's echo. \
                 A request unanswered after 5s is reported as modbus_error kind timeout.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Modbus/TCP master for reading and writing coils and registers on a device"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the Modbus device at 192.168.1.50:502 and read holding registers 0-9"
    }

    fn group_name(&self) -> &'static str {
        "Industrial"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5020",
                "base_stack": "modbus",
                "instruction": "Read holding registers 0-3 and report the values",
                "startup_params": {"unit_id": 1}
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5020",
                "base_stack": "modbus",
                "event_handlers": [{
                    "event_pattern": "modbus_read_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<modbus_client_handler>"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5020",
                "base_stack": "modbus",
                "event_handlers": [
                    {
                        "event_pattern": "modbus_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "modbus_read_holding_registers",
                                "address": 0,
                                "quantity": 4
                            }]
                        }
                    },
                    {
                        "event_pattern": "modbus_read_response",
                        "handler": {"type": "static", "actions": [{"type": "disconnect"}]}
                    }
                ]
            }),
        )
    }
}

impl Client for ModbusClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let unit_id = match ctx.startup_params.as_ref() {
                Some(p) => match p.get_optional_u64("unit_id")? {
                    None => DEFAULT_UNIT_ID,
                    Some(n) => {
                        u8::try_from(n).map_err(|_| anyhow!("unit_id {n} is outside 0-255"))?
                    }
                },
                None => DEFAULT_UNIT_ID,
            };
            crate::client::modbus::ModbusClient::connect_with_llm_actions(
                ctx.remote_addr,
                unit_id,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match request_from_action(&action)? {
            None => Ok(ClientActionResult::Disconnect),
            Some(_) => Ok(ClientActionResult::Custom {
                name: REQUEST_RESULT.to_string(),
                data: action,
            }),
        }
    }
}
