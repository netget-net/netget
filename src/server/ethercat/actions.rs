//! EtherCAT slave: what the model is asked and what it may answer.
//!
//! Rust is the ESC — every datagram, working counter, register, SyncManager, FMMU and the SII —
//! and the slave firmware's protocol work: the AL state machine's checks, the mailbox, the SDO
//! transfer itself and the objects that describe the device. The model decides what a device
//! application decides: whether an upward state transition is taken (and with which AL status
//! code it is refused), what a declared object reads as, whether a write to one is accepted, and
//! the input process data. Output process data arrives as typed values.
//!
//! Four events, all raised in `mod.rs`:
//!
//! - `ethercat_state_change_request` — a master asks a slave to go up a state
//! - `ethercat_sdo_read` / `ethercat_sdo_write` — CoE access to a declared object
//! - `ethercat_outputs_changed` — the output process data changed in OP
use super::device::{self, DataType, Image};
use super::esc::{al_code, state};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

pub const ACCEPT_STATE: &str = "ethercat_accept_state_change";
pub const REFUSE_STATE: &str = "ethercat_refuse_state_change";
pub const SET_INPUTS: &str = "ethercat_set_inputs";
pub const SDO_VALUE: &str = "ethercat_sdo_value";
pub const SDO_ACCEPT: &str = "ethercat_sdo_accept_write";
pub const SDO_ABORT: &str = "ethercat_sdo_abort";

#[derive(Clone, Default)]
pub struct EthercatProtocol;

impl EthercatProtocol {
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
    log: LogTemplate,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log),
    }
}

fn al_code_names() -> String {
    al_code::NAMES
        .iter()
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

fn abort_names() -> String {
    super::coe::abort::NAMES
        .iter()
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

fn accept_state() -> ActionDefinition {
    action(
        ACCEPT_STATE,
        "Take the requested AL state transition: the slave's AL status becomes the new state. \
         Going to SAFE-OP also needs the inputs to have been set (set them in the same answer \
         with ethercat_set_inputs); without them the slave refuses with 'no valid inputs'",
        vec![],
        json!({"type": ACCEPT_STATE}),
        LogTemplate::new().with_info("EtherCAT state change accepted"),
    )
}

fn refuse_state() -> ActionDefinition {
    action(
        REFUSE_STATE,
        &format!(
            "Refuse the requested state transition: the slave stays where it is with the AL \
             status error bit set and this AL status code, which the master reads. \
             al_status_code is one of {} or a number (default unspecified_error)",
            al_code_names()
        ),
        vec![
            p(
                "al_status_code",
                "string",
                "The AL status code, by name or as a number such as \"0x001E\"",
                false,
            ),
            p("reason", "string", "Why, for the log", false),
        ],
        json!({"type": REFUSE_STATE, "al_status_code": "invalid_input_configuration",
               "reason": "inputs not wired"}),
        LogTemplate::new().with_info("EtherCAT state change refused: {reason}"),
    )
}

fn set_inputs() -> ActionDefinition {
    action(
        SET_INPUTS,
        "Set input process data (slave → master) of one slave: values is an object of the \
         slave's input entry names to numbers (true/false for bool entries); entries left out \
         keep their value. slave is the slave's position on the segment (default: the slave \
         the event is about, else 0). Until a slave's inputs are set it refuses SAFE-OP, so the \
         master never reads data nobody chose",
        vec![
            p(
                "slave",
                "number",
                "Position of the slave on the segment (0 is the first)",
                false,
            ),
            p(
                "values",
                "object",
                "Input entry name → value, e.g. {\"temperature\": 215, \"ready\": true}",
                true,
            ),
        ],
        json!({"type": SET_INPUTS, "slave": 0, "values": {"inputs": 5}}),
        LogTemplate::new()
            .with_info("EtherCAT inputs of slave {slave} set")
            .with_debug("EtherCAT set inputs: {json(.)}"),
    )
}

fn sdo_value() -> ActionDefinition {
    action(
        SDO_VALUE,
        "Answer an SDO read with the object's value: a number (or \"0x…\" text) for numeric \
         types, true/false for bool, text for string. It is encoded with the object's declared \
         type; a value that does not fit is refused, not truncated",
        vec![p("value", "any", "The object's value", true)],
        json!({"type": SDO_VALUE, "value": 1500}),
        LogTemplate::new()
            .with_info("EtherCAT SDO read answered")
            .with_debug("EtherCAT SDO value: {json(.)}"),
    )
}

fn sdo_accept() -> ActionDefinition {
    action(
        SDO_ACCEPT,
        "Accept the SDO write: the master is told the download succeeded",
        vec![],
        json!({"type": SDO_ACCEPT}),
        LogTemplate::new().with_info("EtherCAT SDO write accepted"),
    )
}

fn sdo_abort() -> ActionDefinition {
    action(
        SDO_ABORT,
        &format!(
            "Refuse an SDO read or write with an SDO abort code: abort is one of {} or a number \
             (default general_error)",
            abort_names()
        ),
        vec![
            p(
                "abort",
                "string",
                "The abort code, by name or as a number such as \"0x06090030\"",
                false,
            ),
            p("reason", "string", "Why, for the log", false),
        ],
        json!({"type": SDO_ABORT, "abort": "value_range_exceeded", "reason": "speed too high"}),
        LogTemplate::new().with_info("EtherCAT SDO aborted: {reason}"),
    )
}

pub static ACCEPT_STATE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(accept_state);
pub static REFUSE_STATE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(refuse_state);
pub static SET_INPUTS_ACTION: LazyLock<ActionDefinition> = LazyLock::new(set_inputs);
pub static SDO_VALUE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(sdo_value);
pub static SDO_ACCEPT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(sdo_accept);
pub static SDO_ABORT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(sdo_abort);

fn slave_fields() -> Vec<Parameter> {
    vec![
        p(
            "slave",
            "number",
            "Position of the slave on the segment (0 is the first)",
            true,
        ),
        p(
            "station_address",
            "number",
            "The configured station address the master gave the slave",
            true,
        ),
        p("name", "string", "The slave's device name", true),
    ]
}

pub static STATE_CHANGE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = slave_fields();
    params.extend([
        p(
            "from",
            "string",
            "The slave's current AL state: init, preop or safeop",
            true,
        ),
        p(
            "to",
            "string",
            "The requested state: preop, safeop or op",
            true,
        ),
        p(
            "inputs",
            "array",
            "The slave's input entries ({name, type}) — what ethercat_set_inputs takes",
            true,
        ),
        p(
            "outputs",
            "array",
            "The slave's output entries ({name, type})",
            true,
        ),
        p(
            "inputs_set",
            "boolean",
            "Whether the inputs have been set (SAFE-OP needs them)",
            true,
        ),
    ]);
    EventType::new(
        "ethercat_state_change_request",
        "The master asks a slave to go up one AL state (INIT→PRE-OP: mailbox; PRE-OP→SAFE-OP: \
         inputs flowing, outputs held safe; SAFE-OP→OP: outputs applied). The SyncManager \
         configuration has already been checked. Accept it (with the inputs, for SAFE-OP) or \
         refuse it with an AL status code",
        json!({"type": ACCEPT_STATE}),
    )
    .with_parameters(params)
    .with_actions(vec![
        ACCEPT_STATE_ACTION.clone(),
        REFUSE_STATE_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(
        json!({"type": REFUSE_STATE, "al_status_code": "needs_init", "reason": "maintenance"}),
    )
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT slave {slave} asked {from} → {to}")
            .with_debug("EtherCAT state change request: {json(.)}"),
    )
});

pub static SDO_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = slave_fields();
    params.extend([
        p(
            "index",
            "number",
            "The object index (e.g. 8192 = 0x2000)",
            true,
        ),
        p("subindex", "number", "The object subindex", true),
        p(
            "object",
            "string",
            "The object's declared name, from the device description",
            true,
        ),
        p("data_type", "string", "The object's declared type", true),
    ]);
    EventType::new(
        "ethercat_sdo_read",
        "The master reads a declared object over CoE (an SDO upload). Answer with its value, or \
         abort",
        json!({"type": SDO_VALUE, "value": 0}),
    )
    .with_parameters(params)
    .with_actions(vec![
        SDO_VALUE_ACTION.clone(),
        SDO_ABORT_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": SDO_ABORT, "abort": "device_state"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT SDO read of {object} on slave {slave}")
            .with_debug("EtherCAT SDO read: {json(.)}"),
    )
});

pub static SDO_WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = slave_fields();
    params.extend([
        p("index", "number", "The object index", true),
        p("subindex", "number", "The object subindex", true),
        p("object", "string", "The object's declared name", true),
        p("data_type", "string", "The object's declared type", true),
        p(
            "value",
            "any",
            "The value the master wrote, decoded with the declared type",
            true,
        ),
    ]);
    EventType::new(
        "ethercat_sdo_write",
        "The master writes a declared object over CoE (an SDO download). Accept or abort",
        json!({"type": SDO_ACCEPT}),
    )
    .with_parameters(params)
    .with_actions(vec![
        SDO_ACCEPT_ACTION.clone(),
        SDO_ABORT_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": SDO_ABORT, "abort": "value_too_high"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT SDO write of {object} on slave {slave}")
            .with_debug("EtherCAT SDO write: {json(.)}"),
    )
});

pub static OUTPUTS_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = slave_fields();
    params.push(p(
        "outputs",
        "object",
        "Output entry name → value: what the master commands the slave to do",
        true,
    ));
    EventType::new(
        "ethercat_outputs_changed",
        "The master's output process data for a slave in OP changed (at most one event per \
         200 ms per slave, carrying the latest values)",
        json!({"type": SET_INPUTS, "slave": 0, "values": {"inputs": 1}}),
    )
    .with_parameters(params)
    .with_actions(vec![SET_INPUTS_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT outputs of slave {slave} changed")
            .with_debug("EtherCAT outputs: {json(.)}"),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        STATE_CHANGE_REQUEST_EVENT.clone(),
        SDO_READ_EVENT.clone(),
        SDO_WRITE_EVENT.clone(),
        OUTPUTS_CHANGED_EVENT.clone(),
    ]
}

/// An AL status code given by name or number.
pub fn refusal_code(v: Option<&Value>) -> Result<u16> {
    Ok(match v {
        None | Some(Value::Null) => al_code::UNSPECIFIED,
        Some(Value::String(s)) => {
            if let Some((_, c)) = al_code::NAMES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(s))
            {
                *c
            } else {
                let n = device::parse_int_text(s).map_err(|_| {
                    anyhow!(
                        "al_status_code {s:?} is one of {} or a number",
                        al_code_names()
                    )
                })?;
                u16::try_from(n).map_err(|_| anyhow!("al_status_code {n} is not 16-bit"))?
            }
        }
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .context("al_status_code must be 0..=0xFFFF")?,
        Some(other) => bail!("al_status_code is a name or a number, got {other}"),
    }
    .max(1))
}

/// The values of an `ethercat_set_inputs`, checked for shape.
pub fn input_values(v: &Value) -> Result<(Option<usize>, Map<String, Value>)> {
    let slave = match v.get("slave") {
        None | Some(Value::Null) => None,
        some => Some(device::number_field(some, "slave", device::MAX_SLAVES as u64 - 1)? as usize),
    };
    let values = match v.get("values") {
        Some(Value::Object(m)) => m.clone(),
        None | Some(Value::Null) => bail!("values is required: entry name → value"),
        Some(other) => bail!("values must be an object of entry name → value, got {other}"),
    };
    Ok((slave, values))
}

/// Encode an SDO value for an object of `ty`.
pub fn sdo_value_bytes(v: &Value, ty: DataType) -> Result<Vec<u8>> {
    let value = v.get("value").context("value is required")?;
    ty.encode(value)
}

impl Protocol for EthercatProtocol {
    fn protocol_name(&self) -> &'static str {
        "EtherCAT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>EtherCAT"
    }
    fn description(&self) -> &'static str {
        "EtherCAT slave (SubDevice): an emulated ESC with registers, SII EEPROM, SyncManagers, FMMUs and exact working counters, the AL state machine and CoE SDO mailbox, on raw Ethernet or EtherCAT-in-UDP — the LLM decides state transitions, object values and input process data"
    }
    fn example_prompt(&self) -> &'static str {
        "Be an EtherCAT slave on eth1 named Conveyor IO with a u16 input count and a bool output motor_on: accept every state change, report count = 0 and add one each time motor_on goes true"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ethercat",
            "ethercat slave",
            "ethercat subdevice",
            "ecat",
            "coe",
            "canopen over ethercat",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .well_known_udp_port(34980)
            // Every refusal EtherCAT defines is sent: an unanswered state change leaves the
            // AL status error bit set with a code the master reads, an unanswered SDO is
            // aborted. Inputs nobody set are never claimed valid: the slave refuses SAFE-OP.
            .answers_on_failure()
            .max_inbound_bytes(super::frame::MAX_ETHERNET_FRAME)
            .implementation(
                "Hand-written emulated EtherCAT Slave Controller (no crate), one slave or a \
                 chain of up to 8: datagram processing of NOP, APRD/APWR/APRW, FPRD/FPWR/FPRW, \
                 BRD/BWR/BRW (OR on read), LRD/LWR/LRW and ARMW/FRMW with exact working counters \
                 (read +1, write +1, read-write +3) and auto-increment, configured-address and \
                 alias addressing; a 4 KiB register space (type, features, station address and \
                 alias, DL control and status with the chain's port topology, AL control/status/\
                 status code, watchdogs, SII interface with 8-octet reads, 8 FMMUs with bit \
                 granularity, 8 SyncManagers in mailbox and buffered modes with direction, \
                 enable and PDI-deactivate rules and the mailbox repeat request) over 8 KiB of \
                 process memory; an SII image (identity, mailbox, strings, General with CoE \
                 details, FMMU, SyncM, TxPDO and RxPDO categories, CRC-checked configuration \
                 area); the AL state machine with SyncManager checks and the AL status codes of \
                 ETG.1000.6; the SyncManager watchdog; and CoE SDO upload and download \
                 (expedited, normal and segmented, aborts) with 0x1000, 0x1008-0x100A, 0x1018, \
                 0x1600, 0x1A00, 0x1C00, 0x1C12, 0x1C13, 0x6000 and 0x7000 answered from the \
                 device description. Raw Ethernet (EtherType 0x88A4) through pnet's packet \
                 socket, or EtherCAT-in-UDP on port 34980",
            )
            .llm_control(
                "Whether each upward AL state transition is taken and the AL status code it is \
                 refused with; what declared CoE objects read as and whether writes to them are \
                 accepted (or the SDO abort code); every input value. Output process data in OP \
                 arrives as typed values",
            )
            .e2e_testing(
                "tests/server/ethercat: the ESC, SII, CoE and frame codecs against literal \
                 frames and every bound; in-process over EtherCAT-in-UDP, ethercrab 0.7 (an \
                 independent Rust EtherCAT MainDevice) bridged from Ethernet to UDP, walking to \
                 OP and exchanging process data and SDOs, with tshark's ecatf/ecat/ecat_mailbox \
                 dissectors reading both directions; on Linux over a veth, SOEM 2.0 (slaveinfo \
                 -map, simple_ng) and ethercrab on its own raw socket, under a live tshark \
                 capture",
            )
            .notes(
                "Experimental: two independent masters (SOEM and ethercrab) drive it, but no \
                 TwinCAT or IgH EtherLab master has been pointed at it, its pair job had not run \
                 in CI when it landed, and the raw transport needs CAP_NET_RAW. Not implemented: \
                 distributed clocks (the ESC reports no DC support and its DC registers read \
                 zero), the bootstrap state and FoE/EoE/SoE/AoE (answered with a mailbox \
                 'unsupported protocol' error), SDO information and complete access (aborted), \
                 emergency messages, PDO remapping (the mapping objects are read-only), SII \
                 writes (refused with a command error), redundancy and more than one port \
                 per slave. Timing is soft real-time: frames are processed by a tokio task, so \
                 latency is whatever the host gives. On LLM failure: the state change is \
                 refused (AL status error, code 0x0001), SDO reads and writes are aborted \
                 (0x08000020), and inputs the model never set are never reported valid.",
            )
            .build()
    }

    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based(
            "127.0.0.1",
            super::frame::UDP_PORT,
        ))
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "transport".into(),
                type_hint: "string".into(),
                description: "raw (default): Ethernet frames with EtherType 0x88A4 on the \
                              server's interface; needs CAP_NET_RAW or BPF access. udp: \
                              EtherCAT-in-UDP on the server's host and port (34980), which \
                              needs no privilege"
                    .into(),
                required: false,
                example: json!("raw"),
                default: Some(json!(super::link::TRANSPORT_RAW)),
            },
            ParameterDefinition {
                name: "slaves".into(),
                type_hint: "array".into(),
                description: format!(
                    "The slaves on the segment, in order (at most {}): each {{name, vendor_id, \
                     product_code, revision, serial, device_type, hardware_version, \
                     software_version, alias, inputs: [{{name, type}}], outputs: [{{name, \
                     type}}], objects: [{{index, subindex, name, type, access: ro|rw|wo}}]}}. \
                     Types: bool, i8, i16, i32, i64, u8, u16, u32, u64, f32, f64 (and string \
                     for objects). Objects live at 0x2000-0x5FFF or 0x8000-0xFFFF. Default: one \
                     slave with a u8 input named inputs and a u8 output named outputs; its \
                     vendor_id 0 is a placeholder, not an ETG assignment",
                    device::MAX_SLAVES
                ),
                required: false,
                example: json!([{
                    "name": "Conveyor IO", "vendor_id": "0x00000002", "product_code": "0x07D83052",
                    "inputs": [{"name": "count", "type": "u16"}, {"name": "ready", "type": "bool"}],
                    "outputs": [{"name": "motor_on", "type": "bool"}],
                    "objects": [{"index": "0x8000", "subindex": 1, "name": "Speed limit",
                                 "type": "u16", "access": "rw"}]
                }]),
                default: None,
            },
            ParameterDefinition {
                name: "mailbox_size".into(),
                type_hint: "number".into(),
                description: format!(
                    "Octets in each mailbox SyncManager ({}-{})",
                    super::sii::MIN_MAILBOX,
                    super::sii::MAX_MAILBOX
                ),
                required: false,
                example: json!(128),
                default: Some(json!(super::sii::DEFAULT_MAILBOX)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![set_inputs()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_state(),
            refuse_state(),
            set_inputs(),
            sdo_value(),
            sdo_accept(),
            sdo_abort(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn startup_privilege_requirement(
        &self,
        startup_params: Option<&Value>,
    ) -> crate::protocol::metadata::PrivilegeRequirement {
        crate::llm::actions::protocol_trait::unless_udp_transport(
            self.metadata().privilege_requirement,
            startup_params,
        )
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let params = json!({
            "slaves": [{
                "name": "Conveyor IO",
                "vendor_id": 2,
                "product_code": 131_084_370,
                "inputs": [{"name": "count", "type": "u16"}],
                "outputs": [{"name": "motor_on", "type": "bool"}],
                "objects": [{"index": "0x8000", "subindex": 1, "name": "Speed limit",
                             "type": "u16", "access": "rw"}]
            }]
        });
        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "ethercat",
                "interface": "eth1",
                "startup_params": params,
                "instruction": "Accept every state change; when going to SAFE-OP set count to \
                                0. Each time motor_on becomes true add one to count. Speed \
                                limit reads 1500; accept writes up to 3000 and abort higher \
                                ones with value_too_high."
            }),
            json!({
                "type": "open_server",
                "base_stack": "ethercat",
                "interface": "eth1",
                "startup_params": params,
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='ethercat_state_change_request':\n  a=[{'type':'ethercat_set_inputs','values':{'count':0}},{'type':'ethercat_accept_state_change'}]\nelif t=='ethercat_sdo_read': a=[{'type':'ethercat_sdo_value','value':1500}]\nelif t=='ethercat_sdo_write': a=[{'type':'ethercat_sdo_accept_write'}] if e['value']<=3000 else [{'type':'ethercat_sdo_abort','abort':'value_too_high'}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "ethercat",
                "interface": "eth1",
                "startup_params": params,
                "event_handlers": [
                    {"event_pattern": "ethercat_state_change_request", "handler": {"type": "static", "actions": [
                        {"type": "ethercat_set_inputs", "values": {"count": 7}},
                        {"type": "ethercat_accept_state_change"}
                    ]}},
                    {"event_pattern": "ethercat_sdo_read", "handler": {"type": "static", "actions": [
                        {"type": "ethercat_sdo_value", "value": 1500}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                ]
            }),
        )
    }
}

impl Server for EthercatProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::EthercatServer::spawn(ctx).await })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        match kind {
            SET_INPUTS => {
                input_values(&action)?;
            }
            REFUSE_STATE => {
                refusal_code(action.get("al_status_code"))?;
            }
            SDO_VALUE => {
                ensure!(
                    action.get("value").is_some_and(|v| !v.is_null()),
                    "{SDO_VALUE} needs a value"
                );
            }
            SDO_ABORT => {
                super::coe::abort_code(action.get("abort"))?;
            }
            ACCEPT_STATE | SDO_ACCEPT => {}
            other => {
                return Err(anyhow!(
                    "Unknown EtherCAT action '{other}'. Valid actions: {ACCEPT_STATE}, \
                     {REFUSE_STATE}, {SET_INPUTS}, {SDO_VALUE}, {SDO_ACCEPT}, {SDO_ABORT}"
                ))
            }
        }
        Ok(ActionResult::Custom {
            name: kind.to_string(),
            data: action,
        })
    }
}

/// The state name for an event.
pub fn state_name(s: u8) -> &'static str {
    state::name(s)
}

/// The entries of an image, for events.
pub fn entries(img: &Image) -> Value {
    img.describe()
}
