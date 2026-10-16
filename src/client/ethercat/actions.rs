//! EtherCAT master: the actions the model drives a segment with, and the events it sees.
//!
//! Rust runs the master: the scan (slave count from a broadcast read's working counter,
//! station addresses, each slave's SII read through its EEPROM registers), the configuration
//! each state needs (mailbox SyncManagers for PRE-OP; the PDO layout — from CoE 0x1C12/0x1C13
//! when the slave has CoE, otherwise from its SII — process data SyncManagers, FMMUs and the
//! logical image for SAFE-OP), the AL state requests and their polling, the cyclic LRW with its
//! working counter check, and every mailbox transfer. The model decides which state to walk
//! the segment to, the output values, and which objects to read and write. Values are named,
//! typed fields; no action or event carries bytes.
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, StartupExamples};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::ethercat::device::{self, DataType};
use crate::server::ethercat::esc::state;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const SCAN: &str = "ethercat_scan";
pub const REQUEST_STATE: &str = "ethercat_request_state";
pub const SET_OUTPUTS: &str = "ethercat_set_outputs";
pub const SDO_READ: &str = "ethercat_sdo_read";
pub const SDO_WRITE: &str = "ethercat_sdo_write";

/// Cyclic process data period.
pub const DEFAULT_CYCLE_MS: u64 = 10;
pub const MAX_CYCLE_MS: u64 = 1000;
/// How long a slave has to reach a requested state.
pub const DEFAULT_STATE_TIMEOUT_MS: u64 = 10_000;
/// How long a slave has to answer a mailbox request.
pub const DEFAULT_MAILBOX_TIMEOUT_MS: u64 = 5_000;
pub const MAX_TIMEOUT_MS: u64 = 120_000;

#[derive(Clone, Default)]
pub struct EthercatClientProtocol;

impl EthercatClientProtocol {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("EtherCAT master: {name}"))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            SCAN,
            "Scan the segment again: reset every slave to INIT, count them, give each a station \
             address and read its identity and process data layout from its SII. Answered by \
             ethercat_segment_scanned. The segment is scanned once on start",
            vec![],
            json!({"type": SCAN}),
        ),
        action(
            REQUEST_STATE,
            "Walk slaves to an AL state: preop (mailbox configured), safeop (process data \
             configured and cycling; inputs valid, outputs held safe), op (outputs applied) or \
             init. Each step is taken from the slave's current state; NetGet does the \
             configuration each needs. op is refused until the outputs of every slave that has \
             outputs have been set with ethercat_set_outputs. Answered by ethercat_state_result",
            vec![
                p("state", "string", "init, preop, safeop or op", true),
                p(
                    "slave",
                    "number",
                    "Only this slave (its position); default every slave",
                    false,
                ),
            ],
            json!({"type": REQUEST_STATE, "state": "op"}),
        ),
        action(
            SET_OUTPUTS,
            "Set output process data (master → slave) of one slave: values is an object of the \
             slave's output entry names to numbers (true/false for bool entries); entries left \
             out keep their value. Outputs are zero and OP is refused until they are set",
            vec![
                p(
                    "slave",
                    "number",
                    "The slave's position on the segment",
                    true,
                ),
                p(
                    "values",
                    "object",
                    "Output entry name → value, e.g. {\"motor_on\": true}",
                    true,
                ),
            ],
            json!({"type": SET_OUTPUTS, "slave": 0, "values": {"outputs": 1}}),
        ),
        action(
            SDO_READ,
            "Read a CoE object of a slave in PRE-OP or above (an SDO upload). data_type decodes \
             the value (bool, i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, string); without \
             it a 1/2/4/8-octet value is read as an unsigned number and longer printable data \
             as text. Answered by ethercat_sdo_result",
            vec![
                p(
                    "slave",
                    "number",
                    "The slave's position on the segment",
                    true,
                ),
                p(
                    "index",
                    "number",
                    "Object index (a number, or \"0x1018\" text)",
                    true,
                ),
                p("subindex", "number", "Object subindex (default 0)", false),
                p("data_type", "string", "How to decode the value", false),
            ],
            json!({"type": SDO_READ, "slave": 0, "index": 4120, "subindex": 1, "data_type": "u32"}),
        ),
        action(
            SDO_WRITE,
            "Write a CoE object of a slave in PRE-OP or above (an SDO download), encoded with \
             data_type. Answered by ethercat_sdo_result",
            vec![
                p(
                    "slave",
                    "number",
                    "The slave's position on the segment",
                    true,
                ),
                p(
                    "index",
                    "number",
                    "Object index (a number, or \"0x8000\" text)",
                    true,
                ),
                p("subindex", "number", "Object subindex (default 0)", false),
                p("data_type", "string", "The object's type", true),
                p("value", "any", "The value to write", true),
            ],
            json!({"type": SDO_WRITE, "slave": 0, "index": 32768, "subindex": 1,
                   "data_type": "u16", "value": 1200}),
        ),
    ]
}

fn slave_field() -> Parameter {
    p(
        "slave",
        "number",
        "The slave's position on the segment",
        true,
    )
}

pub static SEGMENT_SCANNED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ethercat_segment_scanned",
        "The segment was scanned: every slave found, with its identity, state and process data \
         layout",
        json!({"type": REQUEST_STATE, "state": "preop"}),
    )
    .with_parameters(vec![
        p("count", "number", "How many slaves answered", true),
        p(
            "slaves",
            "array",
            "Each slave: position, station_address, name, vendor_id, product_code, revision, \
             serial, state, coe (has an SDO mailbox), inputs and outputs ({name, type})",
            true,
        ),
    ])
    .with_actions(actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT segment scanned: {count} slave(s)")
            .with_debug("EtherCAT scan: {json(.)}"),
    )
});

pub static STATE_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ethercat_state_result",
        "A requested state walk finished: where each slave ended, and the AL status code of \
         any that refused",
        json!({"type": SET_OUTPUTS, "slave": 0, "values": {"outputs": 1}}),
    )
    .with_parameters(vec![
        p("requested", "string", "The state that was requested", true),
        p(
            "slaves",
            "array",
            "Each slave: position, state, ok, al_status_code and al_status (when refused), \
             error (when NetGet could not configure it)",
            true,
        ),
        p(
            "ok",
            "boolean",
            "Whether every slave reached the state",
            true,
        ),
    ])
    .with_actions(actions())
    .with_log_template(LogTemplate::new().with_info("EtherCAT state walk to {requested}: ok={ok}"))
});

pub static INPUTS_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ethercat_inputs_changed",
        "A slave's input process data changed (at most one event per slave per 200 ms, with \
         the latest values; only frames with the expected working counter count)",
        json!({"type": SET_OUTPUTS, "slave": 0, "values": {"outputs": 1}}),
    )
    .with_parameters(vec![
        slave_field(),
        p("inputs", "object", "Input entry name → value", true),
    ])
    .with_actions(actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT inputs of slave {slave} changed")
            .with_debug("EtherCAT inputs: {json(.)}"),
    )
});

pub static SDO_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ethercat_sdo_result",
        "An SDO read or write finished: the value read, or the abort code the slave sent",
        json!({"type": SDO_READ, "slave": 0, "index": 4120, "subindex": 2, "data_type": "u32"}),
    )
    .with_parameters(vec![
        slave_field(),
        p("operation", "string", "Whether the SDO was a read or a write", true),
        p("index", "number", "The object index that was read or written", true),
        p("subindex", "number", "Object subindex", true),
        p("ok", "boolean", "Whether it succeeded", true),
        p("value", "any", "The value read (or written)", false),
        p("data_type", "string", "How the value was decoded", false),
        p(
            "abort_code",
            "number",
            "The SDO abort code, when the slave refused",
            false,
        ),
        p("abort", "string", "What the abort code means", false),
        p(
            "error",
            "string",
            "Why it failed, when it was not an abort",
            false,
        ),
    ])
    .with_actions(actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("EtherCAT SDO {operation} on slave {slave}: ok={ok}")
            .with_debug("EtherCAT SDO result: {json(.)}"),
    )
});

pub static PROCESS_DATA_FAULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ethercat_process_data_fault",
        "Cyclic frames came back with the wrong working counter (a slave stopped taking part) \
         or not at all. Raised at most every 5 s while it lasts",
        json!({"type": REQUEST_STATE, "state": "safeop"}),
    )
    .with_parameters(vec![
        p(
            "expected_wkc",
            "number",
            "The working counter every slave taking part gives",
            true,
        ),
        p(
            "wkc",
            "number",
            "The working counter the last frame came back with (-1 = lost)",
            true,
        ),
        p(
            "bad_frames",
            "number",
            "Bad or lost frames since the last report",
            true,
        ),
    ])
    .with_actions(actions())
    .with_log_template(
        LogTemplate::new().with_info("EtherCAT process data fault: wkc {wkc} of {expected_wkc}"),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        SEGMENT_SCANNED_EVENT.clone(),
        STATE_RESULT_EVENT.clone(),
        INPUTS_CHANGED_EVENT.clone(),
        SDO_RESULT_EVENT.clone(),
        PROCESS_DATA_FAULT_EVENT.clone(),
    ]
}

/// A slave position.
pub fn slave_of(v: &Value) -> Result<usize> {
    Ok(device::number_field(v.get("slave"), "slave", super::MAX_SLAVES as u64 - 1)? as usize)
}

/// An object index and subindex.
pub fn object_of(v: &Value) -> Result<(u16, u8)> {
    let index = device::number_field(v.get("index"), "index", 0xFFFF)? as u16;
    let sub = match v.get("subindex") {
        None | Some(Value::Null) => 0,
        some => device::number_field(some, "subindex", 0xFF)? as u8,
    };
    Ok((index, sub))
}

pub fn data_type_of(v: &Value) -> Result<Option<DataType>> {
    v.get("data_type")
        .and_then(Value::as_str)
        .map(DataType::parse)
        .transpose()
}

/// Check an action's shape before the session sees it.
pub fn check(v: &Value) -> Result<()> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .context("action needs a type")?;
    match t {
        SCAN => {}
        REQUEST_STATE => {
            let s = v
                .get("state")
                .and_then(Value::as_str)
                .context("ethercat_request_state needs state")?;
            let st = state::parse(s).context("state is init, preop, safeop or op")?;
            ensure!(st != state::BOOT, "the bootstrap state is not supported");
            if v.get("slave").is_some_and(|s| !s.is_null()) {
                slave_of(v)?;
            }
        }
        SET_OUTPUTS => {
            slave_of(v)?;
            ensure!(
                v.get("values").is_some_and(Value::is_object),
                "values is an object of output entry name → value"
            );
        }
        SDO_READ => {
            slave_of(v)?;
            object_of(v)?;
            data_type_of(v)?;
        }
        SDO_WRITE => {
            slave_of(v)?;
            object_of(v)?;
            let ty = data_type_of(v)?.context("ethercat_sdo_write needs data_type")?;
            ty.encode(v.get("value").context("ethercat_sdo_write needs value")?)?;
        }
        other => bail!(
            "Unknown EtherCAT master action {other:?}: {SCAN}, {REQUEST_STATE}, {SET_OUTPUTS}, \
             {SDO_READ}, {SDO_WRITE}, disconnect"
        ),
    }
    Ok(())
}

impl crate::llm::actions::protocol_trait::Protocol for EthercatClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "EtherCAT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>EtherCAT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ethercat",
            "ethercat master",
            "ethercat maindevice",
            "ecat master",
        ]
    }
    fn description(&self) -> &'static str {
        "EtherCAT master (MainDevice): scans a segment, reads each slave's identity and layout from its SII, walks slaves INIT → PRE-OP → SAFE-OP → OP, runs cyclic LRW process data and CoE SDO reads and writes — the LLM decides the states, the outputs and the object access"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "transport".into(),
                type_hint: "string".into(),
                description: "raw (default): remote_addr is the Ethernet interface of the \
                              segment (needs CAP_NET_RAW/BPF access). udp: remote_addr is the \
                              HOST[:PORT] of an EtherCAT-in-UDP endpoint (port 34980 by default)"
                    .into(),
                required: false,
                example: json!("raw"),
                default: Some(json!(crate::server::ethercat::link::TRANSPORT_RAW)),
            },
            ParameterDefinition {
                name: "cycle_ms".into(),
                type_hint: "number".into(),
                description: format!("Cyclic process data period in ms (1-{MAX_CYCLE_MS})"),
                required: false,
                example: json!(4),
                default: Some(json!(DEFAULT_CYCLE_MS)),
            },
            ParameterDefinition {
                name: "state_timeout_ms".into(),
                type_hint: "number".into(),
                description: "How long a slave has to reach a requested state".into(),
                required: false,
                example: json!(20000),
                default: Some(json!(DEFAULT_STATE_TIMEOUT_MS)),
            },
            ParameterDefinition {
                name: "mailbox_timeout_ms".into(),
                type_hint: "number".into(),
                description: "How long a slave has to answer an SDO request".into(),
                required: false,
                example: json!(10000),
                default: Some(json!(DEFAULT_MAILBOX_TIMEOUT_MS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .implementation("Hand-written EtherCAT master sharing the slave's codec (src/server/ethercat): frames of datagrams matched to answers by index with retries; a scan (BWR AL control INIT, BRD slave count from the working counter, BWR resets of FMMUs, SyncManagers and EEPROM ownership, APWR station addresses 0x1001…, FPRD of type, DL and AL status) and each slave's SII read through its EEPROM registers in 4- or 8-octet chunks and parsed (identity, mailbox, strings, General, FMMU, SyncM, TxPDO/RxPDO); PRE-OP with the mailbox SyncManagers from the SII; SAFE-OP with the PDO layout read over CoE (0x1C12/0x1C13 and the mapping objects, names and types from the SII) or from the SII, process data SyncManagers, FMMUs and a byte-aligned logical image; OP; AL status polling with the AL status code on refusal; cyclic LRW at a configured period with the expected working counter (outputs 2, inputs 1 per slave) checked; CoE SDO upload and download, expedited, normal and segmented, with aborts decoded. Raw Ethernet (EtherType 0x88A4) or EtherCAT-in-UDP")
            .llm_control("Which state to walk the segment (or one slave) to; every output value; which CoE objects to read and write and with what values. Identity, layouts, inputs and SDO results arrive as typed values")
            .e2e_testing("tests/client/ethercat: on Linux over a veth, KickCAT's network_simulator (an independent C++ software ESC and slave stack) running an emulated CiA 402 drive from its ESI: scan, identity from the SII, PDO layout over CoE, walk to OP, cyclic process data, the drive's statusword answering the controlword the model sets, SDO reads of 0x1018, with tshark reading a live capture; in-process against NetGet's own slave over EtherCAT-in-UDP")
            .notes("Experimental: one independent slave implementation (KickCAT's emulated ESC; no other software EtherCAT slave exists without an ESC chip — SOES needs one), no real ESC has been on the wire, its pair job had not run in CI when it landed, and the raw transport needs CAP_NET_RAW. Not implemented: distributed clocks, topology beyond a line, redundancy, ENI files, FoE/EoE/SoE/AoE, SDO information, complete access, PDO remapping, EEPROM writes, mailbox polling through an FMMU. Outputs are zero and OP is refused until the model sets them; on LLM failure nothing is sent.")
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Act as an EtherCAT master on eth1: bring every slave to OP, enable the CiA 402 drive by writing controlword 6, 7 then 15, and report its statusword"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "EtherCAT", "remote_addr": "eth1",
            "startup_params": {"cycle_ms": 4},
            "instruction": "Walk every slave to SAFE-OP, set the drive's Control Word to 6, then go to OP"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "ethercat_segment_scanned", "handler": {"type": "static", "actions": [
                {"type": REQUEST_STATE, "state": "safeop"}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='ethercat_segment_scanned' and e['count']>0:\n  a=[{'type':'ethercat_request_state','state':'safeop'}]\nelif t=='ethercat_state_result' and e['requested']=='safeop' and e['ok']:\n  a=[{'type':'ethercat_set_outputs','slave':0,'values':{'outputs':1}},{'type':'ethercat_request_state','state':'op'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Client for EthercatClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }

    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
