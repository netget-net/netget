//! PROFINET IO controller: the actions the model drives a device with, and the events it sees.
//!
//! Rust runs DCP (Identify, Set), the AR (Connect → parameter writes → PrmEnd → the device's
//! ApplicationReady → cyclic data → Release), the output provider, the input consumer and its
//! watchdog, and every RPC retransmission. The model decides which device to configure, what
//! name and address it gets, the module layout to connect with, the output values, and which
//! records to read or write. Values are named, typed fields; no action or event carries bytes.
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, StartupExamples};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::profinet::{actions as dev, blocks, values};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const IDENTIFY: &str = "profinet_identify";
pub const DCP_SET: &str = "profinet_dcp_set";
pub const CONNECT: &str = "profinet_connect";
pub const SET_OUTPUTS: &str = "profinet_set_outputs";
pub const READ_RECORD: &str = "profinet_read_record";
pub const WRITE_RECORD: &str = "profinet_write_record";
pub const RELEASE: &str = "profinet_release";

pub const DEFAULT_STATION_NAME: &str = "netget-controller";
/// The default cycle: 32 ms (SendClockFactor 32 × ReductionRatio 32 × 31.25 µs).
pub const DEFAULT_CYCLE_MS: u64 = 32;
/// The default watchdog: 30 cycles.
pub const DEFAULT_WATCHDOG_FACTOR: u64 = 30;
/// How long an Identify collects answers.
pub const DEFAULT_IDENTIFY_MS: u64 = 1500;
pub const MAX_IDENTIFY_MS: u64 = 10_000;

#[derive(Clone, Default)]
pub struct ProfinetClientProtocol;

impl ProfinetClientProtocol {
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
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("PROFINET {name}"))
                .with_debug(format!("PROFINET {name}: {{json(.)}}")),
        ),
    }
}

fn example_layout() -> Value {
    json!([
        {"slot": 0, "subslot": 1, "module_ident": "0x1", "submodule_ident": "0x1"},
        {"slot": 1, "subslot": 1, "module_ident": "0x32", "submodule_ident": "0x132",
         "inputs": [{"name": "inputs", "type": "u8"}],
         "outputs": [{"name": "outputs", "type": "u8"}]}
    ])
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            IDENTIFY,
            "Find PROFINET devices with a DCP Identify (all of them, or the one named \
             name_of_station); the answers arrive as profinet_devices_discovered",
            vec![p("name_of_station", "string", "Only this station", false)],
            json!({"type": IDENTIFY}),
        ),
        action(
            DCP_SET,
            "Configure a device over DCP: give it a station name and/or IP parameters, or make \
             it flash its LED. Target it by mac (or by its current name_of_station). The result \
             arrives as profinet_dcp_set_result",
            vec![
                p("mac", "string", "The device's MAC address", false),
                p(
                    "name_of_station",
                    "string",
                    "Its current station name (instead of mac)",
                    false,
                ),
                p(
                    "new_name_of_station",
                    "string",
                    "The station name to give it",
                    false,
                ),
                p("ip", "string", "The IP address to give it", false),
                p(
                    "netmask",
                    "string",
                    "With ip (default 255.255.255.0)",
                    false,
                ),
                p("gateway", "string", "With ip (default 0.0.0.0)", false),
                p(
                    "permanent",
                    "boolean",
                    "Store across restarts (default true)",
                    false,
                ),
                p("signal", "boolean", "Flash its identification LED", false),
            ],
            json!({"type": DCP_SET, "mac": "02:00:00:00:00:01", "new_name_of_station": "conveyor-1"}),
        ),
        action(
            CONNECT,
            "Connect to a device (found by its name_of_station) with a module layout: \
             submodules [{slot, subslot, module_ident, submodule_ident, inputs: [{name, \
             type}], outputs: [{name, type}]}] — types bool, u8, i8, u16, i16, u32, i32, f32 — \
             as the device's GSDML describes them. Rust sends Connect, writes the optional \
             parameters (records written before PrmEnd: [{slot, subslot, index, fields: \
             [{type, value}]}]), sends PrmEnd, answers the device's ApplicationReady and starts \
             cyclic data; profinet_ar_established follows (or profinet_connect_failed). Outputs \
             are BAD until you set them",
            vec![
                p(
                    "name_of_station",
                    "string",
                    "The device to connect to",
                    true,
                ),
                p("submodules", "array", "The layout to connect with", true),
                p(
                    "cycle_ms",
                    "number",
                    "Cycle time: 1, 2, 4 … 512 ms (default 32)",
                    false,
                ),
                p(
                    "watchdog_factor",
                    "number",
                    "Cycles without data before either side drops the AR (default 30)",
                    false,
                ),
                p(
                    "parameters",
                    "array",
                    "Records to write before PrmEnd",
                    false,
                ),
            ],
            json!({"type": CONNECT, "name_of_station": "conveyor-1", "submodules": example_layout()}),
        ),
        action(
            SET_OUTPUTS,
            "Set the output values (controller → device) of one submodule of the running AR: \
             values is an object of its output field names to numbers (true/false for bool); \
             fields left out keep their value. iops good (default) or bad",
            vec![
                p("slot", "number", "Slot number of the submodule", true),
                p("subslot", "number", "Subslot number of the submodule", true),
                p("values", "object", "Output field name → value", false),
                p("iops", "string", "good (default) or bad", false),
            ],
            json!({"type": SET_OUTPUTS, "slot": 1, "subslot": 1, "values": {"outputs": 128}}),
        ),
        action(
            READ_RECORD,
            "Read a record from the connected device (or, with name_of_station and no AR, an \
             implicit read): index is a number or im0/im1/im2/im3. The answer arrives as \
             profinet_record_read",
            vec![
                p("slot", "number", "Slot (default 0)", false),
                p("subslot", "number", "Subslot (default 1)", false),
                p("index", "string", "im0, im1, im2, im3, or a number", true),
                p(
                    "name_of_station",
                    "string",
                    "Read implicitly from this device",
                    false,
                ),
            ],
            json!({"type": READ_RECORD, "index": "im0"}),
        ),
        action(
            WRITE_RECORD,
            "Write a record on the connected device: index im1/im2/im3 with im1 {tag_function, \
             tag_location} / im2 {installation_date} / im3 {descriptor}, or a number with \
             fields [{type, value}]. The result arrives as profinet_record_written",
            vec![
                p("slot", "number", "Slot (default 0)", false),
                p("subslot", "number", "Subslot (default 1)", false),
                p("index", "string", "im1, im2, im3, or a number", true),
                p(
                    "im1",
                    "object",
                    "I&M1 contents: tag_function, tag_location",
                    false,
                ),
                p("im2", "object", "I&M2 contents: installation_date", false),
                p("im3", "object", "I&M3 contents: descriptor", false),
                p(
                    "fields",
                    "array",
                    "Typed values in order, for other records",
                    false,
                ),
            ],
            json!({"type": WRITE_RECORD, "index": "im1", "im1": {"tag_function": "conveyor", "tag_location": "hall 2"}}),
        ),
        action(
            RELEASE,
            "Release the AR: cyclic data stops and the device is free for another controller",
            vec![],
            json!({"type": RELEASE}),
        ),
        action(
            "disconnect",
            "Stop: release any AR and close the client",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>, example: Value) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(actions())
        .with_log_template(
            LogTemplate::new()
                .with_info(format!("PROFINET {id}"))
                .with_debug(format!("PROFINET {id}: {{json(.)}}")),
        )
}

pub static DEVICES_DISCOVERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_devices_discovered",
        "The devices that answered a DCP Identify",
        vec![p(
            "devices",
            "array",
            "mac, name_of_station, type_of_station, vendor_id, device_id, ip, netmask, gateway, role",
            true,
        )],
        json!({"type": CONNECT, "name_of_station": "conveyor-1", "submodules": example_layout()}),
    )
});

pub static DCP_SET_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_dcp_set_result",
        "A device answered (or did not answer) a DCP Set",
        vec![
            p("mac", "string", "MAC address of the device", true),
            p(
                "results",
                "array",
                "Each option set: option, ok, error",
                false,
            ),
            p("error", "string", "Why nothing was set", false),
        ],
        json!({"type": IDENTIFY}),
    )
});

pub static CONNECT_FAILED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_connect_failed",
        "A Connect did not produce a running AR",
        vec![
            p(
                "name_of_station",
                "string",
                "Station name of the device",
                true,
            ),
            p(
                "stage",
                "string",
                "connect, parameters, prm_end or application_ready",
                true,
            ),
            p(
                "error",
                "string",
                "What went wrong (a PNIO status, a timeout, …)",
                true,
            ),
        ],
        json!({"type": IDENTIFY}),
    )
});

pub static AR_ESTABLISHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_ar_established",
        "The device confirmed ApplicationReady: cyclic data is running. Outputs are BAD until \
         you set them",
        vec![
            p(
                "name_of_station",
                "string",
                "Station name of the device",
                true,
            ),
            p(
                "ar_uuid",
                "string",
                "The application relationship (AR) UUID",
                true,
            ),
            p(
                "cycle_ms",
                "number",
                "Cyclic data period in milliseconds",
                true,
            ),
            p(
                "module_diff",
                "array",
                "Submodules the device reported as different",
                false,
            ),
            p("submodules", "array", "The layout, with field names", true),
        ],
        json!({"type": SET_OUTPUTS, "slot": 1, "subslot": 1, "values": {"outputs": 1}}),
    )
});

pub static INPUTS_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_inputs_changed",
        "The device's input values changed",
        vec![p(
            "inputs",
            "array",
            "Each changed submodule: slot, subslot, iops (good/bad), values {field: value}",
            true,
        )],
        json!({"type": SET_OUTPUTS, "slot": 1, "subslot": 1, "values": {"outputs": 0}}),
    )
});

pub static RECORD_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_record_read",
        "The answer to profinet_read_record",
        vec![
            p("slot", "number", "Slot number of the submodule", true),
            p("subslot", "number", "Subslot number of the submodule", true),
            p(
                "index",
                "number",
                "Record index (0xAFF0 is I&M0; 0-0x7FFF are user records)",
                true,
            ),
            p("record", "string", "I&M0, user record 123, …", true),
            p(
                "ok",
                "boolean",
                "Whether the device answered with data",
                true,
            ),
            p(
                "im0",
                "object",
                "Decoded I&M0 fields, for index 0xAFF0",
                false,
            ),
            p(
                "decoded",
                "object",
                "Decoded I&M1-3, or u8/u16/u32 readings",
                false,
            ),
            p("length", "number", "Octets returned", false),
            p("error", "string", "The PNIO status when refused", false),
        ],
        json!({"type": RELEASE}),
    )
});

pub static RECORD_WRITTEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_record_written",
        "The answer to profinet_write_record",
        vec![
            p(
                "index",
                "number",
                "Record index (0xAFF0 is I&M0; 0-0x7FFF are user records)",
                true,
            ),
            p("ok", "boolean", "Whether the device accepted it", true),
            p("error", "string", "The PNIO status when refused", false),
        ],
        json!({"type": RELEASE}),
    )
});

pub static AR_CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "profinet_ar_closed",
        "The AR ended: released, or the device stopped sending (watchdog)",
        vec![p(
            "reason",
            "string",
            "Why the AR ended: released, watchdog, …",
            true,
        )],
        json!({"type": IDENTIFY}),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        DEVICES_DISCOVERED_EVENT.clone(),
        DCP_SET_RESULT_EVENT.clone(),
        CONNECT_FAILED_EVENT.clone(),
        AR_ESTABLISHED_EVENT.clone(),
        INPUTS_CHANGED_EVENT.clone(),
        RECORD_READ_EVENT.clone(),
        RECORD_WRITTEN_EVENT.clone(),
        AR_CLOSED_EVENT.clone(),
    ]
}

/// A record index given as a number or as im0..im3.
pub fn record_index(v: Option<&Value>) -> Result<u16> {
    Ok(match v {
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "im0" => blocks::index::IM0,
            "im1" => blocks::index::IM1,
            "im2" => blocks::index::IM2,
            "im3" => blocks::index::IM3,
            other => values::ident(Some(&json!(other)), "index")?
                .try_into()
                .context("index is 0..=0xFFFF")?,
        },
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .context("index is 0..=0xFFFF")?,
        _ => bail!("index is required: im0, im1, im2, im3 or a number"),
    })
}

/// The record octets a `profinet_write_record` encodes to.
pub fn write_record_bytes(v: &Value) -> Result<(u16, Vec<u8>)> {
    let index = record_index(v.get("index"))?;
    let s = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let bytes = match index {
        blocks::index::IM1 => blocks::ImText::Im1 {
            tag_function: s(&v["im1"], "tag_function"),
            tag_location: s(&v["im1"], "tag_location"),
        }
        .encode()?,
        blocks::index::IM2 => blocks::ImText::Im2 {
            installation_date: s(&v["im2"], "installation_date"),
        }
        .encode()?,
        blocks::index::IM3 => blocks::ImText::Im3 {
            descriptor: s(&v["im3"], "descriptor"),
        }
        .encode()?,
        blocks::index::IM0 | blocks::index::IM4 | blocks::index::WRITE_MULTIPLE => {
            bail!("{} cannot be written here", blocks::index::name(index))
        }
        _ => dev::typed_fields_bytes(
            v.get("fields")
                .context("fields is required for this index")?,
        )?,
    };
    ensure!(
        bytes.len() <= blocks::MAX_RECORD_LEN as usize,
        "the record is {} octets, more than {}",
        bytes.len(),
        blocks::MAX_RECORD_LEN
    );
    Ok((index, bytes))
}

/// Check an action's shape before the session sees it.
pub fn check(v: &Value) -> Result<()> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .context("action needs a type")?;
    match t {
        IDENTIFY | RELEASE => {}
        DCP_SET => {
            ensure!(
                v.get("mac").is_some_and(|m| !m.is_null())
                    || v.get("name_of_station").is_some_and(|m| !m.is_null()),
                "profinet_dcp_set needs mac or name_of_station"
            );
            if let Some(m) = v.get("mac").and_then(Value::as_str) {
                crate::server::profinet::dcp::parse_mac(m)?;
            }
            if let Some(n) = v.get("new_name_of_station").and_then(Value::as_str) {
                crate::server::profinet::dcp::validate_station_name(n)?;
            }
            ensure!(
                v.get("new_name_of_station").is_some()
                    || v.get("ip").is_some()
                    || v.get("signal").and_then(Value::as_bool) == Some(true),
                "profinet_dcp_set changes nothing: give new_name_of_station, ip or signal"
            );
        }
        CONNECT => {
            v.get("name_of_station")
                .and_then(Value::as_str)
                .context("profinet_connect needs name_of_station")?;
            values::parse_layout(
                v.get("submodules")
                    .context("profinet_connect needs submodules")?,
            )?;
        }
        SET_OUTPUTS => {
            dev::input_update(v)?;
        }
        READ_RECORD => {
            record_index(v.get("index"))?;
        }
        WRITE_RECORD => {
            write_record_bytes(v)?;
        }
        other => bail!(
            "Unknown PROFINET controller action {other:?}: {IDENTIFY}, {DCP_SET}, {CONNECT}, \
             {SET_OUTPUTS}, {READ_RECORD}, {WRITE_RECORD}, {RELEASE}, disconnect"
        ),
    }
    Ok(())
}

impl crate::llm::actions::protocol_trait::Protocol for ProfinetClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "PROFINET"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>PROFINET"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "profinet",
            "profinet io",
            "profinet controller",
            "pnio",
            "io controller",
        ]
    }
    fn description(&self) -> &'static str {
        "PROFINET IO controller: discovers devices with DCP, names and addresses them, connects with a module layout, exchanges cyclic RT_CLASS_1 IO data, and reads/writes I&M records — the LLM decides the configuration, the outputs and the record access"
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
                description: "raw (default): remote_addr is the Ethernet interface to use \
                              (needs CAP_NET_RAW/BPF access). udp: remote_addr is the HOST:PORT \
                              of a device's lab link (whole Ethernet frames in UDP datagrams — \
                              no real PROFINET node speaks it)"
                    .into(),
                required: false,
                example: json!("raw"),
                default: Some(json!(crate::server::profinet::l2::TRANSPORT_RAW)),
            },
            ParameterDefinition {
                name: "station_name".into(),
                type_hint: "string".into(),
                description: "This controller's own station name (CMInitiatorStationName)".into(),
                required: false,
                example: json!("plc-1"),
                default: Some(json!(DEFAULT_STATION_NAME)),
            },
            ParameterDefinition {
                name: "rpc_port".into(),
                type_hint: "number".into(),
                description: "The UDP port devices answer PNIO RPC on".into(),
                required: false,
                example: json!(34964),
                default: Some(json!(crate::server::profinet::rpc::RPC_PORT)),
            },
            ParameterDefinition {
                name: "identify_ms".into(),
                type_hint: "number".into(),
                description: format!(
                    "How long an Identify collects answers (100-{MAX_IDENTIFY_MS})"
                ),
                required: false,
                example: json!(2000),
                default: Some(json!(DEFAULT_IDENTIFY_MS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .implementation("Hand-written PROFINET IO controller sharing the device's codec (src/server/profinet): DCP Identify (all, or by name) with a collection window, DCP Set of NameOfStation, IP parameters and Signal with the per-block results; PNIO-CM over connectionless DCE/RPC on UDP 34964 with retransmission — Connect (ARBlockReq, input and output IOCRBlockReq laid out from typed fields, AlarmCRBlockReq, one ExpectedSubmoduleBlockReq per slot) and its ModuleDiffBlock, parameter Writes, PrmEnd, an RPC endpoint answering the device's ApplicationReady, Read, ReadImplicit, Write and Release; an RT_CLASS_1 output provider (IOPS/IOCS, DataStatus, cycle counter, 802.1Q priority 6) and an input consumer with a watchdog")
            .llm_control("Which device to configure and what name and IP it gets; the module layout to connect with and the parameters written before PrmEnd; every output value and its IOPS; which records to read and write; when to release. Inputs and records arrive as typed values")
            .e2e_testing("tests/client/profinet: on Linux in a network namespace, rt-labs' p-net sample device (pn_dev) — DCP Identify and Set (renamed, re-identified under the new name), Connect with its DAP, digital IO and echo modules, PrmEnd, ApplicationReady, cyclic data (its counter input changes; an output the model sets lights its data LED file; the echo module returns the model's values), I&M0 read — with tshark's pn_dcp/pn_io/pn_rt dissectors reading the capture; in-process against NetGet's own device over the lab transport")
            .notes("Experimental: one independent device implementation (p-net); no second device (no other open-source PROFINET device stack is packaged), its pair job had not run in CI when it landed, and the raw transport needs CAP_NET_RAW. One AR at a time. Not implemented: alarms (an AlarmCR is requested; alarms the device sends are not acknowledged, so a device that raises one will eventually drop the AR), RT_CLASS_2/3, multicast CRs, fragmented RPC, WriteMultiple, a GSDML importer (the model supplies the layout). Outputs are IOPS BAD until the model sets them; on LLM failure nothing is sent.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Act as a PROFINET controller on eth0: find the device named conveyor-1, connect with its DAP and its 8-bit IO module in slot 1, and turn output bit 7 on whenever its input counter is above 100"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "PROFINET", "remote_addr": "eth0",
            "startup_params": {"station_name": "plc-1"},
            "instruction": "Connect to conveyor-1 with its access point and the 8-bit IO module in slot 1, then set the output to 128"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "profinet_devices_discovered", "handler": {"type": "static", "actions": [
                {"type": CONNECT, "name_of_station": "conveyor-1", "submodules": example_layout()}
            ]}},
            {"event_pattern": "profinet_ar_established", "handler": {"type": "static", "actions": [
                {"type": SET_OUTPUTS, "slot": 1, "subslot": 1, "values": {"outputs": 128}}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='profinet_devices_discovered' and any(d.get('name_of_station')=='conveyor-1' for d in e['devices']):\n  a=[{'type':'profinet_connect','name_of_station':'conveyor-1','submodules':[{'slot':0,'subslot':1,'module_ident':'0x1','submodule_ident':'0x1'},{'slot':1,'subslot':1,'module_ident':'0x32','submodule_ident':'0x132','inputs':[{'name':'inputs','type':'u8'}],'outputs':[{'name':'outputs','type':'u8'}]}]}]\nelif t=='profinet_inputs_changed':\n  v=[x for x in e['inputs'] if x['slot']==1]\n  if v: a=[{'type':'profinet_set_outputs','slot':1,'subslot':1,'values':{'outputs':128 if v[0]['values'].get('inputs',0)>100 else 0}}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Client for ProfinetClientProtocol {
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
