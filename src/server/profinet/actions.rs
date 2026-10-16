//! PROFINET IO device: what the model is asked and what it may answer.
//!
//! Rust runs DCP, the DCE/RPC endpoint, the AR state machine (Connect → PrmEnd →
//! ApplicationReady → data exchange → Release), the cyclic provider and consumer, IOPS/IOCS,
//! DataStatus, the watchdog and every bound. The model decides identity changes (a DCP Set),
//! whether a controller may connect, what the inputs are, what records say, and whether a
//! record write is accepted. Values travel as named, typed fields (`values.rs`), never bytes.
//!
//! Seven events, all raised in `mod.rs`:
//!
//! - `profinet_dcp_set_request` — a controller wants to change the station name or IP, flash
//!   the LED, or reset the device
//! - `profinet_connect_request` — a controller asks for an AR with this module layout
//! - `profinet_ar_established` — the controller confirmed ApplicationReady; data is flowing
//! - `profinet_outputs_changed` — the controller's output values (or their IOPS) changed
//! - `profinet_read_record` / `profinet_write_record` — acyclic record access (I&M and user
//!   records)
//! - `profinet_ar_closed` — an AR ended (Release, watchdog, or an abort)
use super::blocks::{self, index, Im0, ImText};
use super::values::{self, SubmoduleSpec};
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

pub const ACCEPT_CONNECT: &str = "profinet_accept_connect";
pub const REFUSE_CONNECT: &str = "profinet_refuse_connect";
pub const SET_INPUTS: &str = "profinet_set_inputs";
pub const ACCEPT_DCP_SET: &str = "profinet_accept_dcp_set";
pub const REFUSE_DCP_SET: &str = "profinet_refuse_dcp_set";
pub const READ_RESPONSE: &str = "profinet_read_response";
pub const ACCEPT_WRITE: &str = "profinet_accept_write";
pub const REFUSE_RECORD: &str = "profinet_refuse_record";
pub const ABORT_AR: &str = "profinet_abort_ar";

/// Default identity values. The vendor and device IDs are placeholders, not a PI assignment:
/// set them to the device being described.
pub const DEFAULT_STATION_NAME: &str = "netget-device";
pub const DEFAULT_TYPE_OF_STATION: &str = "NetGet PROFINET device";
pub const DEFAULT_VENDOR_ID: u16 = 0x0000;
pub const DEFAULT_DEVICE_ID: u16 = 0x0001;

#[derive(Clone, Default)]
pub struct ProfinetProtocol;

impl ProfinetProtocol {
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

fn accept_connect() -> ActionDefinition {
    action(
        ACCEPT_CONNECT,
        "Accept the controller's Connect: the AR is created, the device starts sending its \
         inputs every cycle, and mismatched submodules are reported back in a ModuleDiffBlock. \
         Inputs stay BAD (IOPS bad, zero data) until you set them with profinet_set_inputs",
        vec![],
        json!({"type": ACCEPT_CONNECT}),
        LogTemplate::new().with_info("PROFINET Connect accepted"),
    )
}

fn refuse_connect() -> ActionDefinition {
    action(
        REFUSE_CONNECT,
        "Refuse the controller's Connect; it is answered with a PNIO error and no AR is created",
        vec![p("reason", "string", "Why, for the log", false)],
        json!({"type": REFUSE_CONNECT, "reason": "unknown controller"}),
        LogTemplate::new().with_info("PROFINET Connect refused: {reason}"),
    )
}

fn set_inputs() -> ActionDefinition {
    action(
        SET_INPUTS,
        "Set the input values (device → controller) of one submodule: values is an object of \
         the submodule's input field names to numbers (or true/false for bool fields); fields \
         you leave out keep their value. iops \"good\" (default) marks the data valid, \"bad\" \
         tells the controller not to use it. Until a submodule's inputs are set its IOPS is BAD",
        vec![
            p("slot", "number", "Slot of the submodule", true),
            p("subslot", "number", "Subslot of the submodule", true),
            p(
                "values",
                "object",
                "Input field name → value, e.g. {\"temperature\": 215, \"running\": true}",
                false,
            ),
            p("iops", "string", "good (default) or bad", false),
        ],
        json!({"type": SET_INPUTS, "slot": 1, "subslot": 1, "values": {"inputs": 5}}),
        LogTemplate::new()
            .with_info("PROFINET inputs of {slot}/{subslot} set")
            .with_debug("PROFINET set inputs: {json(.)}"),
    )
}

fn accept_dcp_set() -> ActionDefinition {
    action(
        ACCEPT_DCP_SET,
        "Accept the DCP Set: the device takes the new station name and/or IP parameters (they \
         are what it reports from now on), flashes its LED, or resets — whatever was asked",
        vec![],
        json!({"type": ACCEPT_DCP_SET}),
        LogTemplate::new().with_info("PROFINET DCP Set accepted"),
    )
}

fn refuse_dcp_set() -> ActionDefinition {
    action(
        REFUSE_DCP_SET,
        "Refuse the DCP Set; every block is answered 'set not possible' and nothing changes",
        vec![p("reason", "string", "Why, for the log", false)],
        json!({"type": REFUSE_DCP_SET, "reason": "name is locked"}),
        LogTemplate::new().with_info("PROFINET DCP Set refused: {reason}"),
    )
}

fn read_response() -> ActionDefinition {
    action(
        READ_RESPONSE,
        "Answer a record read. For I&M0 (index 0xAFF0) give im0 {order_id (≤20 chars), \
         serial_number (≤16), hardware_revision, software_revision (\"V1.2.3\"), \
         revision_counter, profile_id, profile_specific_type, im_supported ([1,2,3] = which of \
         I&M1-4 exist); vendor_id defaults to the device's}. For I&M1 give im1 {tag_function \
         (≤32), tag_location (≤22)}, I&M2 im2 {installation_date \"YYYY-MM-DD HH:MM\"}, I&M3 im3 \
         {descriptor (≤54)}. For any other record give fields: [{\"type\": \"u16\", \"value\": \
         5}, …] encoded in order, big-endian",
        vec![
            p(
                "im0",
                "object",
                "I&M0 contents, for a read of index 0xAFF0",
                false,
            ),
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
                "For other records: typed values in order ({type: bool/u8/i8/u16/i16/u32/i32/f32, \
                 value})",
                false,
            ),
        ],
        json!({"type": READ_RESPONSE, "im0": {
            "order_id": "6ES7 000-0AA00-0AA0", "serial_number": "S C-X0001", "hardware_revision": 1,
            "software_revision": "V1.0.0", "revision_counter": 0, "profile_id": 0,
            "profile_specific_type": 0, "im_supported": [1]}}),
        LogTemplate::new()
            .with_info("PROFINET record read answered")
            .with_debug("PROFINET read response: {json(.)}"),
    )
}

fn accept_write() -> ActionDefinition {
    action(
        ACCEPT_WRITE,
        "Accept the record write: the controller is told it succeeded",
        vec![],
        json!({"type": ACCEPT_WRITE}),
        LogTemplate::new().with_info("PROFINET record write accepted"),
    )
}

fn refuse_record() -> ActionDefinition {
    action(
        REFUSE_RECORD,
        "Refuse a record read or write with a PNIO error: error is invalid_index (default), \
         access_denied, invalid_range or invalid_slot",
        vec![
            p(
                "error",
                "string",
                "invalid_index, access_denied, invalid_range or invalid_slot",
                false,
            ),
            p("reason", "string", "Why, for the log", false),
        ],
        json!({"type": REFUSE_RECORD, "error": "invalid_index"}),
        LogTemplate::new().with_info("PROFINET record access refused ({error})"),
    )
}

fn abort_ar() -> ActionDefinition {
    action(
        ABORT_AR,
        "End this AR now: cyclic data stops and the controller sees the device disappear (its \
         watchdog expires)",
        vec![p("reason", "string", "Why, for the log", false)],
        json!({"type": ABORT_AR, "reason": "maintenance"}),
        LogTemplate::new().with_info("PROFINET AR aborted by decision: {reason}"),
    )
}

pub static ACCEPT_CONNECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(accept_connect);
pub static REFUSE_CONNECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(refuse_connect);
pub static SET_INPUTS_ACTION: LazyLock<ActionDefinition> = LazyLock::new(set_inputs);
pub static ACCEPT_DCP_SET_ACTION: LazyLock<ActionDefinition> = LazyLock::new(accept_dcp_set);
pub static REFUSE_DCP_SET_ACTION: LazyLock<ActionDefinition> = LazyLock::new(refuse_dcp_set);
pub static READ_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(read_response);
pub static ACCEPT_WRITE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(accept_write);
pub static REFUSE_RECORD_ACTION: LazyLock<ActionDefinition> = LazyLock::new(refuse_record);
pub static ABORT_AR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(abort_ar);

pub static DCP_SET_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_dcp_set_request",
        "A controller sent a DCP Set: decide whether the device takes the new name/IP (or \
         flashes its LED, or resets)",
        json!({"type": ACCEPT_DCP_SET}),
    )
    .with_parameters(vec![
        p(
            "controller_mac",
            "string",
            "MAC address of the controller that sent the Set",
            true,
        ),
        p(
            "name_of_station",
            "string",
            "The requested station name (\"\" clears it)",
            false,
        ),
        p(
            "ip",
            "object",
            "The requested IP parameters: ip, netmask, gateway",
            false,
        ),
        p(
            "permanent",
            "boolean",
            "Whether the controller asked for the change to persist",
            false,
        ),
        p(
            "signal",
            "boolean",
            "The controller asked the device to flash its LED",
            false,
        ),
        p(
            "factory_reset",
            "boolean",
            "The controller asked for a factory reset",
            false,
        ),
        p(
            "current",
            "object",
            "The device's current name and IP",
            true,
        ),
        p(
            "ar_active",
            "boolean",
            "Whether an IO controller currently has an AR",
            true,
        ),
    ])
    .with_actions(vec![
        ACCEPT_DCP_SET_ACTION.clone(),
        REFUSE_DCP_SET_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": REFUSE_DCP_SET, "reason": "name is locked"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET DCP Set from {controller_mac}")
            .with_debug("PROFINET DCP Set request: {json(.)}"),
    )
});

pub static CONNECT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_connect_request",
        "An IO controller asks for an application relationship (AR) with the module layout it \
         expects. Accept it (and optionally set the inputs right away) or refuse it",
        json!({"type": ACCEPT_CONNECT}),
    )
    .with_parameters(vec![
        p("ar_uuid", "string", "The AR being requested", true),
        p(
            "ar_type",
            "string",
            "io_controller (cyclic data) or supervisor_device_access (records only)",
            true,
        ),
        p(
            "controller",
            "object",
            "station_name, mac and address of the controller",
            true,
        ),
        p(
            "submodules",
            "array",
            "Each expected submodule: slot, subslot, module_ident, submodule_ident, \
             input_length, output_length, state (ok, wrong_module, wrong_submodule, no_module, \
             no_submodule), and the device's input/output fields when it has the submodule",
            false,
        ),
        p("cycle_ms", "number", "The cyclic data period", false),
        p(
            "watchdog_ms",
            "number",
            "How long without data before the AR drops",
            false,
        ),
    ])
    .with_actions(vec![
        ACCEPT_CONNECT_ACTION.clone(),
        REFUSE_CONNECT_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": REFUSE_CONNECT, "reason": "unknown controller"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET Connect from {controller.station_name} ({ar_type})")
            .with_debug("PROFINET Connect request: {json(.)}"),
    )
});

pub static AR_ESTABLISHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_ar_established",
        "The controller confirmed ApplicationReady: cyclic data is running. Set the inputs it \
         should see (they are BAD until you do)",
        json!({"type": SET_INPUTS, "slot": 1, "subslot": 1, "values": {"inputs": 0}}),
    )
    .with_parameters(vec![
        p(
            "ar_uuid",
            "string",
            "The application relationship (AR) UUID",
            true,
        ),
        p("controller", "object", "station_name, mac, address", true),
        p(
            "submodules",
            "array",
            "slot, subslot, inputs and outputs fields of every submodule in the AR",
            true,
        ),
        p("cycle_ms", "number", "The cyclic data period", true),
    ])
    .with_actions(vec![SET_INPUTS_ACTION.clone(), ABORT_AR_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET AR {ar_uuid} established")
            .with_debug("PROFINET AR established: {json(.)}"),
    )
});

pub static OUTPUTS_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_outputs_changed",
        "The controller's output values changed (they are what it commands this device to do)",
        json!({"type": SET_INPUTS, "slot": 1, "subslot": 1, "values": {"inputs": 1}}),
    )
    .with_parameters(vec![
        p(
            "ar_uuid",
            "string",
            "The application relationship (AR) UUID",
            true,
        ),
        p(
            "outputs",
            "array",
            "Each changed output submodule: slot, subslot, iops (good/bad), values {field: \
             value}",
            true,
        ),
    ])
    .with_actions(vec![SET_INPUTS_ACTION.clone(), ABORT_AR_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET outputs changed on AR {ar_uuid}")
            .with_debug("PROFINET outputs: {json(.)}"),
    )
});

pub static READ_RECORD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_read_record",
        "The controller reads a record (I&M0-3 or a user record). Answer with \
         profinet_read_response or refuse",
        json!({"type": READ_RESPONSE, "im0": {"order_id": "NG-1", "serial_number": "0001",
            "hardware_revision": 1, "software_revision": "V1.0.0"}}),
    )
    .with_parameters(vec![
        p("slot", "number", "Slot number of the submodule", true),
        p("subslot", "number", "Subslot number of the submodule", true),
        p(
            "index",
            "number",
            "Record index (0xAFF0 is I&M0; 0-0x7FFF are user records)",
            true,
        ),
        p(
            "record",
            "string",
            "What the index is: I&M0, I&M1, user record 123, …",
            true,
        ),
        p(
            "max_length",
            "number",
            "The most octets the controller accepts",
            true,
        ),
        p(
            "implicit",
            "boolean",
            "Read without an AR (ReadImplicit)",
            true,
        ),
    ])
    .with_actions(vec![
        READ_RESPONSE_ACTION.clone(),
        REFUSE_RECORD_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": REFUSE_RECORD, "error": "invalid_index"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET read {record} at {slot}/{subslot}")
            .with_debug("PROFINET read request: {json(.)}"),
    )
});

pub static WRITE_RECORD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_write_record",
        "The controller writes a record. Accept or refuse it",
        json!({"type": ACCEPT_WRITE}),
    )
    .with_parameters(vec![
        p("slot", "number", "Slot number of the submodule", true),
        p("subslot", "number", "Subslot number of the submodule", true),
        p(
            "index",
            "number",
            "Record index (0xAFF0 is I&M0; 0-0x7FFF are user records)",
            true,
        ),
        p("record", "string", "What the index is", true),
        p(
            "length",
            "number",
            "Number of octets the controller wrote",
            true,
        ),
        p(
            "decoded",
            "object",
            "I&M1-3 text fields, or u8/u16/u32 readings of a 1/2/4-octet user record",
            false,
        ),
        p(
            "text",
            "string",
            "The data as text, when it is printable",
            false,
        ),
    ])
    .with_actions(vec![
        ACCEPT_WRITE_ACTION.clone(),
        REFUSE_RECORD_ACTION.clone(),
        SET_INPUTS_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": REFUSE_RECORD, "error": "access_denied"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("PROFINET write {record} at {slot}/{subslot}")
            .with_debug("PROFINET write request: {json(.)}"),
    )
});

pub static AR_CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "profinet_ar_closed",
        "An AR ended: the controller released it, its watchdog expired, or it was aborted. \
         Nothing to answer",
        json!({"type": "show_message", "message": "PROFINET AR closed"}),
    )
    .with_parameters(vec![
        p(
            "ar_uuid",
            "string",
            "The application relationship (AR) UUID",
            true,
        ),
        p("reason", "string", "released, watchdog, aborted, …", true),
    ])
    .with_no_actions()
    .with_log_template(LogTemplate::new().with_info("PROFINET AR {ar_uuid} closed: {reason}"))
});

pub fn event_types() -> Vec<EventType> {
    vec![
        DCP_SET_REQUEST_EVENT.clone(),
        CONNECT_REQUEST_EVENT.clone(),
        AR_ESTABLISHED_EVENT.clone(),
        OUTPUTS_CHANGED_EVENT.clone(),
        READ_RECORD_EVENT.clone(),
        WRITE_RECORD_EVENT.clone(),
        AR_CLOSED_EVENT.clone(),
    ]
}

fn get_u16(v: &Value, key: &str) -> Result<u16> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .with_context(|| format!("\"{key}\" must be a number 0-65535"))
}

fn opt_u16(v: &Value, key: &str, default: u16) -> Result<u16> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(_) => get_u16(v, key),
    }
}

/// The inputs a `profinet_set_inputs` names, checked for shape (the layout check happens where
/// the layout is known).
pub struct InputUpdate {
    pub slot: u16,
    pub subslot: u16,
    pub values: Map<String, Value>,
    pub good: bool,
}

pub fn input_update(v: &Value) -> Result<InputUpdate> {
    let values = match v.get("values") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(other) => bail!("\"values\" must be an object of field → value, got {other}"),
    };
    let good = match v.get("iops").and_then(Value::as_str) {
        None | Some("good") => true,
        Some("bad") => false,
        Some(other) => bail!("\"iops\" is good or bad, not {other:?}"),
    };
    Ok(InputUpdate {
        slot: get_u16(v, "slot")?,
        subslot: get_u16(v, "subslot")?,
        values,
        good,
    })
}

/// What a `profinet_read_response` encodes to, for the index being read.
pub fn read_record_bytes(v: &Value, idx: u16, vendor_id: u16) -> Result<Vec<u8>> {
    let present: Vec<&str> = ["im0", "im1", "im2", "im3", "fields"]
        .into_iter()
        .filter(|k| v.get(*k).is_some_and(|x| !x.is_null()))
        .collect();
    ensure!(
        present.len() == 1,
        "give exactly one of im0, im1, im2, im3 or fields (got {})",
        if present.is_empty() {
            "none".to_string()
        } else {
            present.join(", ")
        }
    );
    let want = match idx {
        index::IM0 => "im0",
        index::IM1 => "im1",
        index::IM2 => "im2",
        index::IM3 => "im3",
        _ => "fields",
    };
    ensure!(
        present[0] == want,
        "record {} is answered with {want}, not {}",
        index::name(idx),
        present[0]
    );
    let o = &v[want];
    let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    match want {
        "im0" => {
            let supported = match o.get("im_supported") {
                None | Some(Value::Null) => 0u16,
                Some(Value::Array(a)) => {
                    let mut bits = 0u16;
                    for x in a {
                        let n = x
                            .as_u64()
                            .filter(|n| (1..=15).contains(n))
                            .context("im_supported lists I&M numbers 1-15")?;
                        bits |= 1 << n;
                    }
                    bits
                }
                Some(_) => bail!("im_supported is a list such as [1, 2, 3]"),
            };
            Im0 {
                vendor_id: opt_u16(o, "vendor_id", vendor_id)?,
                order_id: s("order_id"),
                serial_number: s("serial_number"),
                hardware_revision: opt_u16(o, "hardware_revision", 0)?,
                software_revision: blocks::parse_software_revision(
                    o.get("software_revision")
                        .and_then(Value::as_str)
                        .unwrap_or("V0.0.0"),
                )?,
                revision_counter: opt_u16(o, "revision_counter", 0)?,
                profile_id: opt_u16(o, "profile_id", 0)?,
                profile_specific_type: opt_u16(o, "profile_specific_type", 0)?,
                im_version: (1, 1),
                im_supported: supported,
            }
            .encode()
        }
        "im1" => ImText::Im1 {
            tag_function: s("tag_function"),
            tag_location: s("tag_location"),
        }
        .encode(),
        "im2" => ImText::Im2 {
            installation_date: s("installation_date"),
        }
        .encode(),
        "im3" => ImText::Im3 {
            descriptor: s("descriptor"),
        }
        .encode(),
        _ => typed_fields_bytes(&v["fields"]),
    }
}

/// `[{"type": "u16", "value": 5}, …]` → big-endian octets.
pub fn typed_fields_bytes(v: &Value) -> Result<Vec<u8>> {
    let arr = v
        .as_array()
        .context("fields is an array of {type, value}")?;
    ensure!(
        arr.len() <= values::MAX_FIELDS,
        "fields has {} entries, at most {}",
        arr.len(),
        values::MAX_FIELDS
    );
    let mut fields = Vec::new();
    let mut vals = Map::new();
    for (i, f) in arr.iter().enumerate() {
        let ty = values::FieldType::parse(
            f.get("type")
                .and_then(Value::as_str)
                .with_context(|| format!("fields[{i}] needs a \"type\""))?,
        )?;
        let name = format!("f{i}");
        vals.insert(
            name.clone(),
            f.get("value")
                .cloned()
                .with_context(|| format!("fields[{i}] needs a \"value\""))?,
        );
        fields.push(values::Field { name, ty });
    }
    let mut buf = vec![0u8; values::fields_len(&fields)];
    values::encode_into(&fields, &vals, &mut buf)?;
    Ok(buf)
}

/// The PNIORW ErrorCode1 a `profinet_refuse_record` names.
pub fn refuse_code(v: &Value) -> Result<u8> {
    use super::rpc::rw_error;
    Ok(match v.get("error").and_then(Value::as_str) {
        None | Some("invalid_index") => rw_error::ACCESS_INVALID_INDEX,
        Some("access_denied") => rw_error::ACCESS_DENIED,
        Some("invalid_range") => rw_error::ACCESS_INVALID_RANGE,
        Some("invalid_slot") => rw_error::ACCESS_INVALID_SLOT,
        Some(other) => bail!(
            "error {other:?} is one of invalid_index, access_denied, invalid_range, invalid_slot"
        ),
    })
}

impl Protocol for ProfinetProtocol {
    fn protocol_name(&self) -> &'static str {
        "PROFINET"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>PROFINET"
    }
    fn description(&self) -> &'static str {
        "PROFINET IO device: answers DCP discovery, accepts an IO controller's Connect for a described module layout, exchanges cyclic RT_CLASS_1 IO data, and serves I&M records — the LLM decides identity changes, connections, input values and record contents"
    }
    fn example_prompt(&self) -> &'static str {
        "Be a PROFINET IO device on eth0 named conveyor-1 with an 8-bit input module in slot 1: accept any controller, report the input as the number of boxes counted, and log every output change"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "profinet",
            "profinet io",
            "profinet device",
            "pnio",
            "dcp",
            "io device",
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
            .well_known_udp_port(34964)
            // Every refusal PROFINET defines is sent: a DCP Set the model did not approve is
            // answered "set not possible", an unanswered Connect gets a PNIO error, a record
            // read gets "resource unavailable". Inputs nobody set carry IOPS BAD.
            .answers_on_failure()
            .max_inbound_bytes(super::rt::MAX_FRAME_LEN)
            .implementation(
                "Hand-written PROFINET IO device (no crate): DCP Identify (AllSelector and \
                 NameOfStation filters, ResponseDelay), Get and Set (NameOfStation, IP \
                 parameters, Signal, factory reset, Start/Stop) on EtherType 0x8892; \
                 connectionless DCE/RPC on UDP 34964 (both dreps, replayed responses for \
                 retransmissions, PING answered WORKING/NOCALL) carrying PNIO-CM Connect \
                 (ARBlockReq, IOCRBlockReq, AlarmCRBlockReq, ExpectedSubmoduleBlockReq → \
                 ARBlockRes, IOCRBlockRes with FrameIDs assigned from the RT_CLASS_1 range, \
                 AlarmCRBlockRes, ModuleDiffBlock), Control (PrmBegin, PrmEnd), the device's \
                 own ApplicationReady CControl request to the controller with retransmission, \
                 Release, Read, ReadImplicit and Write with I&M0-3 encoded from structured \
                 fields; RT_CLASS_1 cyclic frames (802.1Q priority from the IOCR tag header, \
                 cycle counter, DataStatus, IOPS/IOCS) at the negotiated period, an output \
                 consumer with a watchdog, and IOSAR device-access ARs that expire on RPC \
                 inactivity. Two transports: raw Ethernet through pnet (AF_PACKET / BPF) and a \
                 lab transport carrying whole frames in UDP datagrams",
            )
            .llm_control(
                "Whether a DCP Set (name, IP, LED signal, reset) is taken; whether a \
                 controller's Connect is accepted; every input value and its IOPS; I&M and user \
                 record contents; whether record writes are accepted; when to abort an AR. \
                 Output changes arrive as typed values",
            )
            .e2e_testing(
                "tests/server/profinet: in-process over the lab transport (NetGet's own \
                 controller and a hand-built raw peer for the bounds and fail-closed paths), \
                 the codec against literal frames, and on Linux in a network namespace \
                 profinet-py (an independent Python IO controller: DCP discovery, Connect, \
                 PrmEnd, ApplicationReady, RT_CLASS_1 cyclic data, I&M0 read) and pnio_dcp \
                 (Codewerk's Python DCP library: identify, set name, set IP, blink) against the \
                 raw transport, with tshark's pn_dcp / pn_io / pn_rt dissectors reading a live \
                 capture of both directions",
            )
            .notes(
                "Experimental: one independent IO controller (profinet-py) and one independent \
                 DCP implementation (pnio_dcp); no PLC (a Siemens or CODESYS controller) has \
                 been pointed at it, its pair job had not run in CI when it landed, and the raw \
                 transport needs CAP_NET_RAW so it runs only in that job. Not implemented: \
                 alarms (the AlarmCR is accepted, no alarm is ever sent and none is \
                 acknowledged), RT_CLASS_2/3 and RT over UDP, multicast CRs, MRP, LLDP/SNMP \
                 neighbourhood records, diagnosis records, shared devices beyond one IO AR plus \
                 one supervisor AR, WriteMultiple (0xE040), fragmented RPC, and actually \
                 changing the host's IP when a DCP Set is accepted (the device reports the new \
                 address; the RPC endpoint stays where it was bound). Cyclic timing is soft \
                 real-time from a tokio timer: 1 ms is the fastest cycle accepted and jitter is \
                 whatever the host gives. On LLM failure: DCP Set refused (set not possible), \
                 Connect refused with a PNIO error, record reads answered 'resource \
                 unavailable', writes refused, and inputs stay IOPS BAD.",
            )
            .build()
    }

    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // The RPC endpoint is a host and port (loopback and 34964 unless the caller names
        // them); the raw transport also needs the caller's interface, which has no default —
        // guessing one would put PROFINET frames on a link nobody chose.
        Some(crate::protocol::BindingDefaults::port_based(
            "127.0.0.1",
            super::rpc::RPC_PORT,
        ))
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "transport".into(),
                type_hint: "string".into(),
                description: "raw (default): real Ethernet on the server's interface, needs \
                              CAP_NET_RAW/BPF access. udp: lab transport carrying whole \
                              Ethernet frames in UDP datagrams — no real PROFINET node speaks \
                              it"
                .into(),
                required: false,
                example: json!("raw"),
                default: Some(json!(crate::server::profinet::l2::TRANSPORT_RAW)),
            },
            ParameterDefinition {
                name: "udp_peer".into(),
                type_hint: "string".into(),
                description: "Lab transport only: HOST:PORT that frames are sent to (default: \
                              whoever sent the last frame)"
                    .into(),
                required: false,
                example: json!("127.0.0.1:40000"),
                default: None,
            },
            ParameterDefinition {
                name: "name_of_station".into(),
                type_hint: "string".into(),
                description: "The DCP station name (lower-case letters, digits, '-', '.')".into(),
                required: false,
                example: json!("conveyor-1"),
                default: Some(json!(DEFAULT_STATION_NAME)),
            },
            ParameterDefinition {
                name: "type_of_station".into(),
                type_hint: "string".into(),
                description: "The DCP DeviceVendorValue (what the device says it is)".into(),
                required: false,
                example: json!("ET 200SP"),
                default: Some(json!(DEFAULT_TYPE_OF_STATION)),
            },
            ParameterDefinition {
                name: "vendor_id".into(),
                type_hint: "number".into(),
                description: "PROFINET VendorID reported by DCP and in I&M0 (0x002A is Siemens); \
                              the default is a placeholder, not an assignment"
                    .into(),
                required: false,
                example: json!(42),
                default: Some(json!(DEFAULT_VENDOR_ID)),
            },
            ParameterDefinition {
                name: "device_id".into(),
                type_hint: "number".into(),
                description: "PROFINET DeviceID".into(),
                required: false,
                example: json!(1),
                default: Some(json!(DEFAULT_DEVICE_ID)),
            },
            ParameterDefinition {
                name: "ip".into(),
                type_hint: "string".into(),
                description: "The IP address DCP reports (default: the bound host, or the \
                              interface's address when bound to 0.0.0.0)"
                    .into(),
                required: false,
                example: json!("192.168.0.50"),
                default: None,
            },
            ParameterDefinition {
                name: "netmask".into(),
                type_hint: "string".into(),
                description: "The netmask DCP reports (default: the interface's, else \
                              255.255.255.0)"
                    .into(),
                required: false,
                example: json!("255.255.255.0"),
                default: None,
            },
            ParameterDefinition {
                name: "gateway".into(),
                type_hint: "string".into(),
                description: "The gateway DCP reports (default 0.0.0.0, none)".into(),
                required: false,
                example: json!("192.168.0.1"),
                default: None,
            },
            ParameterDefinition {
                name: "modules".into(),
                type_hint: "array".into(),
                description: format!(
                    "The device's modules: each {{slot, subslot, module_ident, \
                     submodule_ident, inputs: [{{name, type}}], outputs: [{{name, type}}]}} \
                     with types bool, u8, i8, u16, i16, u32, i32, f32 (at most {} \
                     submodules). Default: the access point in slot 0 (subslots 1, 0x8000, \
                     0x8001) and module 0x32/submodule 0x132 in slot 1 with one u8 input \
                     named inputs and one u8 output named outputs",
                    blocks::MAX_SUBMODULES
                ),
                required: false,
                example: json!([
                    {"slot": 0, "subslot": 1, "module_ident": "0x1", "submodule_ident": "0x1"},
                    {"slot": 1, "subslot": 1, "module_ident": "0x32", "submodule_ident": "0x132",
                     "inputs": [{"name": "boxes", "type": "u8"}],
                     "outputs": [{"name": "belt_on", "type": "bool"}]}
                ]),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![set_inputs(), abort_ar()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_connect(),
            refuse_connect(),
            set_inputs(),
            accept_dcp_set(),
            refuse_dcp_set(),
            read_response(),
            accept_write(),
            refuse_record(),
            abort_ar(),
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
            "name_of_station": "conveyor-1",
            "vendor_id": 42,
            "device_id": 1,
            "modules": [
                {"slot": 0, "subslot": 1, "module_ident": "0x1", "submodule_ident": "0x1"},
                {"slot": 1, "subslot": 1, "module_ident": "0x32", "submodule_ident": "0x132",
                 "inputs": [{"name": "boxes", "type": "u8"}],
                 "outputs": [{"name": "belt_on", "type": "bool"}]}
            ]
        });
        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "profinet",
                "interface": "eth0",
                "host": "0.0.0.0",
                "port": 34964,
                "startup_params": params,
                "instruction": "Accept any controller. When the AR is up, report boxes = 0; \
                                each time belt_on goes true, add one to boxes. Answer I&M0 \
                                with order id NG-CONV-1, serial 0001, version V1.0.0. Refuse \
                                renaming."
            }),
            json!({
                "type": "open_server",
                "base_stack": "profinet",
                "interface": "eth0",
                "host": "0.0.0.0",
                "port": 34964,
                "startup_params": params,
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='profinet_connect_request': a=[{'type':'profinet_accept_connect'},{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'boxes':0}}]\nelif t=='profinet_dcp_set_request': a=[{'type':'profinet_refuse_dcp_set','reason':'locked'}]\nelif t=='profinet_read_record' and e['index']==0xAFF0: a=[{'type':'profinet_read_response','im0':{'order_id':'NG-CONV-1','serial_number':'0001','software_revision':'V1.0.0'}}]\nelif t=='profinet_read_record': a=[{'type':'profinet_refuse_record'}]\nelif t=='profinet_write_record': a=[{'type':'profinet_accept_write'}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "profinet",
                "interface": "eth0",
                "host": "0.0.0.0",
                "port": 34964,
                "startup_params": params,
                "event_handlers": [
                    {"event_pattern": "profinet_connect_request", "handler": {"type": "static", "actions": [
                        {"type": "profinet_accept_connect"},
                        {"type": "profinet_set_inputs", "slot": 1, "subslot": 1, "values": {"boxes": 7}}
                    ]}},
                    {"event_pattern": "profinet_dcp_set_request", "handler": {"type": "static", "actions": [
                        {"type": "profinet_refuse_dcp_set", "reason": "locked"}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                ]
            }),
        )
    }
}

impl Server for ProfinetProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::ProfinetServer::spawn(ctx).await })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        match kind {
            SET_INPUTS => {
                input_update(&action)?;
            }
            READ_RESPONSE => {
                // The index is known only where the request is; check the shape here.
                let n = ["im0", "im1", "im2", "im3", "fields"]
                    .iter()
                    .filter(|k| action.get(**k).is_some_and(|x| !x.is_null()))
                    .count();
                ensure!(
                    n == 1,
                    "profinet_read_response needs exactly one of im0, im1, im2, im3, fields"
                );
                if let Some(f) = action.get("fields").filter(|f| !f.is_null()) {
                    typed_fields_bytes(f)?;
                }
            }
            REFUSE_RECORD => {
                refuse_code(&action)?;
            }
            ACCEPT_CONNECT | REFUSE_CONNECT | ACCEPT_DCP_SET | REFUSE_DCP_SET | ACCEPT_WRITE
            | ABORT_AR => {}
            "close_connection" => return Ok(ActionResult::CloseConnection),
            other => {
                return Err(anyhow!(
                    "Unknown PROFINET action '{other}'. Valid actions: {ACCEPT_CONNECT}, \
                     {REFUSE_CONNECT}, {SET_INPUTS}, {ACCEPT_DCP_SET}, {REFUSE_DCP_SET}, \
                     {READ_RESPONSE}, {ACCEPT_WRITE}, {REFUSE_RECORD}, {ABORT_AR}"
                ))
            }
        }
        Ok(ActionResult::Custom {
            name: kind.to_string(),
            data: action,
        })
    }
}

/// The layout a startup `modules` parameter describes, or the default.
pub fn layout_from_params(v: Option<&Value>) -> Result<Vec<SubmoduleSpec>> {
    match v {
        None | Some(Value::Null) => Ok(values::default_layout()),
        Some(v) => values::parse_layout(v),
    }
}
