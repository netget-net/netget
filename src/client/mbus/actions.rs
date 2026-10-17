//! M-Bus master actions, events and metadata.
//!
//! NetGet is the master behind an M-Bus/IP gateway: it dials the gateway's TCP port and the
//! model decides which meters to look for and read, and what to write. The link layer — SND_NKE,
//! REQ_UD2 with the FCB toggled per readout, selection, the wildcard search, collision
//! detection, multi-telegram readouts — and every byte are the shared codec's
//! (`src/server/mbus/frame.rs`, `records.rs`); the model works in addresses and records.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::mbus::{frame, records};
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every operation travels as.
pub const OPERATION_RESULT: &str = "mbus_operation";

/// How long a meter has to answer one telegram. At 2400 baud a full 261-byte telegram takes
/// 1.1 s on the wire, so a gateway needs well over a second.
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 2000;
pub const MIN_RESPONSE_TIMEOUT_MS: u64 = 20;
pub const MAX_RESPONSE_TIMEOUT_MS: u64 = 60_000;

#[derive(Default)]
pub struct MbusClientProtocol;

impl MbusClientProtocol {
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

fn target_params() -> Vec<Parameter> {
    vec![
        p(
            "address",
            "number",
            "The meter's primary address, 0-250 (give this or secondary_address)",
            false,
        ),
        p(
            "secondary_address",
            "string",
            "The meter's 16-character secondary address (8 identification digits, then \
             manufacturer, version and medium bytes in hex, e.g. \"123456782D2C0107\"); NetGet \
             selects it and talks to it at address 253",
            false,
        ),
    ]
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
                .with_info(format!("-> M-Bus {}", name.trim_start_matches("mbus_")))
                .with_debug(format!("M-Bus {name}: {{json(.)}}")),
        ),
    }
}

fn read_action() -> ActionDefinition {
    let mut params = target_params();
    params.push(p(
        "max_telegrams",
        "number",
        &format!(
            "Telegrams to follow when the meter says more records follow (1-{}, default {})",
            records::MAX_TELEGRAMS,
            records::MAX_TELEGRAMS
        ),
        false,
    ));
    action(
        "mbus_read",
        "Read a meter's data (REQ_UD2 -> RSP_UD), following a multi-telegram readout with the \
         FCB toggled; the decoded records arrive as mbus_data",
        params,
        json!({"type": "mbus_read", "address": 1}),
    )
}

fn scan_primary_action() -> ActionDefinition {
    action(
        "mbus_scan_primary",
        "Look for meters by primary address: a SND_NKE to every address in the range, \
         reporting which acknowledged and where two answered at once (mbus_scan_result). Each \
         silent address costs one response timeout",
        vec![
            p("from", "number", "First address (default 0)", false),
            p("to", "number", "Last address (default 250)", false),
        ],
        json!({"type": "mbus_scan_primary", "from": 0, "to": 10}),
    )
}

fn scan_secondary_action() -> ActionDefinition {
    action(
        "mbus_scan_secondary",
        "Find meters by secondary address: select with a wildcard mask and narrow it digit by \
         digit wherever two meters answer at once, reading each meter found for its full \
         address (mbus_scan_result)",
        vec![p(
            "mask",
            "string",
            "16 hex characters, F a wildcard nibble (default FFFFFFFFFFFFFFFF: every meter)",
            false,
        )],
        json!({"type": "mbus_scan_secondary", "mask": "FFFFFFFFFFFFFFFF"}),
    )
}

fn write_action() -> ActionDefinition {
    let mut params = target_params();
    params.push(p(
        "records",
        "array",
        "Data records to send (SND_UD, CI 0x51), written like a slave's: {\"quantity\", \
         \"unit\", \"value\"}, e.g. [{\"quantity\": \"energy\", \"unit\": \"kWh\", \"value\": \
         0}] to reset a counter",
        true,
    ));
    action(
        "mbus_write",
        "Send a meter data records (SND_UD); whether it acknowledged arrives as mbus_ack",
        params,
        json!({"type": "mbus_write", "address": 1, "records": [{"quantity": "energy", "unit": "Wh", "value": 0}]}),
    )
}

fn set_address_action() -> ActionDefinition {
    let mut params = target_params();
    params.push(p(
        "new_address",
        "number",
        "The primary address to give the meter, 0-250",
        true,
    ));
    action(
        "mbus_set_primary_address",
        "Give a meter a new primary address (SND_UD with a bus-address record)",
        params,
        json!({"type": "mbus_set_primary_address", "secondary_address": "123456782D2C0107", "new_address": 7}),
    )
}

fn reset_action() -> ActionDefinition {
    let mut params = target_params();
    params.push(p(
        "subcode",
        "number",
        "Optional reset subcode byte (0-255)",
        false,
    ));
    action(
        "mbus_application_reset",
        "Reset a meter's application (SND_UD, CI 0x50); the answer arrives as mbus_ack",
        params,
        json!({"type": "mbus_application_reset", "address": 1}),
    )
}

fn ping_action() -> ActionDefinition {
    action(
        "mbus_ping",
        "Initialise a meter's link (SND_NKE): resets its FCB and any readout in progress; the \
         answer arrives as mbus_ack",
        vec![p("address", "number", "Primary address, 0-250", true)],
        json!({"type": "mbus_ping", "address": 1}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection to the gateway",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        read_action(),
        scan_primary_action(),
        scan_secondary_action(),
        write_action(),
        set_address_action(),
        reset_action(),
        ping_action(),
        disconnect_action(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": "mbus_read", "address": 1}))
        .with_parameters(params)
        .with_actions(all_actions())
        .with_log_template(
            LogTemplate::new()
                .with_info(format!("M-Bus {id}"))
                .with_debug(format!("M-Bus {id}: {{json(.)}}")),
        )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "mbus_connected",
        "Connected to the M-Bus/IP gateway; nothing has been sent yet",
        vec![p("gateway", "string", "The gateway's address", true)],
    )
});

pub static DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "mbus_data",
        "A meter answered mbus_read: its identity and its decoded records",
        vec![
            p(
                "target",
                "object",
                "What was read: address or secondary_address",
                true,
            ),
            p(
                "meter",
                "object",
                "secondary_address, id, manufacturer, version, medium, access_number, status",
                true,
            ),
            p(
                "records",
                "array",
                "Records: quantity, unit, value (in the unit), raw_value and exponent when \
                 scaled, encoding, function, storage, tariff, subunit",
                true,
            ),
            p(
                "telegrams",
                "number",
                "How many telegrams the readout took",
                true,
            ),
            p(
                "truncated",
                "boolean",
                "True when the meter had more telegrams than max_telegrams allowed",
                false,
            ),
        ],
    )
});

pub static SCAN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "mbus_scan_result",
        "A scan finished: the meters found and where meters collided",
        vec![
            p("kind", "string", "primary or secondary", true),
            p(
                "found",
                "array",
                "primary: addresses; secondary: meters (secondary_address, id, manufacturer, \
                 version, medium)",
                true,
            ),
            p(
                "collisions",
                "array",
                "Addresses or masks where more than one meter answered and the search could \
                 narrow no further",
                true,
            ),
            p(
                "probes",
                "number",
                "How many telegrams the scan sent (each silent one cost a response timeout)",
                true,
            ),
            p(
                "truncated",
                "boolean",
                "True when the probe budget ran out",
                false,
            ),
        ],
    )
});

pub static ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "mbus_ack",
        "The answer to mbus_write, mbus_set_primary_address, mbus_application_reset or \
         mbus_ping: acknowledged (E5) or not (silence, which is how a meter refuses)",
        vec![
            p("operation", "string", "The action this answers: mbus_write, mbus_set_primary_address, mbus_application_reset or mbus_ping", true),
            p("target", "object", "address or secondary_address", true),
            p(
                "acknowledged",
                "boolean",
                "True when the meter answered E5",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "mbus_error",
        "An operation failed: no answer (timeout), several meters answered (collision), a \
         broken telegram, or an answer that is not what was asked",
        vec![
            p(
                "operation",
                "string",
                "The action that failed, e.g. mbus_read or mbus_write",
                true,
            ),
            p("target", "object", "address or secondary_address", false),
            p(
                "kind",
                "string",
                "timeout, collision, bad_frame, unexpected_reply or not_selected",
                true,
            ),
            p(
                "message",
                "string",
                "A sentence saying what was sent and what came back, or that nothing did",
                true,
            ),
        ],
    )
});

/// A meter to talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Primary(u8),
    Secondary([u8; 8]),
}

impl Target {
    pub fn json(&self) -> Value {
        match self {
            Target::Primary(a) => json!({"address": a}),
            Target::Secondary(m) => json!({"secondary_address": frame::mask_to_hex(m)}),
        }
    }
}

/// One operation the transport carries out.
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    Read {
        target: Target,
        max_telegrams: usize,
    },
    ScanPrimary {
        from: u8,
        to: u8,
    },
    ScanSecondary {
        mask: [u8; 8],
    },
    Write {
        target: Target,
        /// The encoded records (CI 0x51 user data).
        data: Vec<u8>,
        operation: &'static str,
    },
    Reset {
        target: Target,
        subcode: Option<u8>,
    },
    Ping {
        address: u8,
    },
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::Read { .. } => "mbus_read",
            Operation::ScanPrimary { .. } => "mbus_scan_primary",
            Operation::ScanSecondary { .. } => "mbus_scan_secondary",
            Operation::Write { operation, .. } => operation,
            Operation::Reset { .. } => "mbus_application_reset",
            Operation::Ping { .. } => "mbus_ping",
        }
    }
}

fn primary(v: &Value, key: &str) -> Result<u8> {
    let n = v
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("{key} is a primary address, 0-250"))?;
    ensure!(
        n <= frame::addr::MAX_PRIMARY as u64,
        "{key} {n} is above 250"
    );
    Ok(n as u8)
}

fn target(v: &Value) -> Result<Target> {
    match (
        v.get("address").filter(|x| !x.is_null()),
        v.get("secondary_address").filter(|x| !x.is_null()),
    ) {
        (Some(_), Some(_)) => bail!("give address or secondary_address, not both"),
        (Some(_), None) => Ok(Target::Primary(primary(v, "address")?)),
        (None, Some(s)) => {
            let s = s
                .as_str()
                .context("secondary_address is a 16-character string")?;
            Ok(Target::Secondary(frame::mask_from_hex(s)?))
        }
        (None, None) => bail!("name the meter: address (0-250) or secondary_address"),
    }
}

fn opt_u64(v: &Value, key: &str, default: u64, max: u64) -> Result<u64> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(x) => {
            let n = x
                .as_u64()
                .with_context(|| format!("{key} is a whole number"))?;
            ensure!(n <= max, "{key} is {n}, above {max}");
            Ok(n)
        }
    }
}

/// The operation an action asks for; `None` for disconnect.
pub fn operation_from_action(v: &Value) -> Result<Option<Operation>> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .context("an action needs a type")?;
    Ok(Some(match t {
        "disconnect" => return Ok(None),
        "mbus_read" => {
            let max = opt_u64(
                v,
                "max_telegrams",
                records::MAX_TELEGRAMS as u64,
                records::MAX_TELEGRAMS as u64,
            )?;
            ensure!(max >= 1, "max_telegrams is at least 1");
            Operation::Read {
                target: target(v)?,
                max_telegrams: max as usize,
            }
        }
        "mbus_scan_primary" => {
            let from = opt_u64(v, "from", 0, 250)? as u8;
            let to = opt_u64(v, "to", 250, 250)? as u8;
            ensure!(from <= to, "from {from} is after to {to}");
            Operation::ScanPrimary { from, to }
        }
        "mbus_scan_secondary" => {
            let mask = v
                .get("mask")
                .and_then(Value::as_str)
                .unwrap_or("FFFFFFFFFFFFFFFF");
            Operation::ScanSecondary {
                mask: frame::mask_from_hex(mask)?,
            }
        }
        "mbus_write" => {
            let list = v
                .get("records")
                .and_then(Value::as_array)
                .context("mbus_write needs records, a list")?;
            ensure!(!list.is_empty(), "mbus_write needs at least one record");
            ensure!(
                list.len() <= records::MAX_RECORDS_PER_TELEGRAM,
                "at most {} records in one write",
                records::MAX_RECORDS_PER_TELEGRAM
            );
            let mut data = Vec::new();
            for (i, r) in list.iter().enumerate() {
                data.extend(records::encode_record(r).with_context(|| format!("record {i}"))?);
            }
            ensure!(
                data.len() <= frame::MAX_USER_DATA,
                "the records take {} bytes; one telegram carries {}",
                data.len(),
                frame::MAX_USER_DATA
            );
            Operation::Write {
                target: target(v)?,
                data,
                operation: "mbus_write",
            }
        }
        "mbus_set_primary_address" => {
            let new = primary(v, "new_address")?;
            let data = records::encode_record(
                &json!({"quantity": "bus_address", "value": new, "encoding": "int8"}),
            )?;
            Operation::Write {
                target: target(v)?,
                data,
                operation: "mbus_set_primary_address",
            }
        }
        "mbus_application_reset" => Operation::Reset {
            target: target(v)?,
            subcode: match v.get("subcode") {
                None | Some(Value::Null) => None,
                Some(_) => Some(opt_u64(v, "subcode", 0, 255)? as u8),
            },
        },
        "mbus_ping" => Operation::Ping {
            address: primary(v, "address")?,
        },
        other => bail!(
            "unknown action {other:?}; actions are mbus_read, mbus_scan_primary, \
             mbus_scan_secondary, mbus_write, mbus_set_primary_address, \
             mbus_application_reset, mbus_ping, disconnect"
        ),
    }))
}

impl Protocol for MbusClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "M-Bus"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MBUS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "m-bus",
            "mbus",
            "meter-bus",
            "meter bus",
            "en 13757",
            "m-bus master",
            "meter reading",
        ]
    }
    fn description(&self) -> &'static str {
        "M-Bus (Meter-Bus, EN 13757) master through an M-Bus/IP gateway: scans for meters by primary and secondary address, reads and decodes their records, and writes what the LLM decides"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the M-Bus gateway at 192.168.1.60:10001, find every meter with a secondary-address search and read each one"
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            DATA_EVENT.clone(),
            SCAN_EVENT.clone(),
            ACK_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "response_timeout_ms".into(),
            type_hint: "number".into(),
            description: format!(
                "How long a meter has to answer one telegram, in milliseconds \
                 ({MIN_RESPONSE_TIMEOUT_MS}-{MAX_RESPONSE_TIMEOUT_MS}). Every silent address in \
                 a scan costs this long"
            ),
            required: false,
            example: json!(500),
            default: Some(json!(DEFAULT_RESPONSE_TIMEOUT_MS)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written M-Bus master over TCP sharing the slave's codec \
                 (src/server/mbus/frame.rs, records.rs): SND_NKE, REQ_UD2 with the FCB toggled \
                 across a multi-telegram readout (DIF 0x1F) and one retry with the same FCB on \
                 a timeout, SND_UD for data, primary address and application reset, \
                 secondary selection, a primary scan and the libmbus-style secondary wildcard \
                 search that narrows by digit on collision; a collision is more than one answer \
                 or a garbled one. One operation on the wire at a time; the model is asked from \
                 a separate task",
            )
            .llm_control(
                "Which meters to look for and read, what to write, primary-address \
                 assignment and application resets; every answer arrives as a decoded event",
            )
            .e2e_testing(
                "tests/client/mbus: two independent slaves — pyMbusSlave (Python, its own \
                 encoder; TCP mode) and Addiva Elektronik's mbus-device (C, on Addiva's libmbus \
                 fork; served behind a pty-to-TCP bridge as an M-Bus/IP gateway would) replaying \
                 libmbus's captured telegrams from real meters, whose decoded records are \
                 checked against libmbus's own normalised XML. Against NetGet's own slave as a \
                 regression only: scans, multi-telegram FCB readouts, writes, collisions, \
                 bounds and the follow-up depth",
            )
            .notes(
                "Experimental: the independent slaves are a sample program and a test device, \
                 not production meters; neither multi-telegram readouts nor the secondary \
                 wildcard search with collisions are exercised against anything but NetGet's \
                 own slave, and its pair job had not run in CI when it landed. TCP only (no \
                 serial port), wired M-Bus only (no wireless EN 13757-4), CI 0x72 variable data \
                 only (fixed data CI 0x73 is reported, not decoded), no encryption.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "M-Bus",
            "remote_addr": "127.0.0.1:10001",
            "startup_params": {"response_timeout_ms": 1000},
            "instruction": "Find every meter with a secondary-address search, then read each one and report its energy and volume"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "mbus_connected", "handler": {"type": "static", "actions": [{"type": "mbus_read", "address": 1}]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python",
                "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='mbus_connected': a=[{'type':'mbus_scan_secondary'}]\nelif t=='mbus_scan_result': a=[{'type':'mbus_read','secondary_address':m['secondary_address']} for m in e['found']]\nprint(json.dumps({'actions':a}))"}
        }]);
        StartupExamples::new(llm, scripted, static_example)
    }
}

impl Client for MbusClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let timeout = match ctx.startup_params.as_ref() {
                Some(p) => p
                    .get_optional_u64("response_timeout_ms")?
                    .unwrap_or(DEFAULT_RESPONSE_TIMEOUT_MS),
                None => DEFAULT_RESPONSE_TIMEOUT_MS,
            };
            ensure!(
                (MIN_RESPONSE_TIMEOUT_MS..=MAX_RESPONSE_TIMEOUT_MS).contains(&timeout),
                "response_timeout_ms must be between {MIN_RESPONSE_TIMEOUT_MS} and \
                 {MAX_RESPONSE_TIMEOUT_MS}, got {timeout}"
            );
            super::MbusClient::connect(
                ctx.remote_addr,
                std::time::Duration::from_millis(timeout),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match operation_from_action(&action)? {
            None => Ok(ClientActionResult::Disconnect),
            Some(_) => Ok(ClientActionResult::Custom {
                name: OPERATION_RESULT.to_string(),
                data: action,
            }),
        }
    }
}

/// Validate an action into its operation, for the transport.
pub fn require_operation(v: &Value) -> Result<Operation> {
    operation_from_action(v)?.ok_or_else(|| anyhow!("disconnect is not an operation"))
}
