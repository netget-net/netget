//! M-Bus slave actions and events: what the model decides for the meters behind the gateway.
//!
//! Rust owns the bus: framing and checksums, primary and secondary addressing, selection and
//! wildcard search (with every matching meter answering, so a master sees the collision), the
//! FCB repeat rule, splitting a readout into telegrams, the access number. The model owns the
//! meters' readings and whether a write or an application reset is accepted.
//!
//! Three events, all raised in `src/server/mbus/mod.rs`:
//!
//! - `mbus_request_data` — a master asked a meter for its data (REQ_UD2); answer with records
//! - `mbus_write_data` — a master sent a meter data records (SND_UD, CI 0x51); accept or ignore
//! - `mbus_application_reset` — a master reset a meter's application (SND_UD, CI 0x50)
use super::frame::{self, SecondaryAddress};
use super::records;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How long a master may stay silent before its connection is closed.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;
/// The most meters one gateway emulates.
pub const MAX_METERS: usize = 250;

/// `Custom` result names shared with `mod.rs`.
pub const RESULT_RESPOND: &str = "mbus_respond_data";
pub const RESULT_ACK: &str = "mbus_acknowledge";
pub const RESULT_SILENT: &str = "mbus_no_response";

#[derive(Clone, Default)]
pub struct MbusProtocol;

impl MbusProtocol {
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

fn respond_example() -> Value {
    json!({
        "type": "mbus_respond_data",
        "records": [
            {"quantity": "energy", "unit": "kWh", "value": 12345.678},
            {"quantity": "volume", "unit": "m3", "value": 456.789, "encoding": "bcd"},
            {"quantity": "flow_temperature", "unit": "°C", "value": 65.4},
            {"quantity": "energy", "unit": "kWh", "value": 11000, "storage": 1},
            {"quantity": "date", "value": "2026-09-30", "storage": 1}
        ]
    })
}

fn respond_action() -> ActionDefinition {
    ActionDefinition {
        name: "mbus_respond_data".into(),
        description: format!(
            "Answer the meter's REQ_UD2 with a RSP_UD carrying these data records. Each record \
             is {{\"quantity\", \"unit\", \"value\"}} with optional storage (0 = current, 1 and \
             up = historic values such as the last billing date), tariff, subunit, function \
             (instantaneous, maximum, minimum, error), encoding (int — the default, the \
             smallest integer that fits — bcd, real, or int8/16/24/32/48/64, bcd2/4/6/8/12, \
             real32) and resolution (the meter's step as a power of ten in the given unit, \
             e.g. 0.01). Quantities: {}. Units: energy Wh/kWh/MWh or J/kJ/MJ/GJ, volume \
             m3 or l, mass kg/t, power W/kW or J/h/GJ/h, volume_flow m3/h, l/h, m3/min, m3/s, \
             mass_flow kg/h, temperatures °C (temperature_difference K), pressure bar, \
             voltage V, current A; on_time, operating_time and the durations take s, min, h \
             or d; date is \"YYYY-MM-DD\", datetime \"YYYY-MM-DDTHH:MM\". NetGet chooses the \
             VIF and its power of ten, encodes the value exactly, and splits more records \
             than fit one telegram into several (the master fetches the rest). status: \
             optional flags power_low, permanent_error, temporary_error, application_busy, \
             application_error",
            records::quantity_names()
        ),
        parameters: vec![
            p(
                "records",
                "array",
                "The data records, e.g. [{\"quantity\": \"energy\", \"unit\": \"kWh\", \
                 \"value\": 12.5}]; [] answers with the meter's identity and no readings",
                true,
            ),
            p(
                "status",
                "array",
                "Status flags for the telegram header, e.g. [\"power_low\"]",
                false,
            ),
        ],
        example: respond_example(),
        log_template: Some(
            LogTemplate::new()
                .with_info("M-Bus RSP_UD queued")
                .with_debug("M-Bus respond: {json(.)}"),
        ),
    }
}

fn ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "mbus_acknowledge".into(),
        description: "Accept the master's write or application reset: the meter answers with \
                      the single character E5. A write that sets bus_address changes the \
                      meter's primary address once acknowledged"
            .into(),
        parameters: vec![],
        example: json!({"type": "mbus_acknowledge"}),
        log_template: Some(LogTemplate::new().with_info("M-Bus E5 queued")),
    }
}

fn silent_action() -> ActionDefinition {
    ActionDefinition {
        name: "mbus_no_response".into(),
        description: "Do not answer. M-Bus has no negative acknowledgement: a meter refuses a \
                      write, or declines a request, by staying silent, and the master times out"
            .into(),
        parameters: vec![p("reason", "string", "Why, for the log", false)],
        example: json!({"type": "mbus_no_response", "reason": "write protected"}),
        log_template: Some(LogTemplate::new().with_info("M-Bus meter stays silent by decision")),
    }
}

pub static RESPOND_ACTION: LazyLock<ActionDefinition> = LazyLock::new(respond_action);
pub static ACK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(ack_action);
pub static SILENT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(silent_action);

fn meter_param() -> Parameter {
    p(
        "meter",
        "object",
        "The meter addressed: primary_address, secondary_address (16 hex characters), id, \
         manufacturer, version, medium",
        true,
    )
}

fn addressed_param() -> Parameter {
    p(
        "addressed_by",
        "string",
        "primary (its primary address), secondary (selected by secondary address and \
         addressed at 253) or broadcast (254/255)",
        true,
    )
}

pub static REQUEST_DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mbus_request_data",
        "A master asked this meter for its data (REQ_UD2). Answer with mbus_respond_data and \
         the meter's current readings, or stay silent with mbus_no_response",
        respond_example(),
    )
    .with_parameters(vec![
        meter_param(),
        addressed_param(),
        p(
            "fcb",
            "boolean",
            "The request's frame count bit (a repeated FCB is answered by NetGet with the \
             previous telegram and never reaches you)",
            false,
        ),
    ])
    .with_actions(vec![RESPOND_ACTION.clone(), SILENT_ACTION.clone()])
    .with_alternative_example(json!({"type": "mbus_no_response", "reason": "meter offline"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("M-Bus REQ_UD2 for meter {meter.secondary_address} ({addressed_by})")
            .with_debug("M-Bus request data: {json(.)}"),
    )
});

pub static WRITE_DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mbus_write_data",
        "A master sent this meter data records (SND_UD, CI 0x51): a setting, a new primary \
         address (bus_address), a reset of a register. Accept with mbus_acknowledge or refuse \
         by staying silent (mbus_no_response)",
        json!({"type": "mbus_acknowledge"}),
    )
    .with_parameters(vec![
        meter_param(),
        addressed_param(),
        p(
            "records",
            "array",
            "The decoded records: quantity, unit, value, storage, tariff, encoding",
            true,
        ),
        p(
            "global_readout",
            "boolean",
            "True when the master asked for a global readout (DIF 0x7F)",
            false,
        ),
    ])
    .with_actions(vec![ACK_ACTION.clone(), SILENT_ACTION.clone()])
    .with_alternative_example(json!({"type": "mbus_no_response", "reason": "read-only meter"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("M-Bus SND_UD data for meter {meter.secondary_address}")
            .with_debug("M-Bus write data: {json(.)}"),
    )
});

pub static APPLICATION_RESET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mbus_application_reset",
        "A master reset this meter's application (SND_UD, CI 0x50), optionally with a subcode \
         naming what to reset. Accept with mbus_acknowledge (any readout in progress is \
         discarded) or stay silent",
        json!({"type": "mbus_acknowledge"}),
    )
    .with_parameters(vec![
        meter_param(),
        addressed_param(),
        p(
            "subcode",
            "number",
            "The reset subcode byte, when the master sent one",
            false,
        ),
    ])
    .with_actions(vec![ACK_ACTION.clone(), SILENT_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("M-Bus application reset for meter {meter.secondary_address}")
            .with_debug("M-Bus application reset: {json(.)}"),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        REQUEST_DATA_EVENT.clone(),
        WRITE_DATA_EVENT.clone(),
        APPLICATION_RESET_EVENT.clone(),
    ]
}

/// One meter as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterConfig {
    pub primary_address: u8,
    pub address: SecondaryAddress,
}

impl MeterConfig {
    pub fn json(&self) -> Value {
        json!({
            "primary_address": self.primary_address,
            "secondary_address": self.address.to_hex(),
            "id": frame::id_hex(&self.address.id),
            "manufacturer": frame::manufacturer_letters(self.address.manufacturer),
            "version": self.address.version,
            "medium": frame::medium_name(self.address.medium),
        })
    }
}

pub fn default_meters() -> Value {
    json!([{
        "primary_address": 1,
        "id": "00000001",
        "manufacturer": "NGT",
        "version": 1,
        "medium": "heat"
    }])
}

/// The meters from the `meters` startup parameter.
pub fn meters_from_json(v: &Value) -> Result<Vec<MeterConfig>> {
    let list = v.as_array().context("meters is a list of meter objects")?;
    ensure!(!list.is_empty(), "a gateway needs at least one meter");
    ensure!(list.len() <= MAX_METERS, "at most {MAX_METERS} meters");
    list.iter()
        .enumerate()
        .map(|(i, m)| meter_from_json(m).with_context(|| format!("meter {i}")))
        .collect()
}

fn meter_from_json(m: &Value) -> Result<MeterConfig> {
    let primary = m
        .get("primary_address")
        .and_then(Value::as_u64)
        .context("primary_address is a number 0-250")?;
    ensure!(
        primary <= frame::addr::MAX_PRIMARY as u64,
        "primary_address {primary} is above 250"
    );
    let id = match m.get("id") {
        Some(Value::String(s)) => {
            ensure!(
                !s.is_empty() && s.len() <= 8 && s.chars().all(|c| c.is_ascii_digit()),
                "id {s:?} is up to 8 decimal digits"
            );
            s.parse::<u32>()?
        }
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .context("id is up to 8 decimal digits")?,
        _ => anyhow::bail!("id is the meter's identification number, up to 8 digits"),
    };
    let manufacturer = frame::manufacturer_code(
        m.get("manufacturer")
            .and_then(Value::as_str)
            .unwrap_or("NGT"),
    )?;
    let version = m.get("version").and_then(Value::as_u64).unwrap_or(1);
    ensure!(version <= 255, "version is a byte, 0-255");
    let medium = match m.get("medium") {
        None | Some(Value::Null) => 0x00,
        Some(Value::String(s)) => frame::medium_from_name(s)?,
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .context("medium code is a byte")?,
        Some(other) => anyhow::bail!("medium is a name such as \"water\", not {other}"),
    };
    Ok(MeterConfig {
        primary_address: primary as u8,
        address: SecondaryAddress {
            id: frame::id_to_bcd(id)?,
            manufacturer,
            version: version as u8,
            medium,
        },
    })
}

/// The records and status byte of a `mbus_respond_data` action, encoded.
pub fn respond_from_json(v: &Value) -> Result<(Vec<Vec<u8>>, u8)> {
    let list = v
        .get("records")
        .and_then(Value::as_array)
        .context("mbus_respond_data needs \"records\", a list ([] for none)")?;
    ensure!(
        list.len() <= records::MAX_RECORDS_PER_READOUT,
        "{} records; at most {} make one readout",
        list.len(),
        records::MAX_RECORDS_PER_READOUT
    );
    let encoded = list
        .iter()
        .enumerate()
        .map(|(i, r)| records::encode_record(r).with_context(|| format!("record {i}")))
        .collect::<Result<Vec<_>>>()?;
    let status = records::status_from_json(v.get("status"))?;
    Ok((encoded, status))
}

impl Protocol for MbusProtocol {
    fn protocol_name(&self) -> &'static str {
        "M-Bus"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MBUS"
    }
    fn description(&self) -> &'static str {
        "M-Bus (Meter-Bus, EN 13757-2/-3) gateway: wired utility meters behind an M-Bus/IP gateway, whose readings the LLM supplies as structured records"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an M-Bus/IP gateway on port 10001 with a heat meter at primary address 1 (id 12345678, manufacturer KAM) reporting 1234.5 kWh and 56.7 m3"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "m-bus",
            "mbus",
            "meter-bus",
            "meter bus",
            "en 13757",
            "m-bus gateway",
            "m-bus slave",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // A failed readout is answered: RSP_UD with the meter's identity, no records and
            // the status byte's application bits (busy when the model is overloaded, error
            // otherwise), so a master learns the meter is there and has nothing to report
            // rather than concluding it is gone. A failed write or reset is NOT acknowledged:
            // E5 would accept a change nobody approved.
            .answers_on_failure()
            .request_only(
                "An M-Bus meter only answers its master; a slave never transmits unprompted \
                 (EN 13757-2)",
            )
            .max_inbound_bytes(frame::MAX_FRAME_LEN)
            .implementation(
                "Hand-written EN 13757-2/-3 (no crate: the Rust M-Bus crates decode wireless \
                 telegrams or a subset of records and none encodes): single character, short, \
                 control and long frames with checksum and stop byte; SND_NKE, REQ_UD2, \
                 REQ_UD1, SND_UD (data send, application reset, secondary selection, baud \
                 rate); primary addresses 0-250, 253 after selection, 254 and 255 broadcast; \
                 secondary selection with nibble wildcards, where every matching meter \
                 answers so a master sees the collision; the FCB repeat rule and multi-telegram \
                 readouts (DIF 0x1F) per master connection; variable data responses (CI 0x72) \
                 with DIF/DIFE/VIF/VIFE records in integer, BCD (signed), real and date codings \
                 for energy, volume, mass, power, flows, temperatures, pressure, durations, \
                 voltage and current",
            )
            .llm_control(
                "Each meter's readings for every fresh REQ_UD2 (structured records the Rust \
                 side encodes), and whether a SND_UD write or an application reset is accepted",
            )
            .e2e_testing(
                "tests/server/mbus: libmbus 0.10.3 (rSCADA, C) — mbus-tcp-scan finds the meters \
                 by primary address, mbus-tcp-scan-secondary finds them by wildcard search, \
                 mbus-tcp-request-data prints the model's readings as XML (primary and \
                 secondary addressing, and the collision report for a mask matching two \
                 meters), mbus-tcp-request-data-multi-reply reads a three-telegram readout with \
                 FCB toggling, mbus-tcp-application-reset and mbus-tcp-raw-send are \
                 acknowledged or refused by the model; pyMeterBus 0.8.5 (Python) decodes the \
                 same telegrams with its own record decoder, checks a repeated FCB, and reads \
                 every coding. In-process: bounds, FCB, and fail-closed paths from a raw \
                 socket, and a mocked model through the binary",
            )
            .notes(
                "Experimental: two independent masters (libmbus and pyMeterBus) read it, but \
                 no fuzz corpus has been run at length, there is no pcap oracle (tshark has no \
                 wired M-Bus dissector), and its pair job had not run in CI when it landed. \
                 Wired M-Bus over TCP only — no serial port, no wireless M-Bus (EN 13757-4), no \
                 encryption or authentication (the signature field is 0), no fixed-data \
                 (CI 0x73) responses, no extended selection by fabrication number, mode-2 \
                 selection (CI 0x56) refused. FCB state and selection belong to each master \
                 connection: a new TCP connection starts as if the master had sent SND_NKE. \
                 Meters at the same address all answer, back to back. A failed readout answers \
                 with error status and no readings (decision=fail_closed_llm_error); a failed \
                 write or reset is not acknowledged.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "meters".into(),
                type_hint: "array".into(),
                description: format!(
                    "The meters behind the gateway (at most {MAX_METERS}): objects with \
                     primary_address (0-250), id (up to 8 digits), manufacturer (three \
                     letters, the FLAG code), version (0-255) and medium (heat, water, \
                     electricity, gas, warm_water, cold_water, …). Meters may share a primary \
                     address or match one selection mask; they then answer together, as \
                     colliding meters on a real bus do. Default: one heat meter at address 1, \
                     id 00000001, manufacturer NGT"
                ),
                required: false,
                example: json!([
                    {"primary_address": 1, "id": "12345678", "manufacturer": "KAM", "version": 1, "medium": "heat"},
                    {"primary_address": 2, "id": "87654321", "manufacturer": "ELS", "version": 2, "medium": "water"}
                ]),
                default: None,
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: format!(
                    "Seconds a master connection may stay silent before it is closed \
                     (1-{MAX_IDLE_TIMEOUT_SECS})"
                ),
                required: false,
                example: json!(600),
                default: Some(json!(DEFAULT_IDLE_TIMEOUT_SECS)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![respond_action(), ack_action(), silent_action()]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let meters = json!([
            {"primary_address": 1, "id": "12345678", "manufacturer": "KAM", "version": 1, "medium": "heat"}
        ]);
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 10001,
                "base_stack": "mbus",
                "startup_params": {"meters": meters},
                "instruction": "You are a Kamstrup heat meter. Report the energy counter in \
                                kWh (start at 1234.5 and add a little each reading), the volume \
                                in m3, flow and return temperatures, and last month's energy as \
                                storage 1. Refuse every write."
            }),
            json!({
                "type": "open_server",
                "port": 10001,
                "base_stack": "mbus",
                "startup_params": {"meters": meters},
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\nif t=='mbus_request_data':\n  a=[{'type':'mbus_respond_data','records':[{'quantity':'energy','unit':'kWh','value':1234.5},{'quantity':'volume','unit':'m3','value':56.7}]}]\nelse:\n  a=[{'type':'mbus_no_response','reason':'read-only'}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 10001,
                "base_stack": "mbus",
                "startup_params": {"meters": meters},
                "event_handlers": [
                    {"event_pattern": "mbus_request_data", "handler": {"type": "static", "actions": [
                        {"type": "mbus_respond_data", "records": [
                            {"quantity": "energy", "unit": "kWh", "value": 1234.5},
                            {"quantity": "volume", "unit": "m3", "value": 56.7}
                        ]}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": [
                        {"type": "mbus_no_response", "reason": "read-only"}
                    ]}}
                ]
            }),
        )
    }
}

impl Server for MbusProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let meters = match params.map(|p| p.get_optional_array("meters")).transpose()? {
                Some(Some(list)) => meters_from_json(&Value::Array(list.clone()))?,
                _ => meters_from_json(&default_meters())?,
            };
            let idle = params
                .map(|p| p.get_optional_u64("idle_timeout_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
            ensure!(
                (1..=MAX_IDLE_TIMEOUT_SECS).contains(&idle),
                "idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}, got {idle}"
            );
            super::MbusServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                meters,
                std::time::Duration::from_secs(idle),
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        let custom = |name: &str| ActionResult::Custom {
            name: name.to_string(),
            data: action.clone(),
        };
        match kind {
            "mbus_respond_data" => {
                respond_from_json(&action)?;
                Ok(custom(RESULT_RESPOND))
            }
            "mbus_acknowledge" => Ok(custom(RESULT_ACK)),
            "mbus_no_response" => Ok(custom(RESULT_SILENT)),
            other => Err(anyhow!(
                "Unknown M-Bus action '{other}'. Valid actions: mbus_respond_data, \
                 mbus_acknowledge, mbus_no_response"
            )),
        }
    }
}
