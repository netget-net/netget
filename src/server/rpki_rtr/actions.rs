use super::codec::{self, Record};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RpkiRtrProtocol;
impl RpkiRtrProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let log_template = match name {
        "rpki_rtr_response" => LogTemplate::new().with_info("-> RPKI-RTR response serial={serial} records={records_len} cache_reset={cache_reset} no_data={no_data}"),
        "rpki_rtr_serial_notify" => LogTemplate::new().with_info("-> RPKI-RTR Serial Notify serial={serial}"),
        _ => LogTemplate::new().with_info(format!("-> RPKI-RTR {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

const RECORDS_HELP: &str = "VRPs [{prefix: CIDR like 192.0.2.0/24 or 2001:db8::/32 with no host bits, max_length, asn, announcement: true|false (default true; false withdraws, serial-query answers only)}]";

fn response_action() -> ActionDefinition {
    action(
        "rpki_rtr_response",
        "Answer the router's pending Reset Query or Serial Query. Rust frames Cache Response, one Prefix PDU per record and End of Data with this server's session id and timers. Supply serial+records, or cache_reset=true (serial query only: the router must reset), or no_data=true (Error Report 2: no data yet).",
        vec![
            parameter("serial", "number", "Serial (u32) of the data this answer brings the router to; for a serial query it must be the router's serial or newer (RFC 1982)", false),
            parameter("records", "array", RECORDS_HELP, false),
            parameter("cache_reset", "boolean", "true to answer a serial query with Cache Reset (the router's serial is too old)", false),
            parameter("no_data", "boolean", "true to answer with Error Report 'No Data Available'", false),
        ],
        json!({"type":"rpki_rtr_response","serial":42,"records":[{"prefix":"192.0.2.0/24","max_length":24,"asn":64496}]}),
    )
}

fn notify_action() -> ActionDefinition {
    action(
        "rpki_rtr_serial_notify",
        "Tell this router new data exists (Serial Notify). The router answers with a Serial Query, which raises rpki_rtr_serial_query.",
        vec![parameter("serial", "number", "The cache's new serial (u32)", true)],
        json!({"type":"rpki_rtr_serial_notify","serial":43}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close this router's RTR session",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn query_parameters() -> Vec<Parameter> {
    vec![
        parameter(
            "session_id",
            "number",
            "This cache's session id, which every answer carries",
            true,
        ),
        parameter(
            "version",
            "number",
            "RTR protocol version the router speaks: 0 (RFC 6810) or 1 (RFC 8210)",
            true,
        ),
    ]
}

pub static RESET_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rpki_rtr_reset_query",
        "A router asked for the complete VRP set. Answer with every record it should hold, all announcements.",
        response_action().example.clone(),
    )
    .with_parameters(query_parameters())
    .with_actions(vec![response_action()])
});

pub static SERIAL_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = query_parameters();
    params.push(parameter(
        "router_serial",
        "number",
        "Serial the router already holds; answer with the changes since it",
        true,
    ));
    EventType::new(
        "rpki_rtr_serial_query",
        "A router holding router_serial asked for changes. Answer with announcements and withdrawals since that serial, cache_reset if you cannot, or the same serial with no records if nothing changed.",
        json!({"type":"rpki_rtr_response","serial":43,"records":[{"prefix":"198.51.100.0/24","max_length":24,"asn":64497},{"prefix":"192.0.2.0/24","max_length":24,"asn":64496,"announcement":false}]}),
    )
    .with_parameters(params)
    .with_actions(vec![response_action()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for RpkiRtrProtocol {
    fn protocol_name(&self) -> &'static str {
        "RPKI-RTR"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RPKI-RTR"
    }
    fn description(&self) -> &'static str {
        "RPKI-to-Router cache (RFC 8210/6810) serving handler-chosen VRPs to routers"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rpki",
            "rtr",
            "rpki-rtr",
            "rfc8210",
            "rfc6810",
            "vrp",
            "route origin validation",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![notify_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RESET_QUERY_EVENT.clone(), SERIAL_QUERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("session_id", "number", "Cache session id (0..=65535); omitted, a random one per start", json!(4242), None),
            startup("refresh_interval_secs", "number", "Refresh interval sent to version-1 routers (1..=86400)", json!(3600), Some(json!(codec::DEFAULT_REFRESH_SECONDS))),
            startup("retry_interval_secs", "number", "Retry interval sent to version-1 routers (1..=7200)", json!(600), Some(json!(codec::DEFAULT_RETRY_SECONDS))),
            startup("expire_interval_secs", "number", "Expire interval sent to version-1 routers (600..=172800, above refresh and retry)", json!(7200), Some(json!(codec::DEFAULT_EXPIRE_SECONDS))),
            startup("idle_timeout_secs", "number", "Seconds (1..=172800) a router may stay silent between queries before the cache closes the session; a parked handler does not count", json!(7200), Some(json!(super::IDLE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(323))
            .well_known_port(323)
            .implementation("Native RFC 8210 (version 1) and RFC 6810 (version 0) PDU codec over Tokio TCP; one bounded PDU read before allocation; Rust owns session id, framing, timers and version negotiation")
            .llm_control("The VRP set for each Reset Query, the delta (or Cache Reset) for each Serial Query, and when to send Serial Notify")
            .e2e_testing("tests/server/rpki_rtr: StayRTR 0.6.4 rtrdump (Go) and RTRlib 0.8.0 rtrclient (C), both independent routers, plus codec and lifecycle tests")
            .notes("No RPKI repository, validation engine or VRP store: the handler supplies data (persist with memory or SQLite). Plain TCP only (no SSH/TLS transports). IPv4/IPv6 prefix PDUs; Router Key and ASPA PDUs are not served. A router speaking a version above 1 is told Unsupported Protocol Version. 4096 records per answer, 4096-byte PDUs, 256 connections.")
            .answers_on_failure()
            .max_inbound_bytes(codec::MAX_PDU_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RPKI-RTR cache on port 323 telling routers AS64496 originates 192.0.2.0/24"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"rpki_rtr","port":323,"instruction":"Serve VRP 192.0.2.0/24 maxlen 24 from AS64496 at serial 1"});
        let answer = json!([{"type":"rpki_rtr_response","serial":1,"records":[{"prefix":"192.0.2.0/24","max_length":24,"asn":64496}]}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"rpki_rtr_reset_query","handler":{"type":"static","actions":answer}},
            {"event_pattern":"rpki_rtr_serial_query","handler":{"type":"static","actions":[{"type":"rpki_rtr_response","serial":1,"records":[]}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\nfull=i['event_type_id']=='rpki_rtr_reset_query'\nprint(json.dumps({'actions':[{'type':'rpki_rtr_response','serial':1,'records':[{'prefix':'192.0.2.0/24','max_length':24,'asn':64496}] if full else []}]}))"}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Server for RpkiRtrProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("rpki_rtr_response") => {
                let v = codec::owned_json(v)?;
                Response::from_action(&v)?;
                Ok(ActionResult::Custom {
                    name: "rpki_rtr_response".into(),
                    data: v,
                })
            }
            Some("rpki_rtr_serial_notify") => {
                serial(&v)?;
                Ok(ActionResult::Custom {
                    name: "rpki_rtr_serial_notify".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ActionResult::CloseConnection),
            _ => bail!("Unknown RPKI-RTR server action"),
        }
    }
}

pub fn serial(v: &Value) -> Result<u32> {
    let n = v["serial"].as_u64().context("serial must be a number")?;
    u32::try_from(n).context("serial must fit in 32 bits")
}

/// A validated handler answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Data { serial: u32, records: Vec<Record> },
    CacheReset,
    NoData,
}

impl Response {
    pub fn from_action(v: &Value) -> Result<Self> {
        let obj = v.as_object().context("response must be an object")?;
        for key in obj.keys() {
            ensure!(
                matches!(
                    key.as_str(),
                    "type" | "serial" | "records" | "cache_reset" | "no_data"
                ),
                "unknown response field '{key}'"
            );
        }
        let flag = |k: &str| -> Result<bool> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(b)) => Ok(*b),
                _ => bail!("{k} must be boolean"),
            }
        };
        let (reset, none) = (flag("cache_reset")?, flag("no_data")?);
        let has_data = obj.contains_key("serial") || obj.contains_key("records");
        ensure!(
            u8::from(reset) + u8::from(none) + u8::from(has_data) == 1,
            "supply exactly one of serial+records, cache_reset or no_data"
        );
        if reset {
            return Ok(Self::CacheReset);
        }
        if none {
            return Ok(Self::NoData);
        }
        let serial = serial(v)?;
        let records: Vec<Record> = match obj.get("records") {
            None | Some(Value::Null) => Vec::new(),
            Some(r) => serde_json::from_value(r.clone())
                .context("records must be [{prefix,max_length,asn,announcement}]")?,
        };
        codec::Batch {
            serial,
            records: records.clone(),
        }
        .validate(false)?;
        Ok(Self::Data { serial, records })
    }
}
