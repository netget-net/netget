use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::rpki_rtr::actions::{action, parameter};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RpkiRtrClientProtocol;
impl RpkiRtrClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn reset_action() -> ActionDefinition {
    action("rpki_rtr_reset_query", "Ask the cache for its complete VRP set (Reset Query). Rust already sends one on connect and after Cache Reset.", vec![], json!({"type":"rpki_rtr_reset_query"}))
}
fn serial_action() -> ActionDefinition {
    action("rpki_rtr_serial_query", "Ask the cache for changes since the last synchronized serial (Serial Query). Rust also sends one at every refresh interval and on Serial Notify.", vec![], json!({"type":"rpki_rtr_serial_query"}))
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the RTR session",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![reset_action(), serial_action(), disconnect_action()]
}

pub static SYNCHRONIZED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rpki_rtr_synchronized",
        "A Reset or Serial exchange completed with End of Data",
        json!({"type":"rpki_rtr_serial_query"}),
    )
    .with_parameters(vec![
        parameter(
            "kind",
            "string",
            "reset (complete set) or incremental (changes since the previous serial)",
            true,
        ),
        parameter("session_id", "number", "The cache's session id", true),
        parameter("serial", "number", "Serial the router now holds", true),
        parameter(
            "announced",
            "number",
            "Announcements in this exchange",
            true,
        ),
        parameter("withdrawn", "number", "Withdrawals in this exchange", true),
        parameter(
            "records",
            "array",
            "Up to 256 of this exchange's records: {prefix, max_length, asn, announcement}",
            true,
        ),
        parameter(
            "truncated",
            "boolean",
            "true when the exchange had more records than listed",
            true,
        ),
        parameter(
            "intervals",
            "object",
            "refresh, retry and expire seconds in force",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static CACHE_RESET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rpki_rtr_cache_reset",
        "The cache cannot serve the router's serial; Rust has already sent a Reset Query",
        json!({"type":"rpki_rtr_reset_query"}),
    )
    .with_parameters(vec![parameter(
        "previous_serial",
        "number",
        "Serial the router held, if any",
        false,
    )])
    .with_actions(actions())
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rpki_rtr_error_report",
        "The cache sent an Error Report. Every code except no_data_available ends the session.",
        json!({"type":"disconnect"}),
    )
    .with_parameters(vec![
        parameter("code", "number", "RFC 8210 error code", true),
        parameter(
            "name",
            "string",
            "Error name such as no_data_available or unsupported_protocol_version",
            true,
        ),
        parameter("diagnostic", "string", "The cache's diagnostic text", true),
    ])
    .with_actions(actions())
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

impl Protocol for RpkiRtrClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RPKI-RTR"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RPKI-RTR"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rpki", "rtr", "rpki-rtr", "rfc8210", "router", "vrp"]
    }
    fn description(&self) -> &'static str {
        "RPKI-to-Router client (router role) that synchronizes VRPs from a cache"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SYNCHRONIZED_EVENT.clone(),
            CACHE_RESET_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("version", "number", "RTR version to speak: 1 (RFC 8210) or 0 (RFC 6810); fixed for the session", json!(1), Some(json!(1))),
            startup("refresh_interval_secs", "number", "Polling interval until a version-1 End of Data supplies the cache's own (1..=86400)", json!(3600), Some(json!(crate::server::rpki_rtr::codec::DEFAULT_REFRESH_SECONDS))),
            startup("exchange_timeout_secs", "number", "Seconds (1..=600) one query may take from sending to End of Data", json!(120), Some(json!(super::EXCHANGE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(323)
            .implementation("Native RFC 8210/6810 router: shared bounded codec, a registered reader task, Rust-owned Reset/Serial queries, refresh timer, Serial Notify and Cache Reset handling")
            .llm_control("Reacting to each synchronization, error report and cache reset; extra Reset/Serial queries; disconnecting")
            .e2e_testing("tests/client/rpki_rtr: StayRTR 0.6.4 (independent Go cache) with reset, notify-driven incremental and version-0 sessions; NetGet cache pair; malformed and out-of-order cache PDUs")
            .notes("No VRP table and no route-origin validation: events report counts and up to 256 records per exchange. Plain TCP; no SSH/TLS. Router Key PDUs are counted and ignored; ASPA is not supported. No reconnect: the session ends on a fatal Error Report or disconnect. 1,000,000 PDUs per exchange.")
            .max_inbound_bytes(crate::server::rpki_rtr::codec::MAX_PDU_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the RPKI cache at 192.0.2.10:323 and report how many VRPs it serves"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rpki_rtr","remote_addr":"127.0.0.1:323","instruction":"Report the VRP count after each synchronization"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"rpki_rtr_error_report","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Client for RpkiRtrClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some(name @ ("rpki_rtr_reset_query" | "rpki_rtr_serial_query")) => {
                Ok(ClientActionResult::Custom {
                    name: name.into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown RPKI-RTR client action"),
        }
    }
}
