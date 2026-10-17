use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::zenoh::actions::{
    action, delete, get, key_list, parameter, put, reply, reply_error,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZenohClientProtocol;
impl ZenohClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the Zenoh session",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zenoh_connected",
        "The session is open; publish, query, or wait for samples and queries",
        put().example.clone(),
    )
    .with_parameters(vec![
        parameter("zid", "string", "This session's Zenoh id", true),
        parameter(
            "mode",
            "string",
            "The session mode this client opened: client (through a router) or peer",
            true,
        ),
        parameter(
            "links",
            "array",
            "The session's links: [{src, dst, zid}]",
            true,
        ),
    ])
    .with_actions(vec![put(), delete(), get(), disconnect()])
});

impl Protocol for ZenohClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zenoh"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Zenoh"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["zenoh", "zenoh client", "zenoh peer"]
    }
    fn description(&self) -> &'static str {
        "Zenoh client or peer connecting over TCP: publishes, deletes and queries, and reacts to samples and queries on declared keys"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        vec![put(), delete(), get(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply(), reply_error()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        let mut out = vec![CONNECTED_EVENT.clone()];
        out.extend(crate::server::zenoh::events().into_iter().cloned());
        out
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            key_list(
                "subscribe",
                "Key expressions to subscribe to; each value raises zenoh_sample",
                json!(["demo/**"]),
            ),
            key_list(
                "queryable",
                "Key expressions to answer queries on; each query raises zenoh_query",
                json!(["demo/q/**"]),
            ),
            ParameterDefinition {
                name: "mode".into(),
                type_hint: "string".into(),
                description: "client (to a router) or peer".into(),
                required: false,
                example: json!("peer"),
                default: Some(json!(super::DEFAULT_MODE)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The zenoh 1.10.1 runtime (TCP only, multicast scouting off) in client or peer mode connecting to remote_addr")
            .llm_control("What to publish, delete and query, and how to react to samples and answer queries")
            .e2e_testing("tests/client/zenoh: zenoh-pico 1.10.1 (independent C implementation) peers listening: one subscribes to what NetGet publishes, one serves a queryable NetGet queries, one publishes to NetGet's subscriber")
            .notes("No TLS, QUIC or UDP transports. Gets time out after 10 s with at most 256 replies; chains stop at depth 4.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Zenoh router at 127.0.0.1:7447 and publish 21.5 on demo/temp"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"zenoh","remote_addr":"127.0.0.1:7447","instruction":"Publish 21.5 on demo/temp"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zenoh_connected","handler":{"type":"static","actions":[put().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"zenoh_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'zenoh_get','selector':'demo/**'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Client for ZenohClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some(
                "zenoh_put" | "zenoh_delete" | "zenoh_get" | "zenoh_reply" | "zenoh_reply_error",
            ) => crate::server::zenoh::node::validate(&v)?,
            _ => bail!("Unknown Zenoh client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
