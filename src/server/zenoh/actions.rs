use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZenohProtocol;
impl ZenohProtocol {
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
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("Zenoh {name}"))),
    }
}

fn payload_params() -> Vec<Parameter> {
    vec![
        parameter(
            "payload",
            "string",
            "The value as text, or hex when payload_encoding is hex",
            true,
        ),
        parameter("payload_encoding", "string", "utf8 (default) or hex", false),
        parameter(
            "encoding",
            "string",
            "Zenoh encoding (media type), e.g. text/plain or application/json",
            false,
        ),
    ]
}

pub fn put() -> ActionDefinition {
    let mut p = vec![parameter(
        "key",
        "string",
        "Key expression to publish on, e.g. demo/temp",
        true,
    )];
    p.extend(payload_params());
    action(
        "zenoh_put",
        "Publish a value on a key: every matching subscriber receives it",
        p,
        json!({"type": "zenoh_put", "key": "demo/temp", "payload": "21.5"}),
    )
}
pub fn delete() -> ActionDefinition {
    action(
        "zenoh_delete",
        "Publish a deletion on a key",
        vec![parameter(
            "key",
            "string",
            "Key expression to delete, e.g. demo/temp",
            true,
        )],
        json!({"type": "zenoh_delete", "key": "demo/temp"}),
    )
}
pub fn get() -> ActionDefinition {
    action(
        "zenoh_get",
        "Query every matching queryable; the replies arrive as zenoh_get_result (10 s timeout, 256 replies)",
        vec![parameter("selector", "string", "Key expression with optional ?parameters, e.g. demo/**?unit=c", true)],
        json!({"type": "zenoh_get", "selector": "demo/**"}),
    )
}
pub fn reply() -> ActionDefinition {
    let mut p = vec![parameter(
        "key",
        "string",
        "The reply's key (default: the query's key expression); must match the query",
        false,
    )];
    p.extend(payload_params());
    action(
        "zenoh_reply",
        "Answer the query with a value (several replies are allowed; none is an empty answer)",
        p,
        json!({"type": "zenoh_reply", "payload": "21.5"}),
    )
}
pub fn reply_error() -> ActionDefinition {
    action(
        "zenoh_reply_error",
        "Answer the query with an error the querier receives as such",
        vec![
            parameter(
                "payload",
                "string",
                "The error text the querier receives, e.g. sensor offline",
                true,
            ),
            parameter("payload_encoding", "string", "utf8 (default) or hex", false),
        ],
        json!({"type": "zenoh_reply_error", "payload": "sensor offline"}),
    )
}

fn sample_params() -> Vec<Parameter> {
    vec![
        parameter("key", "string", "The key the value was published on", true),
        parameter(
            "kind",
            "string",
            "put when a value was published, delete when the key was deleted",
            true,
        ),
        parameter(
            "payload",
            "string",
            "The value as text, or hex per payload_encoding",
            true,
        ),
        parameter(
            "payload_encoding",
            "string",
            "utf8 when the payload is text, hex when it is not UTF-8",
            true,
        ),
        parameter(
            "encoding",
            "string",
            "The Zenoh encoding the publisher declared",
            true,
        ),
    ]
}

pub static SAMPLE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("zenoh_sample", "A value (or deletion) arrived on a subscribed key expression; react with puts, deletes or gets, or nothing", json!({"type": "zenoh_put", "key": "demo/ack", "payload": "seen"}))
        .with_parameters(sample_params())
        .with_actions(vec![put(), delete(), get()])
});
pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zenoh_query",
        "A query reached a declared queryable; answer with replies or an error",
        reply().example.clone(),
    )
    .with_parameters(vec![
        parameter("selector", "string", "The whole selector", true),
        parameter("key", "string", "The queried key expression", true),
        parameter(
            "parameters",
            "string",
            "The selector's parameters after ?",
            true,
        ),
        parameter("payload", "string", "A value sent with the query", false),
        parameter(
            "payload_encoding",
            "string",
            "utf8 when the payload is text, hex when it is not UTF-8",
            false,
        ),
    ])
    .with_actions(vec![reply(), reply_error(), put(), delete()])
});
pub static GET_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zenoh_get_result",
        "The replies to a zenoh_get",
        json!({"type": "zenoh_put", "key": "demo/summary", "payload": "done"}),
    )
    .with_parameters(vec![
        parameter("selector", "string", "The selector queried", true),
        parameter(
            "replies",
            "array",
            "[{key, kind, payload, payload_encoding, encoding} | {error}]",
            true,
        ),
    ])
    .with_actions(vec![put(), delete(), get()])
});

pub fn key_list(name: &str, description: &str, example: Value) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "array".into(),
        description: description.into(),
        required: false,
        example,
        default: None,
    }
}

impl Protocol for ZenohProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zenoh"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Zenoh"
    }
    fn description(&self) -> &'static str {
        "Zenoh router or peer listening on TCP: receives publications on subscribed keys and answers queries; the handler publishes, deletes and queries"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "zenoh",
            "zenoh router",
            "pub/sub",
            "queryable",
            "eclipse zenoh",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![put(), delete(), get(), reply(), reply_error()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SAMPLE_EVENT.clone(),
            QUERY_EVENT.clone(),
            GET_RESULT_EVENT.clone(),
        ]
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
                description: "router (routes between the clients that connect) or peer".into(),
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
            .well_known_port(7447)
            .implementation("The zenoh 1.10.1 runtime (TCP transport only, multicast scouting off) in router or peer mode; Rust declares the subscribers and queryables and runs the handler's actions; links are polled for the connection list")
            .llm_control("Reactions to every publication and the answer to every query: puts, deletes, gets, replies and reply errors")
            .e2e_testing("tests/server/zenoh: zenoh-pico 1.10.1 (independent C implementation) clients publish, subscribe, query and serve a queryable through NetGet")
            .notes("No TLS, QUIC, UDP or shared memory transports; no storage (persist with memory or SQLite). Gets time out after 10 s with at most 256 replies; chains of handler actions stop at depth 4; 64 queries in flight.")
            .request_only("Zenoh traffic is not per connection: the handler publishes, deletes and queries in answer to samples and queries")
            .answers_on_failure()
            .max_inbound_bytes(super::node::MAX_PAYLOAD)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Zenoh router on port 7447 that answers queries on demo/** with the current time"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"zenoh","port":7447,"instruction":"Answer queries on demo/q/** with 42","startup_params":{"queryable":["demo/q/**"]}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zenoh_query","handler":{"type":"static","actions":[{"type":"zenoh_reply","payload":"42"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"zenoh_query","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'zenoh_reply','payload':'answer for '+e['key']}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Server for ZenohProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        super::node::validate(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
