use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::thrift::actions::{action, parameter, EXAMPLE_IDL};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ThriftClientProtocol;
impl ThriftClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn call() -> ActionDefinition {
    action(
        "thrift_call",
        "Call a function of the IDL's service with arguments by name; Rust encodes them by their declared types and reports the result, declared exception or application error",
        vec![
            parameter("method", "string", "The function name, e.g. get_user", true),
            parameter("args", "object", "Arguments by name as JSON (structs as objects, enums by label), e.g. {\"id\": 7}", false),
        ],
        json!({"type": "thrift_call", "method": "get_user", "args": {"id": 7}}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "thrift_connected",
        "Connected; the service's functions are listed",
        call().example.clone(),
    )
    .with_parameters(vec![
        parameter("service", "string", "The service being called", true),
        parameter(
            "functions",
            "array",
            "Its functions: [{name, args, returns, oneway}]",
            true,
        ),
    ])
    .with_actions(vec![call(), disconnect()])
});
pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "thrift_result",
        "The server's answer to a call (none for oneway functions)",
        disconnect().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The function called", true),
        parameter(
            "result",
            "any",
            "The decoded return value (null for void)",
            false,
        ),
        parameter(
            "exception",
            "object",
            "A declared exception: {name, value}",
            false,
        ),
        parameter(
            "application_error",
            "object",
            "A TApplicationException: {type, message}",
            false,
        ),
    ])
    .with_actions(vec![call(), disconnect()])
});

impl Protocol for ThriftClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Thrift"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Thrift"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["thrift", "apache thrift", "rpc client", "idl"]
    }
    fn description(&self) -> &'static str {
        "Apache Thrift RPC client for a service declared in IDL, framed or unframed, binary or compact"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        vec![call(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p = |name: &str,
                 kind: &str,
                 description: &str,
                 required: bool,
                 example: Value,
                 default: Option<Value>| ParameterDefinition {
            name: name.into(),
            type_hint: kind.into(),
            description: description.into(),
            required,
            example,
            default,
        };
        vec![
            p(
                "idl",
                "string",
                "The Thrift IDL declaring the service (no include), up to 256 KiB",
                true,
                json!(EXAMPLE_IDL),
                None,
            ),
            p(
                "service",
                "string",
                "Which service in the IDL to call; the last one when omitted",
                false,
                json!("Users"),
                None,
            ),
            p(
                "protocol",
                "string",
                "binary or compact",
                false,
                json!("compact"),
                Some(json!(super::DEFAULT_PROTOCOL)),
            ),
            p(
                "transport",
                "string",
                "framed or buffered (unframed)",
                false,
                json!("buffered"),
                Some(json!(super::DEFAULT_TRANSPORT)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's IDL parser and codecs as a client")
            .llm_control("Which functions to call with which arguments")
            .e2e_testing("tests/client/thrift: a thriftpy2 0.7.1 server (independent) answers calls in framed binary and buffered compact, including a declared exception and an unknown method")
            .notes("One outstanding call at a time; no multiplexed protocol.")
            .max_inbound_bytes(crate::server::thrift::codec::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Call get_user(7) on the Thrift service at 127.0.0.1:9090 using this IDL"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"thrift","remote_addr":"127.0.0.1:9090","instruction":"Look up user 7","startup_params":{"idl": EXAMPLE_IDL}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"thrift_connected","handler":{"type":"static","actions":[call().example]}},
            {"event_pattern":"thrift_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for ThriftClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 4 * 1024 * 1024, 200_000, 64),
            "action exceeds the Thrift bounds"
        );
        match v["type"].as_str() {
            Some("thrift_call") => {
                ensure!(
                    v["method"]
                        .as_str()
                        .is_some_and(|m| !m.is_empty() && m.len() <= 256),
                    "method names a function"
                );
                if let Some(a) = v.get("args").filter(|a| !a.is_null()) {
                    ensure!(a.is_object(), "args is an object of arguments by name");
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Thrift client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
