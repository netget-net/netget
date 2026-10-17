//! What the model can do on a D-Bus connection: call methods and read the replies, own names,
//! subscribe to signals, emit signals, and answer the calls other clients make to it.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::dbus::actions::{
    action, error_action, p, return_action, signal_action, VALUES_HELP,
};
use crate::server::dbus::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How long a call waits for its reply, by default (libdbus's own default is 25 s).
pub const DEFAULT_TIMEOUT_MS: u64 = 25_000;
pub const DEFAULT_BUS: bool = true;

#[derive(Default)]
pub struct DbusClientProtocol;
impl DbusClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn call_action() -> ActionDefinition {
    action(
        "dbus_call",
        "Call a method; the answer arrives as dbus_reply or dbus_error_reply.",
        vec![
            p("destination", "string", "Bus name to call, e.g. org.freedesktop.DBus or a service's name (omit on a peer-to-peer connection)", false),
            p("path", "string", "Object path, e.g. /org/freedesktop/DBus", true),
            p("interface", "string", "Interface, e.g. org.freedesktop.DBus", false),
            p("member", "string", "Method name, e.g. ListNames (letters, digits, underscore)", true),
            p("signature", "string", "Signature of args (empty for none)", false),
            p("args", "array", VALUES_HELP, false),
        ],
        json!({"type":"dbus_call","destination":"org.freedesktop.DBus","path":"/org/freedesktop/DBus","interface":"org.freedesktop.DBus","member":"ListNames"}),
    )
}

fn request_name_action() -> ActionDefinition {
    action(
        "dbus_request_name",
        "Own a well-known bus name, so other clients can call you; the bus's answer arrives as dbus_reply (1 primary owner, 3 exists, 4 already owner).",
        vec![p("name", "string", "The name, e.g. net.netget.Demo", true)],
        json!({"type":"dbus_request_name","name":"net.netget.Demo"}),
    )
}

fn add_match_action() -> ActionDefinition {
    action(
        "dbus_add_match",
        "Subscribe to signals matching a rule; each arrives as dbus_signal.",
        vec![p(
            "rule",
            "string",
            "Match rule, e.g. type='signal',interface='net.example.Thing'",
            true,
        )],
        json!({"type":"dbus_add_match","rule":"type='signal',interface='org.freedesktop.DBus'"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection; the bus releases every name it owned.",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        call_action(),
        request_name_action(),
        add_match_action(),
        signal_action(),
        disconnect_action(),
    ]
}

fn answering_actions() -> Vec<ActionDefinition> {
    let mut all = vec![return_action(), error_action()];
    all.extend(actions());
    all
}

fn ev(
    id: &str,
    description: &str,
    example: Value,
    parameters: Vec<crate::llm::actions::Parameter>,
    answering: bool,
) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(parameters)
        .with_actions(if answering {
            answering_actions()
        } else {
            actions()
        })
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "dbus_connected",
        "Authenticated, and registered with the bus unless the connection is peer-to-peer.",
        call_action().example.clone(),
        vec![
            p(
                "unique_name",
                "string",
                "The unique name the bus assigned, e.g. :1.42",
                false,
            ),
            p(
                "server_guid",
                "string",
                "The server's GUID from authentication",
                true,
            ),
            p("mechanism", "string", "EXTERNAL or ANONYMOUS", true),
        ],
        false,
    )
});

pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "dbus_reply",
        "A method you called returned.",
        call_action().example.clone(),
        vec![
            p(
                "destination",
                "string",
                "The bus name the call was addressed to",
                false,
            ),
            p(
                "member",
                "string",
                "The method that was called, e.g. Greet",
                true,
            ),
            p(
                "signature",
                "string",
                "D-Bus type signature of values, e.g. \"as\"",
                true,
            ),
            p(
                "values",
                "array",
                "The returned values as JSON; variants as {signature, value}",
                true,
            ),
        ],
        false,
    )
});

pub static ERROR_REPLY_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        ev(
        "dbus_error_reply",
        "A method you called failed, or got no reply in time (org.freedesktop.DBus.Error.NoReply).",
        call_action().example.clone(),
        vec![
            p("destination", "string", "The bus name the call was addressed to", false),
            p("member", "string", "The method that was called, e.g. Greet", true),
            p("name", "string", "The D-Bus error name", true),
            p("message", "string", "The human-readable text the error carried", false),
        ],
        false,
    )
    });

pub static SIGNAL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "dbus_signal",
        "A signal arrived (one you subscribed to with dbus_add_match, or one addressed to you).",
        call_action().example.clone(),
        vec![
            p("sender", "string", "The emitter's unique name", false),
            p(
                "path",
                "string",
                "Object path, e.g. /org/freedesktop/DBus",
                true,
            ),
            p(
                "interface",
                "string",
                "Interface name in dotted form, e.g. org.freedesktop.DBus",
                true,
            ),
            p(
                "member",
                "string",
                "Signal name, e.g. Changed (letters, digits, underscore)",
                true,
            ),
            p(
                "signature",
                "string",
                "D-Bus type signature of args, e.g. \"si\"",
                true,
            ),
            p("args", "array", "The arguments as JSON", true),
        ],
        false,
    )
});

pub static INCOMING_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "dbus_method_call",
        "Another client called a method on you. Answer with dbus_return or dbus_error unless no_reply_expected.",
        return_action().example.clone(),
        vec![
            p("sender", "string", "The caller's unique name", false),
            p("destination", "string", "The name it addressed", false),
            p("path", "string", "Object path, e.g. /org/freedesktop/DBus", true),
            p("interface", "string", "Interface, when named", false),
            p("member", "string", "Method name, e.g. ListNames (letters, digits, underscore)", true),
            p("signature", "string", "D-Bus type signature of args, e.g. \"si\"", true),
            p("args", "array", "The arguments as JSON", true),
            p("no_reply_expected", "boolean", "The caller wants no answer", true),
        ],
        true,
    )
});

pub fn check(v: &Value) -> Result<()> {
    let s = |k: &str| {
        v[k].as_str()
            .with_context(|| format!("{k} must be a string"))
    };
    match v["type"].as_str().unwrap_or_default() {
        "dbus_call" => {
            ensure!(
                wire::valid_object_path(s("path")?),
                "path is not a D-Bus object path"
            );
            ensure!(
                wire::valid_member(s("member")?),
                "member is not a D-Bus member name"
            );
            if let Some(i) = v.get("interface").and_then(Value::as_str) {
                ensure!(
                    wire::valid_interface(i),
                    "interface is not a D-Bus interface name"
                );
            }
            if let Some(d) = v.get("destination").and_then(Value::as_str) {
                ensure!(
                    wire::valid_bus_name(d),
                    "destination is not a D-Bus bus name"
                );
            }
            let args = match v.get("args") {
                None | Some(Value::Null) => vec![],
                Some(Value::Array(a)) => a.clone(),
                Some(_) => bail!("args must be an array"),
            };
            wire::marshal(v["signature"].as_str().unwrap_or_default(), &args)?;
        }
        "dbus_request_name" => {
            let n = s("name")?;
            ensure!(
                wire::valid_bus_name(n) && !n.starts_with(':'),
                "{n:?} is not a well-known bus name"
            );
        }
        "dbus_add_match" => {
            s("rule")?;
        }
        "dbus_emit_signal" | "dbus_return" | "dbus_error" => {
            crate::server::dbus::actions::answer_message(Some(&placeholder_call()), v, None)?;
        }
        other => bail!("Unknown D-Bus client action {other:?}"),
    }
    Ok(())
}

/// A call to validate answer actions against (the shape matters, not the values).
pub fn placeholder_call() -> wire::Message {
    let mut m = wire::Message::call("/", None, "Check");
    m.serial = 1;
    m
}

impl Protocol for DbusClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "D-Bus"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>D-Bus"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dbus", "d-bus", "session bus", "system bus", "freedesktop"]
    }
    fn description(&self) -> &'static str {
        "D-Bus client: joins a message bus (or a peer), calls methods, owns names and answers calls made to them, emits and receives signals"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![return_action(), error_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            REPLY_EVENT.clone(),
            ERROR_REPLY_EVENT.clone(),
            SIGNAL_EVENT.clone(),
            INCOMING_CALL_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "socket_path".into(),
                type_hint: "string".into(),
                description: "Connect to this Unix socket (a bus address's unix:path=...) instead of remote_addr".into(),
                required: false,
                example: json!("/run/user/1000/bus"),
                default: None,
            },
            ParameterDefinition {
                name: "bus".into(),
                type_hint: "boolean".into(),
                description: "Register with a message bus (Hello) after authenticating; false for a peer-to-peer connection".into(),
                required: false,
                example: json!(false),
                default: Some(json!(DEFAULT_BUS)),
            },
            ParameterDefinition {
                name: "timeout_ms".into(),
                type_hint: "number".into(),
                description: "Milliseconds a call waits for its reply (100-120000)".into(),
                required: false,
                example: json!(5000),
                default: Some(json!(DEFAULT_TIMEOUT_MS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The D-Bus server's wire codec (src/server/dbus/wire.rs) over a Unix socket or TCP: SASL EXTERNAL (as the process's uid) then ANONYMOUS, Hello, calls matched to replies by serial with a timeout, incoming calls answered by the model and failed closed when it does not, signals both ways")
            .llm_control("Which methods to call with which arguments, which names to own and signals to subscribe to, and the answer to every call made to it")
            .e2e_testing("tests/client/dbus: dbus-daemon (the reference bus) with a python dbus-next service, dbus-send calling the names NetGet owns, and dbus-monitor; NetGet's own D-Bus server for the peer-to-peer path")
            .notes("No Unix file descriptors and no DBUS_COOKIE_SHA1, so a TCP bus must allow ANONYMOUS. At most 64 calls await replies at once. Messages are bounded at 1 MiB and nesting at 32 like the server. Model turns follow from one another at most eight deep.")
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the session bus at /run/user/1000/bus, list the bus names, and own net.netget.Demo answering Ping with pong"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"dbus","remote_addr":"","startup_params":{"socket_path":"/run/user/1000/bus"},
            "instruction":"List the names on the bus, then own net.netget.Demo and answer Ping with pong"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"dbus_connected","handler":{"type":"static","actions":[{"type":"dbus_request_name","name":"net.netget.Demo"}]}},
            {"event_pattern":"dbus_method_call","handler":{"type":"static","actions":[{"type":"dbus_return","signature":"s","values":["pong"]}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'dbus_return','signature':'s','values':['pong']}] if e['member']=='Ping' else [{'type':'dbus_error','name':'org.freedesktop.DBus.Error.UnknownMethod','message':e['member']}]}))"});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for DbusClientProtocol {
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
