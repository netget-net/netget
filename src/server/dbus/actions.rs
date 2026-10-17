//! What the model sees of a D-Bus method call and how it answers. `dbus_return` and
//! `dbus_error` answer the call being handled — the protocol instance carries it — and
//! `dbus_emit_signal` may accompany either, or be injected into a connection at any time.
use super::wire::{self, Message};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;

/// Serials for messages produced outside a connection's own loop (injected signals). The
/// connection's loop counts up from 1; this range cannot reach it in any real session.
static INJECTED_SERIAL: AtomicU32 = AtomicU32::new(0x8000_0000);

pub fn next_injected_serial() -> u32 {
    INJECTED_SERIAL
        .fetch_add(1, Ordering::Relaxed)
        .max(0x8000_0000)
}

#[derive(Default, Clone)]
pub struct DbusProtocol {
    /// The call being answered, when this instance answers one.
    call: Option<Message>,
    /// The connection's serial counter, so every message the answer produces has its own.
    serials: Option<Arc<AtomicU32>>,
}

impl DbusProtocol {
    pub fn new() -> Self {
        Self::default()
    }

    /// The instance that answers `call` on a connection whose next serial is `serials`.
    pub fn for_call(call: Message, serials: Arc<AtomicU32>) -> Self {
        Self {
            call: Some(call),
            serials: Some(serials),
        }
    }
}

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
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
    let info = match name {
        "dbus_return" => "-> D-Bus return {signature}".to_string(),
        "dbus_error" => "-> D-Bus error {name}: {preview(message,80)}".to_string(),
        "dbus_emit_signal" => "-> D-Bus signal {interface}.{member} on {path}".to_string(),
        "dbus_call" => "-> D-Bus call {destination} {interface}.{member}".to_string(),
        _ => format!("-> D-Bus {}", name.trim_start_matches("dbus_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub const VALUES_HELP: &str = "Values in signature order as JSON: numbers, strings, booleans; arrays for a/(...); objects for a{...}; a variant as {\"signature\":\"s\",\"value\":\"x\"} or a plain value";

pub fn return_action() -> ActionDefinition {
    action(
        "dbus_return",
        "Answer the method call with a return value.",
        vec![
            p(
                "signature",
                "string",
                "D-Bus signature of the values, e.g. \"s\", \"ai\", \"a{sv}\"; empty for none",
                false,
            ),
            p("values", "array", VALUES_HELP, false),
        ],
        json!({"type":"dbus_return","signature":"s","values":["pong"]}),
    )
}

pub fn error_action() -> ActionDefinition {
    action(
        "dbus_error",
        "Refuse the method call with a D-Bus error.",
        vec![
            p(
                "name",
                "string",
                "Error name, e.g. org.freedesktop.DBus.Error.InvalidArgs or one of your own",
                true,
            ),
            p("message", "string", "Human-readable message", false),
        ],
        json!({"type":"dbus_error","name":"org.freedesktop.DBus.Error.AccessDenied","message":"not allowed"}),
    )
}

pub fn signal_action() -> ActionDefinition {
    action(
        "dbus_emit_signal",
        "Emit a signal to the peer.",
        vec![
            p("path", "string", "Object path the signal comes from", true),
            p(
                "interface",
                "string",
                "Interface name in dotted form, e.g. net.netget.Demo",
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
                "Signature of the values (empty for none)",
                false,
            ),
            p("values", "array", VALUES_HELP, false),
        ],
        json!({"type":"dbus_emit_signal","path":"/net/netget/Demo","interface":"net.netget.Demo","member":"Changed","signature":"s","values":["ready"]}),
    )
}

pub static METHOD_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dbus_method_call",
        "A peer called a method. Answer with dbus_return or dbus_error (unless no_reply_expected); dbus_emit_signal may accompany either.",
        json!({"type":"dbus_return","signature":"s","values":["pong"]}),
    )
    .with_parameters(vec![
        p("path", "string", "Object path the call was made on, e.g. /net/netget/Demo", true),
        p("interface", "string", "Interface, when the caller named one", false),
        p("member", "string", "Method name, e.g. ListNames (letters, digits, underscore)", true),
        p("destination", "string", "Bus name the call was addressed to", false),
        p("sender", "string", "The caller's unique name", false),
        p("signature", "string", "D-Bus type signature of args, e.g. \"si\"", true),
        p("args", "array", "The arguments as JSON, in signature order; variants as {signature, value}", true),
        p("no_reply_expected", "boolean", "The caller wants no answer", true),
    ])
    .with_actions(vec![return_action(), error_action(), signal_action()])
});

pub static SIGNAL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dbus_signal_received",
        "A peer emitted a signal. Nothing has to be answered.",
        json!({"type":"dbus_emit_signal","path":"/net/netget/Demo","interface":"net.netget.Demo","member":"Seen","signature":"","values":[]}),
    )
    .with_parameters(vec![
        p("path", "string", "Object path, e.g. /org/freedesktop/DBus", true),
        p("interface", "string", "Interface name in dotted form, e.g. org.freedesktop.DBus", true),
        p("member", "string", "Signal name, e.g. Changed (letters, digits, underscore)", true),
        p("sender", "string", "The emitter's unique name", false),
        p("signature", "string", "D-Bus type signature of args, e.g. \"si\"", true),
        p("args", "array", "The arguments as JSON", true),
    ])
    .with_actions(vec![signal_action()])
});

/// The message an answer action builds: a reply to `call`, or a signal.
pub fn answer_message(
    call: Option<&Message>,
    action: &Value,
    sender: Option<&str>,
) -> Result<Message> {
    let kind = action["type"].as_str().unwrap_or_default();
    let values = |key: &str| -> Result<Vec<Value>> {
        match action.get(key) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(a)) => Ok(a.clone()),
            Some(other) => bail!("{key} must be an array, not {other}"),
        }
    };
    let signature = action["signature"].as_str().unwrap_or_default();
    let mut m = match kind {
        "dbus_return" => {
            let call =
                call.context("dbus_return answers a method call; there is none to answer here")?;
            Message::reply_to(call, signature, values("values")?)
        }
        "dbus_error" => {
            let call =
                call.context("dbus_error answers a method call; there is none to answer here")?;
            let name = action["name"].as_str().context("dbus_error needs a name")?;
            ensure!(
                wire::valid_interface(name),
                "{name:?} is not a D-Bus error name (two or more dotted elements)"
            );
            Message::error_to(call, name, action["message"].as_str().unwrap_or(name))
        }
        "dbus_emit_signal" => {
            let text = |k: &str| {
                action[k]
                    .as_str()
                    .with_context(|| format!("dbus_emit_signal needs {k}"))
            };
            let (path, interface, member) = (text("path")?, text("interface")?, text("member")?);
            ensure!(
                wire::valid_object_path(path),
                "{path:?} is not an object path"
            );
            Message {
                kind: wire::SIGNAL,
                path: Some(path.into()),
                interface: Some(interface.into()),
                member: Some(member.into()),
                destination: call.and_then(|c| c.sender.clone()),
                sender: sender.map(Into::into),
                signature: signature.into(),
                body: values("values")?,
                ..Default::default()
            }
        }
        other => bail!("{other:?} is not a D-Bus answer action"),
    };
    if m.sender.is_none() {
        m.sender = sender.map(Into::into);
    }
    // Encode once now so a malformed answer is refused here, as the model's error.
    m.serial = 1;
    m.encode()?;
    Ok(m)
}

impl Protocol for DbusProtocol {
    fn protocol_name(&self) -> &'static str {
        "D-Bus"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>D-Bus"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dbus", "d-bus", "message bus", "freedesktop"]
    }
    fn description(&self) -> &'static str {
        "D-Bus server: answers method calls from D-Bus clients (dbus-send, gdbus, any binding) over TCP or a Unix socket, acting as a small message bus"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![signal_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![return_action(), error_action(), signal_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![METHOD_CALL_EVENT.clone(), SIGNAL_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "socket_path".into(),
                type_hint: "string".into(),
                description: "Also listen on this Unix socket (unix:path=...), where EXTERNAL authentication checks the peer's uid".into(),
                required: false,
                example: json!("/tmp/netget-dbus.sock"),
                default: None,
            },
            ParameterDefinition {
                name: "allow_anonymous".into(),
                type_hint: "boolean".into(),
                description: "Accept SASL ANONYMOUS (the only mechanism a TCP peer can complete here)".into(),
                required: false,
                example: json!(false),
                default: Some(json!(super::DEFAULT_ALLOW_ANONYMOUS)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds an authenticated connection may stay silent (1-86400)".into(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-rolled D-Bus 1 wire protocol (src/server/dbus/wire.rs): SASL EXTERNAL (checked against SO_PEERCRED on the Unix socket) and ANONYMOUS, both byte orders in, little-endian out, signature-driven JSON marshalling. Acts as a small bus: Hello, RequestName, ReleaseName, GetId, ListNames, NameHasOwner, GetNameOwner, AddMatch/RemoveMatch and org.freedesktop.DBus.Peer are answered in Rust; every other call goes to the model")
            .llm_control("The answer to every method call (a return value with its signature, or a D-Bus error) and the signals sent back")
            .e2e_testing("tests/server/dbus: dbus-send (libdbus, peer-to-peer over TCP), gdbus (GLib, as a bus client over the Unix socket) and python dbus-next (asyncio, receiving a signal); raw tests for the size and variant-depth bounds and the fail-closed error")
            .notes("FAILS CLOSED: a call expecting a reply that the model does not answer gets org.freedesktop.DBus.Error.Failed (LimitsExceeded when the backend is overloaded), never silence. Messages over 1 MiB and values nested past 32 (variants count; the specification allows 64, but NetGet's event pipeline holds 64 JSON levels) close the connection. No Unix file descriptors, no DBUS_COOKIE_SHA1, no routing between peers: each connection talks to NetGet only.")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Run a D-Bus server where net.netget.Demo.Ping answers pong and everything else is UnknownMethod"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"dbus","port":0,
            "instruction":"Answer net.netget.Demo.Ping with the string pong; refuse anything else with org.freedesktop.DBus.Error.UnknownMethod"});
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"dbus_method_call","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'dbus_return','signature':'s','values':['pong']}] if e['member']=='Ping' else [{'type':'dbus_error','name':'org.freedesktop.DBus.Error.UnknownMethod','message':e['member']}]}))"}}]);
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"dbus_method_call","handler":{"type":"static","actions":[{"type":"dbus_return","signature":"s","values":["pong"]}]}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for DbusProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        if self.call.is_none()
            && matches!(
                action["type"].as_str(),
                Some("dbus_return") | Some("dbus_error")
            )
        {
            // The registry's instance answers no call: check the answer's shape and send
            // nothing. Injection offers only dbus_emit_signal (the async set), so nothing
            // reaches a peer this way.
            let mut placeholder = Message::call("/", None, "Check");
            placeholder.serial = 1;
            answer_message(Some(&placeholder), &action, None)?;
            return Ok(ActionResult::NoAction);
        }
        let mut m = answer_message(
            self.call.as_ref(),
            &action,
            self.call.as_ref().and_then(|c| c.destination.as_deref()),
        )?;
        m.serial = match &self.serials {
            Some(counter) => counter.fetch_add(1, Ordering::Relaxed),
            None => next_injected_serial(),
        };
        if m.kind != wire::SIGNAL {
            if let Some(call) = &self.call {
                if !call.expects_reply() {
                    return Ok(ActionResult::NoAction);
                }
            }
        }
        Ok(ActionResult::Output(m.encode()?))
    }
}
