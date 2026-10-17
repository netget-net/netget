//! What the model can ask of an X server, and what it hears back. Every action becomes one
//! `x11_result` or one `x11_error`; X events arrive as `x11_event` for windows created watching
//! them. Window ids are written the way `xwininfo` and `xprop` print them, `0x200001`.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How long one action may wait for the X server's replies, by default.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// Property types the model can write, and how each is encoded.
pub const PROPERTY_TYPES: &[&str] = &[
    "UTF8_STRING",
    "STRING",
    "CARDINAL",
    "INTEGER",
    "ATOM",
    "WINDOW",
];

#[derive(Default)]
pub struct X11ClientProtocol;
impl X11ClientProtocol {
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
) -> ActionDefinition {
    let info = match name {
        "x11_create_window" => {
            "-> X11 create window {preview(title,60)} {width}x{height}".to_string()
        }
        "x11_set_property" => "-> X11 set {property} on {window}".to_string(),
        "x11_get_property" => "-> X11 get {property} of {window}".to_string(),
        "disconnect" => "-> X11 disconnect".to_string(),
        _ => format!("-> X11 {} {{window}}", name.trim_start_matches("x11_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

fn window_param(description: &str) -> Parameter {
    p("window", "string", description, true)
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "x11_create_window",
            "Create a window (a child of the root unless parent is given), optionally titled and mapped; the result names its id.",
            vec![
                p("width", "number", "Width in pixels, 1-32767", true),
                p("height", "number", "Height in pixels, 1-32767", true),
                p("x", "number", "Left edge relative to the parent (default 0)", false),
                p("y", "number", "Top edge relative to the parent (default 0)", false),
                p("title", "string", "Window title, set as both WM_NAME and _NET_WM_NAME", false),
                p("parent", "string", "Parent window id, or \"root\" (default)", false),
                p("background", "string", "\"white\" (default) or \"black\"", false)
                    .with_choices(["white", "black"]),
                p("map", "boolean", "Map (show) the window after creating it (default true)", false),
                p("watch", "array", "X events to report for this window as x11_event: any of structure, property, exposure, focus, keyboard, pointer", false),
            ],
            json!({"type":"x11_create_window","width":320,"height":200,"title":"NetGet","watch":["structure"]}),
        ),
        action(
            "x11_set_property",
            "Set a property on a window. Text types take a string (or an array of strings, stored NUL-separated as WM_CLASS is); CARDINAL and INTEGER take numbers; ATOM takes atom names; WINDOW takes window ids.",
            vec![
                window_param("Window id, or \"root\""),
                p("property", "string", "Property name, e.g. WM_NAME, _NET_WM_NAME, WM_CLASS or one of your own", true),
                p("property_type", "string", "Value type (default UTF8_STRING)", false).with_choices(PROPERTY_TYPES.iter().copied()),
                p("value", "string", "The value: a string, a number, or an array of either", true),
                p("mode", "string", "replace (default), append or prepend", false).with_choices(["replace", "append", "prepend"]),
            ],
            json!({"type":"x11_set_property","window":"root","property":"NETGET_STATUS","value":"ready"}),
        ),
        action(
            "x11_get_property",
            "Read a property of a window (at most 64 KiB of it); the result carries its type and decoded value, or exists false.",
            vec![
                window_param("Window id, or \"root\""),
                p("property", "string", "Property name, e.g. WM_NAME or one of your own", true),
            ],
            json!({"type":"x11_get_property","window":"root","property":"RESOURCE_MANAGER"}),
        ),
        action(
            "x11_delete_property",
            "Delete a property from a window.",
            vec![window_param("Window id, or \"root\""), p("property", "string", "Property name, e.g. WM_NAME or one of your own", true)],
            json!({"type":"x11_delete_property","window":"root","property":"NETGET_STATUS"}),
        ),
        action(
            "x11_list_properties",
            "List the names of a window's properties (at most 256).",
            vec![window_param("Window id, or \"root\"")],
            json!({"type":"x11_list_properties","window":"root"}),
        ),
        action(
            "x11_query_tree",
            "List a window's children with their titles (WM_NAME), up to 256 of them.",
            vec![p("window", "string", "Window id, or \"root\" (default)", false)],
            json!({"type":"x11_query_tree","window":"root"}),
        ),
        action(
            "x11_get_geometry",
            "Read a window's position, size, border width and depth.",
            vec![window_param("Window id, or \"root\"")],
            json!({"type":"x11_get_geometry","window":"0x200001"}),
        ),
        action(
            "x11_configure_window",
            "Move, resize or raise a window; give only what should change.",
            vec![
                window_param("Window id as xwininfo prints it, e.g. 0x200001"),
                p("x", "number", "New left edge relative to the parent, in pixels", false),
                p("y", "number", "New top edge relative to the parent, in pixels", false),
                p("width", "number", "New width in pixels, 1-32767", false),
                p("height", "number", "New height in pixels, 1-32767", false),
                p("raise", "boolean", "Raise to the top of its siblings", false),
            ],
            json!({"type":"x11_configure_window","window":"0x200001","width":640,"height":480}),
        ),
        action("x11_map_window", "Map (show) a window.", vec![window_param("Window id as xwininfo prints it, e.g. 0x200001")], json!({"type":"x11_map_window","window":"0x200001"})),
        action("x11_unmap_window", "Unmap (hide) a window.", vec![window_param("Window id as xwininfo prints it, e.g. 0x200001")], json!({"type":"x11_unmap_window","window":"0x200001"})),
        action("x11_destroy_window", "Destroy a window and its children.", vec![window_param("Window id as xwininfo prints it, e.g. 0x200001")], json!({"type":"x11_destroy_window","window":"0x200001"})),
        action(
            "x11_intern_atom",
            "Look up (or, unless only_if_exists, create) an atom by name.",
            vec![p("name", "string", "Atom name, e.g. _NET_WM_NAME or WM_CLASS", true), p("only_if_exists", "boolean", "Do not create it (default false)", false)],
            json!({"type":"x11_intern_atom","name":"_NET_WM_NAME"}),
        ),
        action("x11_list_extensions", "List the extensions the server supports.", vec![], json!({"type":"x11_list_extensions"})),
        action(
            "x11_bell",
            "Ring the keyboard bell.",
            vec![p("percent", "number", "Volume relative to the base, -100 to 100 (default 0)", false)],
            json!({"type":"x11_bell","percent":0}),
        ),
        action("disconnect", "Close the connection; the server destroys every window this client created.", vec![], json!({"type":"disconnect"})),
    ]
}

fn ev(id: &str, description: &str, example: Value, parameters: Vec<Parameter>) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(parameters)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "x11_connected",
        "The X server accepted the connection.",
        json!({"type":"x11_create_window","width":320,"height":200,"title":"NetGet"}),
        vec![
            p("vendor", "string", "The server's vendor string", true),
            p("release", "number", "The vendor's release number", true),
            p(
                "protocol_version",
                "string",
                "Protocol major.minor the server speaks, 11.0",
                true,
            ),
            p(
                "screen",
                "object",
                "The chosen screen: root, width, height, width_mm, height_mm, root_depth",
                true,
            ),
            p("screens", "number", "How many screens the server has", true),
        ],
    )
});

pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "x11_result",
        "An action completed; the fields depend on the action.",
        json!({"type":"x11_get_property","window":"root","property":"WM_NAME"}),
        vec![
            p("action", "string", "The action that completed", true),
            p(
                "window",
                "string",
                "The window it concerned, when there is one",
                false,
            ),
            p(
                "value",
                "string",
                "For x11_get_property: the decoded value",
                false,
            ),
            p(
                "children",
                "array",
                "For x11_query_tree: each child's id and title",
                false,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "x11_error",
        "The X server refused an action, or it was not valid to send.",
        json!({"type":"x11_query_tree"}),
        vec![
            p("action", "string", "The action that failed", true),
            p(
                "error",
                "string",
                "The X error (BadWindow, BadAtom, BadValue, ...) or why the action was not sent",
                true,
            ),
            p(
                "request",
                "string",
                "The X request the server refused",
                false,
            ),
            p(
                "bad_value",
                "string",
                "The id or value the server objected to",
                false,
            ),
        ],
    )
});

pub static X_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "x11_event",
        "An X event for a window created watching it.",
        json!({"type":"x11_get_geometry","window":"0x200001"}),
        vec![
            p(
                "event",
                "string",
                "MapNotify, ConfigureNotify, PropertyNotify, Expose, KeyPress, ...",
                true,
            ),
            p("window", "string", "The window it concerns", false),
            p(
                "synthetic",
                "boolean",
                "Sent by another client with SendEvent",
                true,
            ),
        ],
    )
});

/// A window id as the model writes it: "root", "0x200001", or a number.
pub fn window_id(v: &Value, root: u32) -> Result<u32> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .context("a window id is a 32-bit number"),
        Value::String(s) if s == "root" => Ok(root),
        Value::String(s) => {
            let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
            match hex {
                Some(h) => u32::from_str_radix(h, 16),
                None => s.parse(),
            }
            .with_context(|| format!("{s:?} is not a window id; write it as 0x200001 or \"root\""))
        }
        _ => bail!("window must be \"root\", a hex id like 0x200001, or a number"),
    }
}

fn num(v: &Value, key: &str, lo: i64, hi: i64) -> Result<Option<i64>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => {
            let n = x
                .as_i64()
                .with_context(|| format!("{key} must be a whole number"))?;
            ensure!(
                (lo..=hi).contains(&n),
                "{key} must be between {lo} and {hi}"
            );
            Ok(Some(n))
        }
    }
}

fn atom_name(v: &Value, key: &str) -> Result<()> {
    let name = v[key]
        .as_str()
        .with_context(|| format!("{key} must be a string"))?;
    ensure!(
        !name.is_empty() && name.len() <= 255,
        "{key} is 1-255 bytes"
    );
    Ok(())
}

/// Shape checks the model's answer must pass before anything is sent.
pub fn check(v: &Value) -> Result<()> {
    let kind = v["type"].as_str().unwrap_or_default();
    match kind {
        "x11_create_window" => {
            num(v, "width", 1, 32767)?.context("width is required")?;
            num(v, "height", 1, 32767)?.context("height is required")?;
            num(v, "x", -32768, 32767)?;
            num(v, "y", -32768, 32767)?;
            if let Some(t) = v.get("title") {
                ensure!(
                    t.as_str().is_some_and(|t| t.len() <= 4096),
                    "title is a string of at most 4096 bytes"
                );
            }
            if let Some(w) = v.get("parent") {
                window_id(w, 0)?;
            }
            ensure!(
                v.get("background")
                    .is_none_or(|b| b == "white" || b == "black"),
                "background is white or black"
            );
            ensure!(
                v.get("map").is_none_or(Value::is_boolean),
                "map must be a boolean"
            );
            if let Some(w) = v.get("watch") {
                let list = w.as_array().context("watch must be an array")?;
                for item in list {
                    let name = item.as_str().unwrap_or_default();
                    ensure!(
                        super::wire::EVENT_MASKS.iter().any(|(n, _)| *n == name),
                        "watch entries are structure, property, exposure, focus, keyboard or pointer, not {item}"
                    );
                }
            }
        }
        "x11_set_property" => {
            window_id(&v["window"], 0)?;
            atom_name(v, "property")?;
            let kind = v
                .get("property_type")
                .and_then(Value::as_str)
                .unwrap_or("UTF8_STRING");
            ensure!(
                PROPERTY_TYPES.contains(&kind),
                "property_type must be one of {PROPERTY_TYPES:?}"
            );
            ensure!(!v["value"].is_null(), "value is required");
            ensure!(
                v.get("mode")
                    .is_none_or(|m| m == "replace" || m == "append" || m == "prepend"),
                "mode is replace, append or prepend"
            );
        }
        "x11_get_property" | "x11_delete_property" => {
            window_id(&v["window"], 0)?;
            atom_name(v, "property")?;
        }
        "x11_list_properties"
        | "x11_get_geometry"
        | "x11_map_window"
        | "x11_unmap_window"
        | "x11_destroy_window" => {
            window_id(&v["window"], 0)?;
        }
        "x11_query_tree" => {
            if let Some(w) = v.get("window") {
                window_id(w, 0)?;
            }
        }
        "x11_configure_window" => {
            window_id(&v["window"], 0)?;
            num(v, "x", -32768, 32767)?;
            num(v, "y", -32768, 32767)?;
            num(v, "width", 1, 32767)?;
            num(v, "height", 1, 32767)?;
            ensure!(
                v.get("raise").is_none_or(Value::is_boolean),
                "raise must be a boolean"
            );
        }
        "x11_intern_atom" => {
            atom_name(v, "name")?;
            ensure!(
                v.get("only_if_exists").is_none_or(Value::is_boolean),
                "only_if_exists must be a boolean"
            );
        }
        "x11_list_extensions" => {}
        "x11_bell" => {
            num(v, "percent", -100, 100)?;
        }
        _ => bail!("Unknown X11 client action {kind:?}"),
    }
    Ok(())
}

impl Protocol for X11ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "X11"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>X11"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["x11", "x window", "xorg", "xvfb", "x server"]
    }
    fn description(&self) -> &'static str {
        "X11 client: connects to an X server, creates and manages windows, reads and writes properties, and watches X events"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESULT_EVENT.clone(),
            ERROR_EVENT.clone(),
            X_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "screen".into(),
                type_hint: "number".into(),
                description: "Which screen's root window \"root\" means (default 0)".into(),
                required: false,
                example: json!(0),
                default: Some(json!(super::DEFAULT_SCREEN)),
            },
            ParameterDefinition {
                name: "auth_cookie".into(),
                type_hint: "string".into(),
                description: "MIT-MAGIC-COOKIE-1 in hex, as `xauth list` prints it; omit for a server run with -ac".into(),
                required: false,
                example: json!("4c3d0c0e5a7f1e2b9d6a8c4e1f3b5a7d"),
                default: None,
            },
            ParameterDefinition {
                name: "socket_path".into(),
                type_hint: "string".into(),
                description: "Connect to this Unix socket (e.g. /tmp/.X11-unix/X0) instead of remote_addr".into(),
                required: false,
                example: json!("/tmp/.X11-unix/X0"),
                default: None,
            },
            ParameterDefinition {
                name: "timeout_ms".into(),
                type_hint: "number".into(),
                description: "Milliseconds one action may wait for the server's replies (100-60000)".into(),
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
            .implementation("Hand-rolled X11 core protocol over Tokio TCP or a Unix socket: setup with optional MIT-MAGIC-COOKIE-1, CreateWindow, Map/Unmap/Destroy/ConfigureWindow, GetGeometry, QueryTree, InternAtom, GetAtomName, Change/Get/Delete/ListProperties, ListExtensions, Bell; errors matched to their request by sequence number, completion confirmed with a GetInputFocus round trip")
            .llm_control("Which windows to create and how, what to read and write on them, and what to do with each result, error and X event")
            .e2e_testing("tests/client/x11: Xvfb (the X.Org server) as the real peer, every effect read back with xprop and xwininfo; an in-test X server for the bounds and refusals")
            .notes("No drawing, fonts, input injection or extensions beyond listing them. Replies and generic events are bounded at 1 MiB, properties at 64 KiB each way. Windows belong to the connection: the server destroys them when the client disconnects.")
            .max_inbound_bytes(super::wire::MAX_REPLY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the X server at 127.0.0.1:6099 and open a window titled Hello"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"x11","remote_addr":"127.0.0.1:6099","instruction":"Open a 320x200 window titled Hello and report the windows on the screen"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"x11_connected","handler":{"type":"static","actions":[{"type":"x11_create_window","width":320,"height":200,"title":"Hello"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"x11_result","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'x11_query_tree'}] if e['action']=='x11_create_window' else []}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for X11ClientProtocol {
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
