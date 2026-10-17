//! What the model does as a Guacamole server (in guacd's place): decide each connection, and
//! drive the remote display it shows — filled rectangles, text, the clipboard — while the
//! client's typing, clicks and clipboard come back as events. Rust owns the handshake, the
//! instruction framing, sync and keepalive, and turns text into PNG image streams.
use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT: &str = "guacamole_accept";
pub const REJECT: &str = "guacamole_reject";
pub const FILL: &str = "guacamole_fill";
pub const TEXT: &str = "guacamole_text";
pub const CLIPBOARD: &str = "guacamole_clipboard";
pub const DISCONNECT: &str = "guacamole_disconnect";
/// The connection parameters advertised when none are configured (what a VNC connection
/// takes, minus the ones only a real VNC server would use).
pub const DEFAULT_PARAMETERS: &[&str] = &["hostname", "port", "username", "password"];

#[derive(Default, Clone)]
pub struct GuacamoleProtocol;

impl GuacamoleProtocol {
    pub fn new() -> Self {
        Self
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
        log_template: Some(LogTemplate::new().with_info(format!(
            "-> Guacamole {}",
            name.trim_start_matches("guacamole_")
        ))),
    }
}

pub fn accept_action() -> ActionDefinition {
    action(ACCEPT, "Accept the connection: the client gets its connection id and a display of the size it asked for.", vec![],
        json!({"type": ACCEPT}))
}
pub fn reject_action() -> ActionDefinition {
    action(
        REJECT,
        "Refuse the connection with a message (the client is told it is unauthorized).",
        vec![p("message", "string", "Why, shown to the user", false)],
        json!({"type": REJECT, "message": "Unknown user"}),
    )
}
pub fn fill_action() -> ActionDefinition {
    action(
        FILL,
        "Fill a rectangle of the display with a colour (the whole display when no size is given).",
        vec![
            p("x", "number", "Left edge in pixels (default 0)", false),
            p("y", "number", "Top edge in pixels (default 0)", false),
            p(
                "width",
                "number",
                "Width in pixels (default: to the right edge)",
                false,
            ),
            p(
                "height",
                "number",
                "Height in pixels (default: to the bottom edge)",
                false,
            ),
            p("color", "string", "Colour as #rrggbb", true),
        ],
        json!({"type": FILL, "x": 0, "y": 0, "width": 320, "height": 40, "color": "#202060"}),
    )
}
pub fn text_action() -> ActionDefinition {
    action(
        TEXT,
        "Draw text on the display in an 8x8 pixel font (lines split on newlines).",
        vec![
            p("x", "number", "Left edge in pixels", true),
            p("y", "number", "Top edge in pixels", true),
            p("text", "string", "The text to draw", true),
            p(
                "color",
                "string",
                "Text colour as #rrggbb (default #ffffff)",
                false,
            ),
            p(
                "background",
                "string",
                "Background colour as #rrggbb (default transparent)",
                false,
            ),
            p(
                "scale",
                "number",
                "Pixel size of the font: 1 (8 px glyphs) to 8 (default 2)",
                false,
            ),
        ],
        json!({"type": TEXT, "x": 8, "y": 8, "text": "Welcome to NetGet", "color": "#ffffff", "scale": 2}),
    )
}
pub fn clipboard_action() -> ActionDefinition {
    action(
        CLIPBOARD,
        "Set the client's clipboard to this text.",
        vec![p("text", "string", "The clipboard's new contents", true)],
        json!({"type": CLIPBOARD, "text": "copied from the remote desktop"}),
    )
}
pub fn disconnect_action() -> ActionDefinition {
    action(
        DISCONNECT,
        "End the session, optionally telling the user why.",
        vec![p(
            "message",
            "string",
            "Shown to the user as the reason",
            false,
        )],
        json!({"type": DISCONNECT, "message": "Session over"}),
    )
}

fn display_actions() -> Vec<ActionDefinition> {
    vec![
        fill_action(),
        text_action(),
        clipboard_action(),
        disconnect_action(),
    ]
}

fn session_params() -> Vec<Parameter> {
    vec![p(
        "connection_id",
        "string",
        "The connection id NetGet gave the session",
        true,
    )]
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut actions = vec![accept_action(), reject_action()];
    actions.extend(
        display_actions()
            .into_iter()
            .filter(|a| a.name != DISCONNECT),
    );
    EventType::new(
        "guacamole_connect",
        "A Guacamole client asks for a remote desktop. Accept (and draw its first screen with guacamole_fill/guacamole_text) or reject.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("protocol", "string", "The protocol the client selected (vnc, rdp, ssh, …)", true),
        p("arguments", "object", "The connection parameters it gave, by name (secrets left out)", true),
        p("secret_arguments", "array", "Names of the parameters it gave that hold secrets (their values are not shown)", true),
        p("width", "number", "Display width the client asked for", true),
        p("height", "number", "Display height the client asked for", true),
        p("image_types", "array", "Image formats the client accepts", true),
        p("timezone", "string", "The client's timezone, when sent", false),
    ])
    .with_actions(actions)
});

pub static TEXT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = session_params();
    params.push(p(
        "text",
        "string",
        "The line the user typed (sent when they press Enter)",
        true,
    ));
    EventType::new(
        "guacamole_typed",
        "The user typed a line and pressed Enter.",
        text_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(display_actions())
});

pub static KEY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = session_params();
    params.push(p(
        "key",
        "string",
        "The key pressed: Escape, Tab, an arrow, F1-F35, Delete, …",
        true,
    ));
    params.push(p(
        "pending_text",
        "string",
        "What has been typed on the current line so far",
        true,
    ));
    EventType::new(
        "guacamole_key",
        "The user pressed a key that does not type text (Enter ends a line instead).",
        text_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(display_actions())
});

pub static CLICK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = session_params();
    params.extend([
        p("x", "number", "Horizontal position in pixels", true),
        p("y", "number", "Vertical position in pixels", true),
        p(
            "button",
            "string",
            "left, middle, right, scroll_up or scroll_down",
            true,
        ),
    ]);
    EventType::new(
        "guacamole_click",
        "The user pressed a mouse button.",
        fill_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(display_actions())
});

pub static CLIPBOARD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = session_params();
    params.push(p("text", "string", "The client's new clipboard text", true));
    EventType::new(
        "guacamole_clipboard_received",
        "The client sent its clipboard.",
        text_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(display_actions())
});

fn num(v: &Value, k: &str, max: u64) -> Result<Option<u32>> {
    if v[k].is_null() {
        return Ok(None);
    }
    let n = v[k]
        .as_u64()
        .with_context(|| format!("{k} must be a whole number"))?;
    ensure!(n <= max, "{k} must be at most {max}");
    Ok(Some(n as u32))
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT | REJECT | DISCONNECT => {}
        FILL => {
            wire::color(v["color"].as_str().context("color is required")?)?;
            for k in ["x", "y", "width", "height"] {
                num(v, k, 16384)?;
            }
        }
        TEXT => {
            v["text"].as_str().context("text is required")?;
            num(v, "x", 16384)?.context("x is required")?;
            num(v, "y", 16384)?.context("y is required")?;
            ensure!(num(v, "scale", 8)?.unwrap_or(2) >= 1, "scale must be 1-8");
            for k in ["color", "background"] {
                if let Some(c) = v[k].as_str() {
                    wire::color(c)?;
                }
            }
        }
        CLIPBOARD => {
            let t = v["text"].as_str().context("text is required")?;
            ensure!(t.len() <= wire::MAX_CLIPBOARD, "clipboard text too long");
        }
        other => bail!("Unknown Guacamole action {other:?}"),
    }
    Ok(())
}

impl Protocol for GuacamoleProtocol {
    fn protocol_name(&self) -> &'static str {
        "Guacamole"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Guacamole"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["guacamole", "guacd", "remote desktop gateway", "4822"]
    }
    fn description(&self) -> &'static str {
        "Apache Guacamole protocol server in guacd's place: accepts connections from Guacamole clients and shows them a display the model draws (rectangles, text, clipboard), hearing their typing, clicks and clipboard"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut v = vec![accept_action(), reject_action()];
        v.extend(display_actions());
        v
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            TEXT_EVENT.clone(),
            KEY_EVENT.clone(),
            CLICK_EVENT.clone(),
            CLIPBOARD_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "parameters".into(),
            type_hint: "array".into(),
            description: "Connection parameter names advertised in the args instruction; the client answers each".into(),
            required: false,
            example: json!(["hostname", "port", "username", "password", "color-depth"]),
            default: Some(json!(DEFAULT_PARAMETERS)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(4822)
            .implementation("Hand-rolled Guacamole protocol (src/server/guacamole/wire.rs): code-point-counted instructions with guacd's 8192-byte and 128-element bounds; the select/args/size/audio/video/image/timezone/connect handshake (VERSION_1_3_0, version element optional); ready, size, rect+cfill, img/blob/end PNG streams (text rendered in Rust with an 8x8 font), clipboard streams both ways with ack, sync answered and sent as a 5-second keepalive, error and disconnect")
            .llm_control("Whether each connection is accepted, and everything the display shows and the clipboard holds, in answer to the user's typed lines, special keys, clicks and clipboard")
            .e2e_testing("tests/server/guacamole: pyguacamole and Apache's own guacamole-common (Java) complete the handshake, read the model's display and clipboard, type, click and send their clipboard; raw instructions for the bounds")
            .notes("NetGet is the remote desktop, not a gateway: it connects to no VNC/RDP/SSH server. Joining an existing connection ($id), audio, video, file transfer and multiple layers are not supported. Typing reaches the model a line at a time; mouse motion does not reach it at all. A model failure on connect refuses the connection (SERVER_ERROR); later failures are logged and the display stays as it was.")
            .max_inbound_bytes(wire::MAX_INSTRUCTION)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Guacamole server on port 4822 showing a blue screen with a welcome line, echoing back each line typed"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"guacamole","port":0,
            "instruction":"Accept everyone; show a dark blue screen titled 'NetGet' and echo each typed line below it"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"guacamole_connect","handler":{"type":"static","actions":[{"type":ACCEPT},{"type":FILL,"color":"#202060"},{"type":TEXT,"x":8,"y":8,"text":"NetGet","scale":3}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='guacamole_connect': a=[{'type':'guacamole_accept'},{'type':'guacamole_fill','color':'#202060'}]\nelif t=='guacamole_typed': a=[{'type':'guacamole_text','x':8,'y':40,'text':'you typed: '+e['text'],'background':'#202060'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for GuacamoleProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        let name = action["type"].as_str().unwrap_or_default().to_string();
        Ok(ActionResult::Custom { name, data: action })
    }
}
