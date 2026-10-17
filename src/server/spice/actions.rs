//! SPICE server actions: who is admitted, what the screen shows, and how it reacts to input.
//!
//! Rust owns the SPICE link (RSA ticket, capabilities, channel connections), the framing and
//! every pixel; the model decides admission and content. It never sees a pixel or the
//! password: it is told whether the password was verified, and it answers with the same
//! structured drawing commands VNC's model uses (`crate::server::vnc::actions::
//! parse_display_commands`), which Rust rasterises and sends as uncompressed bitmaps.
//!
//! Four events, all raised in `src/server/spice/mod.rs`:
//!
//! - `spice_connection_request` — a client linked a main channel and its ticket checked out
//! - `spice_display_ready` — a display channel attached and nothing has been drawn yet
//! - `spice_key_event` — a key went down on the inputs channel
//! - `spice_mouse_event` — a mouse button went down or came up
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::vnc::actions::parse_display_commands;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value as JsonValue};
use std::sync::LazyLock;

pub const DEFAULT_WIDTH: u32 = 800;
pub const DEFAULT_HEIGHT: u32 = 600;
pub const MIN_SIDE: u32 = 16;
pub const MAX_SIDE: u32 = 4096;
/// The surface is `width * height * 4` bytes in memory and on the wire per full frame.
pub const MAX_PIXELS: u64 = 3840 * 2160;
pub const DEFAULT_NAME: &str = "NetGet SPICE";
/// The longest notification the model may send.
pub const MAX_NOTIFY_LEN: usize = 1024;

/// `Custom` result names shared with `mod.rs`.
pub const RESULT_ACCEPT: &str = "spice_accept";
pub const RESULT_REJECT: &str = "spice_reject";
pub const RESULT_DISPLAY: &str = "spice_display";
pub const RESULT_NO_CHANGE: &str = "spice_no_change";
pub const RESULT_NOTIFY: &str = "spice_notify";

#[derive(Clone, Default)]
pub struct SpiceProtocol;

impl SpiceProtocol {
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

fn accept_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_accept_connection".into(),
        description: "Admit this SPICE client: the link completes and its main channel opens. \
                      Without this the client is refused (SPICE_LINK_ERR_PERMISSION_DENIED)."
            .into(),
        parameters: vec![],
        example: json!({"type": "spice_accept_connection"}),
        log_template: Some(LogTemplate::new().with_info("SPICE client admitted")),
    }
}

fn reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_reject_connection".into(),
        description: "Refuse this SPICE client: the link ends with \
                      SPICE_LINK_ERR_PERMISSION_DENIED, which the client reports as an \
                      authentication failure."
            .into(),
        parameters: vec![],
        example: json!({"type": "spice_reject_connection"}),
        log_template: Some(LogTemplate::new().with_info("SPICE client refused")),
    }
}

fn render_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_render_display".into(),
        description:
            "Draw the whole screen and send it to the client. Describe it with drawing commands, \
             never pixels. Each command is an object with a \"type\": \"background\" {color}, \
             \"clear\", \"rectangle\" {x,y,width,height,color,filled}, \"text\" \
             {x,y,text,size,color}, \"line\" {x1,y1,x2,y2,color,width}, \"circle\" \
             {x,y,radius,color,filled}, \"window\" {x,y,width,height,title,content:[...]}, \
             \"button\" {x,y,width,height,label}, \"textbox\" {x,y,width,height,text,placeholder}, \
             \"ascii_art\" {text,size,color,background}. Commands are drawn in order, so start \
             with a \"background\". Colours are hex (\"#1e293b\"), names (\"blue\") or \
             {\"r\":30,\"g\":41,\"b\":59}. Coordinates are pixels from the top left"
                .into(),
        parameters: vec![p(
            "commands",
            "array",
            "Ordered drawing commands making up the entire screen; it is redrawn from scratch",
            true,
        )],
        example: json!({
            "type": "spice_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "Hello from NetGet", "size": 28, "color": "white"},
                {"type": "rectangle", "x": 40, "y": 100, "width": 240, "height": 80, "color": "#38bdf8", "filled": true}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("SPICE screen redrawn")
                .with_trace("SPICE render: {json_pretty(.)}"),
        ),
    }
}

fn no_change_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_no_change".into(),
        description: "Leave the screen as it is: nothing is sent. Use it for input the screen \
                      does not react to."
            .into(),
        parameters: vec![],
        example: json!({"type": "spice_no_change"}),
        log_template: Some(LogTemplate::new().with_debug("SPICE: screen unchanged")),
    }
}

fn notify_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_notify".into(),
        description: "Send a notification on the main channel (SPICE_MSG_NOTIFY). Viewers log \
                      it; they do not draw it, so put anything the user must see on the screen."
            .into(),
        parameters: vec![
            p(
                "message",
                "string",
                &format!("The notification text, at most {MAX_NOTIFY_LEN} bytes"),
                true,
            ),
            p("severity", "string", "info (default), warn or error", false),
        ],
        example: json!({"type": "spice_notify", "message": "Welcome", "severity": "info"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("SPICE notification sent")
                .with_debug("SPICE notify: {preview(message,200)}"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "spice_disconnect_client".into(),
        description: "End this client's whole SPICE session: every channel is closed.".into(),
        parameters: vec![],
        example: json!({"type": "spice_disconnect_client"}),
        log_template: Some(LogTemplate::new().with_info("SPICE session closed by decision")),
    }
}

pub static ACCEPT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(accept_action);
pub static REJECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(reject_action);
pub static RENDER_ACTION: LazyLock<ActionDefinition> = LazyLock::new(render_action);
pub static NO_CHANGE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(no_change_action);
pub static NOTIFY_ACTION: LazyLock<ActionDefinition> = LazyLock::new(notify_action);
pub static DISCONNECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(disconnect_action);

fn screen_actions() -> Vec<ActionDefinition> {
    vec![
        RENDER_ACTION.clone(),
        NO_CHANGE_ACTION.clone(),
        NOTIFY_ACTION.clone(),
        DISCONNECT_ACTION.clone(),
    ]
}

pub static CONNECTION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "spice_connection_request",
        "A SPICE client linked its main channel. Admit it (spice_accept_connection, optionally \
         with a spice_render_display for its first screen) or refuse it",
        json!({"type": "spice_accept_connection"}),
    )
    .with_parameters(vec![
        p("client", "string", "The client's address", true),
        p(
            "password_configured",
            "boolean",
            "True when the server requires a password; the client's ticket has then already \
             been checked against it, and only a correct one reaches you",
            true,
        ),
        p(
            "width",
            "number",
            "Width in pixels of the screen this client will see",
            true,
        ),
        p("height", "number", "Its height in pixels", true),
        p(
            "client_capabilities",
            "array",
            "Common capabilities the client offered (auth_selection, auth_spice, auth_sasl, \
             mini_header)",
            true,
        ),
    ])
    .with_actions(vec![
        ACCEPT_ACTION.clone(),
        REJECT_ACTION.clone(),
        RENDER_ACTION.clone(),
        NOTIFY_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "spice_reject_connection"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("SPICE client {client} asks to connect")
            .with_trace("SPICE connection request: {json_pretty(.)}"),
    )
});

pub static DISPLAY_READY_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "spice_display_ready",
        "A SPICE client opened its display channel and nothing has been drawn yet: draw the \
         whole screen",
        json!({
            "type": "spice_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "NetGet", "size": 32, "color": "white"}
            ]
        }),
    )
    .with_parameters(vec![
        p("width", "number", "Surface width in pixels - draw within this", true),
        p("height", "number", "Surface height in pixels", true),
    ])
    .with_actions(screen_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("SPICE display ready ({width}x{height})")
            .with_trace("SPICE display ready: {json_pretty(.)}"),
    )
    });

pub static KEY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "spice_key_event",
        "A key was pressed on the SPICE client's keyboard - redraw the screen if it should react",
        json!({
            "type": "spice_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "You typed: a", "size": 24, "color": "white"}
            ]
        }),
    )
    .with_parameters(vec![
        p(
            "key",
            "string",
            "The key: its character for a printable key (shift applied), otherwise a name such \
             as Return, BackSpace, Tab, Escape, Left, F1",
            true,
        ),
        p(
            "text",
            "string",
            "The character the key types (US layout), or null for a key that types nothing",
            false,
        ),
        p("scancode", "number", "PC/AT set-1 scancode", true),
        p("extended", "boolean", "True for an 0xE0-prefixed key", true),
        p("shift", "boolean", "True when a Shift key was held as this key went down", true),
        p("ctrl", "boolean", "True when a Control key was held as this key went down", true),
        p("alt", "boolean", "True when an Alt key was held as this key went down", true),
    ])
    .with_actions(screen_actions())
    .with_alternative_example(json!({"type": "spice_no_change"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("SPICE key {key}")
            .with_debug("SPICE key: {json(.)}"),
    )
});

pub static MOUSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "spice_mouse_event",
        "A mouse button went down on the SPICE client - redraw the screen if it should react",
        json!({
            "type": "spice_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "circle", "x": 100, "y": 100, "radius": 20, "color": "#f97316", "filled": true}
            ]
        }),
    )
    .with_parameters(vec![
        p("x", "number", "Pointer X in surface pixels", true),
        p("y", "number", "Pointer Y in surface pixels", true),
        p(
            "button",
            "string",
            "left, middle, right, scroll_up or scroll_down",
            true,
        ),
        p(
            "buttons",
            "array",
            "Buttons held after this press: left, middle, right",
            true,
        ),
        p(
            "mouse_mode",
            "string",
            "client (absolute positions) or server (relative motion, so x and y are where \
             NetGet has tracked the pointer to)",
            true,
        ),
    ])
    .with_actions(screen_actions())
    .with_alternative_example(json!({"type": "spice_no_change"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("SPICE {button} button at {x},{y}")
            .with_debug("SPICE mouse: {json(.)}"),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        CONNECTION_REQUEST_EVENT.clone(),
        DISPLAY_READY_EVENT.clone(),
        KEY_EVENT.clone(),
        MOUSE_EVENT.clone(),
    ]
}

/// Validate a surface size supplied at startup.
pub fn validate_size(width: u32, height: u32) -> Result<(u32, u32)> {
    for (name, v) in [("width", width), ("height", height)] {
        if !(MIN_SIDE..=MAX_SIDE).contains(&v) {
            bail!("{name} must be between {MIN_SIDE} and {MAX_SIDE}, got {v}");
        }
    }
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        bail!("{width}x{height} is above the {MAX_PIXELS} pixel limit");
    }
    Ok((width, height))
}

pub fn parse_severity(v: Option<&str>) -> Result<u32> {
    use crate::server::spice::wire::*;
    Ok(match v.unwrap_or("info") {
        "info" => NOTIFY_SEVERITY_INFO,
        "warn" | "warning" => NOTIFY_SEVERITY_WARN,
        "error" => NOTIFY_SEVERITY_ERROR,
        other => bail!("severity is info, warn or error, not {other:?}"),
    })
}

impl Protocol for SpiceProtocol {
    fn protocol_name(&self) -> &'static str {
        "SPICE"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SPICE"
    }
    fn description(&self) -> &'static str {
        "SPICE remote display server (main, display and inputs channels) whose screen the LLM draws and whose admission the LLM decides"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a SPICE server on port 5930 with password 'pw' showing a login banner, and greet each key the user types"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "spice",
            "spice server",
            "remote display",
            "qxl",
            "virt-viewer",
            "remote-viewer",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Remote Access"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .answers_on_failure()
            .max_inbound_bytes(crate::server::spice::MAX_CLIENT_MESSAGE_BYTES as usize)
            .implementation(
                "Hand-written SPICE 2.2 (no crate): the link stage with an RSA-1024 key per server \
                 and the RSA-OAEP (SHA-1) ticket checked in Rust, mini and full data headers, a \
                 main channel (INIT, NAME, CHANNELS_LIST, MOUSE_MODE, NOTIFY), a display channel \
                 with one primary 32-bit xRGB surface drawn as uncompressed top-down bitmaps \
                 (DRAW_COPY), and an inputs channel decoding PC/AT scancodes and mouse \
                 position, motion and buttons. tiny-skia + cosmic-text render the model's \
                 drawing commands",
            )
            .llm_control(
                "Admission (spice_connection_request, after Rust has checked the password), the \
                 screen (spice_render_display on admission, spice_display_ready, and in reply to \
                 spice_key_event and spice_mouse_event), notifications and disconnects",
            )
            .e2e_testing(
                "tests/server/spice: spice-gtk's spicy-screenshot reads back the rendered \
                 surface pixel by pixel and refuses a wrong password; spicy under Xvfb with \
                 xdotool typing into it delivers keys to the model; spice-html5 in headless \
                 Chrome through websockify renders the same screen; tshark's spice dissector \
                 reads both directions",
            )
            .notes(
                "Experimental: two independent clients drive it (spice-gtk and spice-html5) but \
                 nobody has reviewed it against the spice-protocol headers line by line, no \
                 fuzz target exists, and its pair job had not run in CI when it landed. No TLS channel (NEED_SECURED is never sent; tls-port is not \
                 offered), no SASL, no cursor, audio, agent, USB or smartcard channels, no image \
                 compression (every update is width*height*4 bytes), no streams, one display \
                 and one surface per session. The screen is redrawn whole on every change. \
                 Without a password any ticket is accepted and admission is the model's alone. \
                 Key releases and pointer movement are logged, not sent to the model.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: format!(
                    "Password every channel's ticket must carry (at most \
                     {} bytes). Checked in Rust; never shown to the model. Without one any \
                     ticket is accepted, as QEMU's disable-ticketing, and admission is the \
                     model's decision alone",
                    crate::server::spice::wire::MAX_PASSWORD_LENGTH
                ),
                required: false,
                example: json!("s3cret"),
                default: None,
            },
            ParameterDefinition {
                name: "width".into(),
                type_hint: "number".into(),
                description: format!("Surface width in pixels ({MIN_SIDE}-{MAX_SIDE})"),
                required: false,
                example: json!(1024),
                default: Some(json!(DEFAULT_WIDTH)),
            },
            ParameterDefinition {
                name: "height".into(),
                type_hint: "number".into(),
                description: format!("Surface height in pixels ({MIN_SIDE}-{MAX_SIDE})"),
                required: false,
                example: json!(768),
                default: Some(json!(DEFAULT_HEIGHT)),
            },
            ParameterDefinition {
                name: "name".into(),
                type_hint: "string".into(),
                description: "Guest name sent in SPICE_MSG_MAIN_NAME; viewers put it in their \
                              title bar"
                    .into(),
                required: false,
                example: json!("NetGet Desktop"),
                default: Some(json!(DEFAULT_NAME)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_action(),
            reject_action(),
            render_action(),
            no_change_action(),
            notify_action(),
            disconnect_action(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 5930,
                "base_stack": "spice",
                "startup_params": {"password": "s3cret", "width": 1024, "height": 768},
                "instruction": "Admit every client. Show a dark blue desktop with a window \
                                titled 'Terminal'; append each typed character to it."
            }),
            json!({
                "type": "open_server",
                "port": 5930,
                "base_stack": "spice",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nscreen=lambda s:{'type':'spice_render_display','commands':[{'type':'background','color':'#1e293b'},{'type':'text','x':40,'y':60,'text':s,'size':28,'color':'white'}]}\na=[]\nif t=='spice_connection_request': a=[{'type':'spice_accept_connection'},screen('Welcome')]\nelif t=='spice_key_event': a=[screen('You typed '+e['key'])]\nelse: a=[screen('NetGet')]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 5930,
                "base_stack": "spice",
                "event_handlers": [
                    {"event_pattern": "spice_connection_request", "handler": {"type": "static", "actions": [
                        {"type": "spice_accept_connection"},
                        {"type": "spice_render_display", "commands": [
                            {"type": "background", "color": "#1e293b"},
                            {"type": "text", "x": 40, "y": 60, "text": "NetGet SPICE", "size": 28, "color": "white"}
                        ]}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": [{"type": "spice_no_change"}]}}
                ]
            }),
        )
    }
}

impl Server for SpiceProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let width = params
                .map(|p| p.get_optional_u32("width"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_WIDTH);
            let height = params
                .map(|p| p.get_optional_u32("height"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_HEIGHT);
            let (width, height) = validate_size(width, height)?;
            let password = params
                .map(|p| p.get_optional_string("password"))
                .transpose()?
                .flatten();
            if let Some(pw) = &password {
                if pw.len() > crate::server::spice::wire::MAX_PASSWORD_LENGTH {
                    bail!(
                        "password is {} bytes; SPICE tickets carry at most {}",
                        pw.len(),
                        crate::server::spice::wire::MAX_PASSWORD_LENGTH
                    );
                }
            }
            let name = params
                .map(|p| p.get_optional_string("name"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| DEFAULT_NAME.to_string());
            crate::server::spice::SpiceServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                crate::server::spice::Config {
                    width,
                    height,
                    password,
                    name,
                },
            )
            .await
        })
    }

    fn execute_action(&self, action: JsonValue) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        let custom = |name: &str, data: JsonValue| ActionResult::Custom {
            name: name.to_string(),
            data,
        };
        match kind {
            "spice_accept_connection" => Ok(custom(RESULT_ACCEPT, json!({}))),
            "spice_reject_connection" => Ok(custom(RESULT_REJECT, json!({}))),
            "spice_render_display" => {
                let commands = action.get("commands").ok_or_else(|| {
                    anyhow!(
                        "spice_render_display requires a 'commands' array describing the screen"
                    )
                })?;
                let parsed = parse_display_commands(commands)
                    .context("invalid 'commands' in spice_render_display")?;
                Ok(custom(
                    RESULT_DISPLAY,
                    json!({"commands": serde_json::to_value(parsed)?}),
                ))
            }
            "spice_no_change" => Ok(custom(RESULT_NO_CHANGE, json!({}))),
            "spice_notify" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("spice_notify requires a 'message' string"))?;
                if message.len() > MAX_NOTIFY_LEN {
                    bail!(
                        "spice_notify message is {} bytes, above {MAX_NOTIFY_LEN}",
                        message.len()
                    );
                }
                let severity = parse_severity(action.get("severity").and_then(|v| v.as_str()))?;
                Ok(custom(
                    RESULT_NOTIFY,
                    json!({"message": message, "severity": severity}),
                ))
            }
            "spice_disconnect_client" | "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow!(
                "Unknown SPICE action '{other}'. Valid actions: spice_accept_connection, \
                 spice_reject_connection, spice_render_display, spice_no_change, spice_notify, \
                 spice_disconnect_client"
            )),
        }
    }
}
