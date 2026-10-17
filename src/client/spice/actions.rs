//! What the model can do as a SPICE client: type, press keys, move and click the mouse, and
//! read the display back as colours and draw counts.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::spice::keys;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Most characters one spice_type sends.
pub const MAX_TEXT_CHARS: usize = 4096;
/// Most key combinations one spice_keys sends.
pub const MAX_KEYS: usize = 64;
pub const DEFAULT_GRID: u64 = 4;
pub const MAX_GRID: u64 = 16;
/// Most pixels one spice_read_screen samples.
pub const MAX_POINTS: usize = 32;
pub const DEFAULT_SETTLE_MS: u64 = 500;
/// The longest a read waits for the screen to settle.
pub const MAX_SETTLE_WAIT_MS: u64 = 10_000;
/// The largest coordinate an action may name.
pub const MAX_COORD: u64 = 8192;

#[derive(Default)]
pub struct SpiceClientProtocol;

impl SpiceClientProtocol {
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
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new().with_info(format!("-> spice {}", name.trim_start_matches("spice_"))),
        ),
    }
}

fn type_action() -> ActionDefinition {
    action(
        "spice_type",
        "Type text on the remote display as key presses (US keyboard layout; a newline presses Enter, a tab Tab). Characters a US keyboard cannot type are refused.",
        vec![p("text", "string", "The text to type", true)],
        json!({"type": "spice_type", "text": "hello world"}),
    )
}

fn keys_action() -> ActionDefinition {
    action(
        "spice_keys",
        "Press keys or key combinations in order, e.g. enter, esc, tab, ctrl+alt+delete, f12, up, a.",
        vec![p("keys", "array", "Key names; join modifiers with + (ctrl, shift, alt, win)", true)],
        json!({"type": "spice_keys", "keys": ["esc", "ctrl+alt+delete"]}),
    )
}

fn mouse_action() -> ActionDefinition {
    action(
        "spice_mouse",
        "Move the mouse to a point on the display and act there. In the server's client mouse mode the position is absolute; in server mode it is sent as relative motion from where this client last put the pointer.",
        vec![
            p("x", "number", "Pixels from the left edge", true),
            p("y", "number", "Pixels from the top edge", true),
            p(
                "action",
                "string",
                "move, click (default), double_click, press, release, scroll_up or scroll_down",
                false,
            ),
            p("button", "string", "left (default), right or middle", false),
        ],
        json!({"type": "spice_mouse", "x": 100, "y": 200, "action": "click", "button": "left"}),
    )
}

fn read_screen_action() -> ActionDefinition {
    action(
        "spice_read_screen",
        "Look at the display: once no draw has arrived for settle_ms, its size, most common colour, a grid of each cell's most common colour, a checksum, the colours at any points asked for, and counts of every draw command and image type the server sent arrive as spice_screen. exact is false when some draw could not be applied (a compressed image, a stream).",
        vec![
            p("grid", "number", "Cells per side of the colour grid (1-16, default 4)", false),
            p("settle_ms", "number", "How long the display must go without draws first (default 500)", false),
            p("points", "array", "Up to 32 [x, y] pixels whose colours to report", false),
        ],
        json!({"type": "spice_read_screen", "grid": 4}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close every channel of the session.",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        type_action(),
        keys_action(),
        mouse_action(),
        read_screen_action(),
        disconnect_action(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, read_screen_action().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_connected",
        "The SPICE session is up: the main channel linked and the display and inputs channels opened.",
        vec![
            p("server", "string", "The server's address", true),
            p("session_id", "number", "The session id the server assigned", true),
            p("channels", "array", "Channels the server offered, as type names", true),
            p("mouse_mode", "string", "client (absolute) or server (relative)", true),
            p("name", "string", "The guest name the server sent, if any", false),
            p("agent_connected", "boolean", "Whether a guest agent is running", true),
        ],
    )
});

pub static SURFACE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_surface_created",
        "The server created (or re-created) the primary display surface.",
        vec![
            p(
                "width",
                "number",
                "Surface width in pixels; a spice_mouse x must be below it",
                true,
            ),
            p("height", "number", "Surface height in pixels", true),
            p(
                "format",
                "number",
                "SPICE surface format (32 is 32-bit xRGB)",
                true,
            ),
        ],
    )
});

pub static SCREEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_screen",
        "What the display looks like now, as colours, and what the server drew to get there.",
        vec![
            p("width", "number", "Width of the primary surface", true),
            p("height", "number", "Height of the primary surface", true),
            p(
                "dominant_color",
                "string",
                "The most common colour, #rrggbb",
                true,
            ),
            p(
                "dominant_share",
                "number",
                "Fraction of the screen in that colour (0-1)",
                true,
            ),
            p(
                "grid",
                "array",
                "Rows top to bottom, each cell's most common colour",
                true,
            ),
            p(
                "checksum",
                "string",
                "FNV-1a of the surface's RGB bytes; it changes when the picture does",
                true,
            ),
            p(
                "points",
                "array",
                "The colours at the points asked for",
                false,
            ),
            p(
                "draw_ops",
                "object",
                "Count of each display message the server sent",
                true,
            ),
            p(
                "images",
                "object",
                "Count of each image type the server sent",
                true,
            ),
            p(
                "exact",
                "boolean",
                "False when some draw could not be applied to the picture",
                true,
            ),
            p(
                "settled",
                "boolean",
                "False when draws kept arriving past the wait",
                true,
            ),
        ],
    )
});

pub static NOTIFY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_notify",
        "The server sent a notification on the main channel.",
        vec![
            p("severity", "string", "info, warn or error", true),
            p(
                "message",
                "string",
                "The text, with control characters removed",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_error",
        "An action could not be carried out.",
        vec![
            p("action", "string", "The action's type", true),
            p("message", "string", "What went wrong", true),
        ],
    )
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spice_disconnected",
        "The session ended.",
        vec![p(
            "reason",
            "string",
            "Why the session ended: the server closed a channel, a bound was broken, or the client disconnected",
            true,
        )],
    )
});

/// A validated action.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// (scancode, extended) presses and releases in order: (key, released).
    Keys(Vec<((u8, bool), bool)>),
    Mouse {
        x: u32,
        y: u32,
        action: String,
        button: String,
    },
    ReadScreen {
        grid: u64,
        settle_ms: u64,
        points: Vec<(u32, u32)>,
    },
}

const MOUSE_ACTIONS: [&str; 7] = [
    "move",
    "click",
    "double_click",
    "press",
    "release",
    "scroll_up",
    "scroll_down",
];

const SHIFT: (u8, bool) = (0x2A, false);

/// The key strokes that type `text`.
pub fn strokes_for_text(text: &str) -> Result<Vec<((u8, bool), bool)>> {
    let mut out = Vec::new();
    for ch in text.chars() {
        let (sc, shift) = keys::scancode_for_char(ch)
            .with_context(|| format!("{ch:?} cannot be typed on a US keyboard"))?;
        if shift {
            out.push((SHIFT, false));
        }
        out.push(((sc, false), false));
        out.push(((sc, false), true));
        if shift {
            out.push((SHIFT, true));
        }
    }
    Ok(out)
}

/// The key strokes for one combination such as `ctrl+alt+delete`: pressed in order, released
/// in reverse.
pub fn strokes_for_combo(combo: &str) -> Result<Vec<((u8, bool), bool)>> {
    let parts: Vec<&str> = if combo.trim() == "+" {
        vec!["+"]
    } else {
        combo.split('+').map(str::trim).collect()
    };
    ensure!(
        !parts.is_empty() && parts.iter().all(|p| !p.is_empty()),
        "{combo:?} is not a key combination"
    );
    let mut keys_down = Vec::new();
    for part in &parts {
        let key = keys::named_key(part).with_context(|| format!("unknown key {part:?}"))?;
        keys_down.push(key);
    }
    let mut out: Vec<((u8, bool), bool)> = keys_down.iter().map(|k| (*k, false)).collect();
    out.extend(keys_down.iter().rev().map(|k| (*k, true)));
    Ok(out)
}

pub fn check(v: &Value) -> Result<Input> {
    match v["type"].as_str().unwrap_or_default() {
        "spice_type" => {
            let text = v["text"].as_str().context("text is required")?;
            ensure!(
                text.chars().count() <= MAX_TEXT_CHARS,
                "text is at most {MAX_TEXT_CHARS} characters"
            );
            Ok(Input::Keys(strokes_for_text(text)?))
        }
        "spice_keys" => {
            let list = v["keys"]
                .as_array()
                .context("keys is an array of key names")?;
            ensure!(
                !list.is_empty() && list.len() <= MAX_KEYS,
                "keys holds 1 to {MAX_KEYS} entries"
            );
            let mut out = Vec::new();
            for k in list {
                out.extend(strokes_for_combo(
                    k.as_str().context("each key is a string")?,
                )?);
            }
            Ok(Input::Keys(out))
        }
        "spice_mouse" => {
            let coord = |k: &str| -> Result<u32> {
                let n = v[k]
                    .as_u64()
                    .with_context(|| format!("{k} is a number of pixels"))?;
                ensure!(n < MAX_COORD, "{k} is off the display");
                Ok(n as u32)
            };
            let action = v["action"].as_str().unwrap_or("click").to_string();
            ensure!(
                MOUSE_ACTIONS.contains(&action.as_str()),
                "action is one of {}",
                MOUSE_ACTIONS.join(", ")
            );
            let button = v["button"].as_str().unwrap_or("left").to_string();
            ensure!(
                ["left", "right", "middle"].contains(&button.as_str()),
                "button is left, right or middle"
            );
            Ok(Input::Mouse {
                x: coord("x")?,
                y: coord("y")?,
                action,
                button,
            })
        }
        "spice_read_screen" => {
            let grid = v["grid"].as_u64().unwrap_or(DEFAULT_GRID);
            ensure!((1..=MAX_GRID).contains(&grid), "grid is 1 to {MAX_GRID}");
            let settle_ms = v["settle_ms"].as_u64().unwrap_or(DEFAULT_SETTLE_MS);
            ensure!(
                settle_ms <= MAX_SETTLE_WAIT_MS,
                "settle_ms is at most {MAX_SETTLE_WAIT_MS}"
            );
            let mut points = Vec::new();
            if let Some(list) = v.get("points").filter(|p| !p.is_null()) {
                let list = list.as_array().context("points is an array of [x, y]")?;
                ensure!(list.len() <= MAX_POINTS, "at most {MAX_POINTS} points");
                for pt in list {
                    let xy = pt
                        .as_array()
                        .filter(|a| a.len() == 2)
                        .context("each point is [x, y]")?;
                    let n = |i: usize| -> Result<u32> {
                        let n = xy[i]
                            .as_u64()
                            .context("a point's coordinates are numbers")?;
                        ensure!(n < MAX_COORD, "a point is off the display");
                        Ok(n as u32)
                    };
                    points.push((n(0)?, n(1)?));
                }
            }
            Ok(Input::ReadScreen {
                grid,
                settle_ms,
                points,
            })
        }
        other => bail!("unknown SPICE action {other:?}"),
    }
}

impl Protocol for SpiceClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SPICE"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SPICE"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "spice",
            "spice client",
            "remote display",
            "qemu",
            "virt-viewer",
            "remote-viewer",
        ]
    }
    fn description(&self) -> &'static str {
        "SPICE client: links main, display and inputs channels with a password, reads the display back as colours and draw counts, and types and clicks"
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
            SURFACE_EVENT.clone(),
            SCREEN_EVENT.clone(),
            NOTIFY_EVENT.clone(),
            ERROR_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "password".into(),
            type_hint: "string".into(),
            description: "The server's SPICE password (at most 60 bytes), sent as the RSA-OAEP ticket every channel carries. Leave it out for a server without one".into(),
            required: false,
            example: json!("s3cret"),
            default: None,
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written SPICE 2.2 client: link stage with the RSA-OAEP (SHA-1) ticket, mini and full headers, SET_ACK/ACK flow control and PING/PONG on every channel, main (INIT, CHANNELS_LIST, MOUSE_MODE, NAME, NOTIFY), display (primary surface, uncompressed and cached bitmaps through DRAW_COPY, solid DRAW_FILL, BLACKNESS/WHITENESS/INVERS, COPY_BITS, clip rectangles; asks for uncompressed images) and inputs (PC/AT scancodes, absolute or relative mouse)")
            .llm_control("What to type, which keys to press, where to click, and when to look; the display comes back as size, colours, a checksum, sampled points and counts of what the server drew")
            .e2e_testing("tests/client/spice: QEMU's spice-server (qemu-system-x86_64 -spice, no disk, SeaBIOS on the VGA console) — the surface size, the firmware screen appearing after the VM is resumed, keystrokes and mouse buttons read back from QEMU's input trace events, and a wrong password refused; tshark's spice dissector over both directions")
            .notes("Experimental: one independent server (spice-server through QEMU). No TLS (tls-port), no SASL, no cursor, audio, agent, USB or smartcard channels. Compressed images (QUIC, LZ, GLZ, JPEG, LZ4) and video streams are counted but not decoded, so a reading says exact: false when they were drawn; the client asks for uncompressed images, which spice-server honours. One primary surface; off-screen surfaces are counted, not kept. Typing is US layout only; SPICE has no Unicode key event.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the SPICE display at 127.0.0.1:5930 with password s3cret, press Escape and tell me what colour the screen is"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"SPICE","remote_addr":"127.0.0.1:5930",
            "startup_params":{"password":"s3cret"},
            "instruction":"Once connected, read the screen and report its main colour"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"spice_connected","handler":{"type":"static","actions":[read_screen_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0] = json!({"event_pattern":"spice_surface_created","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'spice_mouse','x':e['width']//2,'y':e['height']//2}]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Remote Access"
    }
}

impl Client for SpiceClientProtocol {
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
