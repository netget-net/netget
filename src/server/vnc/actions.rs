//! VNC protocol actions — RFB 3.8, LLM-controlled display.
//!
//! The division of labour follows netget's model: Rust owns RFB framing, the framebuffer and
//! the pixel encoding; the LLM decides *what is on screen* and how to react to input. The model
//! never sees or produces pixels. It answers an event with a structured description of the
//! screen — rectangles, text, lines, circles, windows, buttons — and
//! [`parse_display_commands`] turns that into [`DisplayCommand`]s that
//! `crate::display::DisplayCanvas` rasterises.
//!
//! Four events, all of which fire (see `src/server/vnc/mod.rs`):
//!
//! - `vnc_framebuffer_update_request` — a client asked for a full (non-incremental) frame
//! - `vnc_key_event` — a key went down or up
//! - `vnc_pointer_event` — a mouse button changed state (bare movement is logged, not modelled)
//! - `vnc_client_cut_text` — the client copied text to its clipboard
//!
//! Four sync actions, each reachable from at least one event: `vnc_render_display`,
//! `vnc_no_change`, `vnc_set_clipboard`, `vnc_disconnect_client`.
//!
//! There are no async (user-triggered) actions: the server keeps no registry of live
//! connections, so there is nothing for an async action to address. Declaring one would be a
//! promise the code does not keep.

use crate::display::{Color, DisplayCommand};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value as JsonValue};
use std::sync::LazyLock;

// ============================================================================
// Limits
//
// Startup parameters come from the LLM or an MCP client and the display commands come from a
// model answering an event, so every one of these is untrusted input. Nothing below is
// allocated or indexed before it has been bounds-checked.
// ============================================================================

/// Framebuffer size used when the caller does not pass `width` / `height`.
pub const DEFAULT_FRAMEBUFFER_WIDTH: u16 = 800;
/// Framebuffer size used when the caller does not pass `width` / `height`.
pub const DEFAULT_FRAMEBUFFER_HEIGHT: u16 = 600;

/// Smallest accepted framebuffer edge. `Pixmap::new` panics on a zero dimension, and a
/// one-pixel desktop is never what anybody meant.
pub const MIN_FRAMEBUFFER_DIMENSION: u32 = 16;
/// Largest accepted framebuffer edge.
pub const MAX_FRAMEBUFFER_DIMENSION: u32 = 4096;
/// Largest accepted framebuffer area. A frame is `pixels * 4` bytes on the wire *and* in
/// memory, uncompressed, so the area matters more than either edge.
pub const MAX_FRAMEBUFFER_PIXELS: u64 = 3840 * 2160;

/// Largest number of drawing commands accepted in one `vnc_render_display`.
const MAX_DISPLAY_COMMANDS: usize = 256;
/// Largest nesting depth for `window` command content.
const MAX_NESTING_DEPTH: usize = 4;
/// Largest string accepted in a `text` / `title` / `label` field.
const MAX_TEXT_LEN: usize = 4096;
/// Largest coordinate or size accepted in a drawing command.
const MAX_COORDINATE: u64 = 65535;
/// Largest clipboard payload the server will push to a client with ServerCutText.
pub const MAX_CLIPBOARD_LEN: usize = 1 << 16;

// ============================================================================
// ActionResult::Custom names, shared with the connection loop in mod.rs
// ============================================================================

/// `Custom` result carrying the rendered screen description.
pub const RESULT_DISPLAY: &str = "vnc_display";
/// `Custom` result meaning "the screen is unchanged; send nothing new".
pub const RESULT_NO_CHANGE: &str = "vnc_no_change";
/// `Custom` result carrying text for the client's clipboard.
pub const RESULT_CLIPBOARD: &str = "vnc_clipboard";

/// VNC protocol implementation
#[derive(Clone, Default)]
pub struct VncProtocol;

impl VncProtocol {
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// Display command parsing
// ============================================================================

/// Short name for a JSON value's type, for error messages.
fn json_type(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

/// Read a required non-negative integer field, bounded by [`MAX_COORDINATE`].
fn u32_field(obj: &JsonValue, key: &str) -> Result<u32> {
    let value = obj
        .get(key)
        .ok_or_else(|| anyhow!("missing required field '{key}'"))?;
    let number = match value {
        JsonValue::Number(n) => n
            .as_u64()
            // Models frequently emit 10.0 where 10 was meant; a negative or fractional
            // coordinate is still rejected below.
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0)
                    .map(|f| f as u64)
            })
            .ok_or_else(|| {
                anyhow!("field '{key}' must be a non-negative whole number, got {value}")
            })?,
        other => bail!("field '{key}' must be a number, got {}", json_type(other)),
    };
    if number > MAX_COORDINATE {
        bail!("field '{key}' is {number}, which exceeds the maximum of {MAX_COORDINATE}");
    }
    Ok(number as u32)
}

/// Read an optional non-negative integer field.
fn u32_field_or(obj: &JsonValue, key: &str, default: u32) -> Result<u32> {
    if obj.get(key).is_none() || obj.get(key) == Some(&JsonValue::Null) {
        return Ok(default);
    }
    u32_field(obj, key)
}

/// Read an optional boolean field.
fn bool_field_or(obj: &JsonValue, key: &str, default: bool) -> Result<bool> {
    match obj.get(key) {
        None | Some(JsonValue::Null) => Ok(default),
        Some(JsonValue::Bool(b)) => Ok(*b),
        Some(other) => bail!(
            "field '{key}' must be true or false, got {}",
            json_type(other)
        ),
    }
}

/// Read a required string field, bounded by [`MAX_TEXT_LEN`] bytes.
fn string_field(obj: &JsonValue, key: &str) -> Result<String> {
    let value = obj
        .get(key)
        .ok_or_else(|| anyhow!("missing required field '{key}'"))?;
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("field '{key}' must be a string, got {}", json_type(value)))?;
    if text.len() > MAX_TEXT_LEN {
        bail!(
            "field '{key}' is {} bytes, which exceeds the maximum of {MAX_TEXT_LEN}",
            text.len()
        );
    }
    Ok(text.to_string())
}

/// Read an optional string field.
fn optional_string_field(obj: &JsonValue, key: &str) -> Result<Option<String>> {
    match obj.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(_) => Ok(Some(string_field(obj, key)?)),
    }
}

/// Named colours a model can use instead of a hex string.
fn named_color(name: &str) -> Option<Color> {
    Some(match name {
        "black" => Color::BLACK,
        "white" => Color::WHITE,
        "red" => Color::RED,
        "green" => Color::GREEN,
        "blue" => Color::BLUE,
        "yellow" => Color::rgb(255, 255, 0),
        "cyan" => Color::rgb(0, 255, 255),
        "magenta" => Color::rgb(255, 0, 255),
        "orange" => Color::rgb(255, 165, 0),
        "purple" => Color::rgb(128, 0, 128),
        "navy" => Color::rgb(0, 0, 128),
        "teal" => Color::rgb(0, 128, 128),
        "olive" => Color::rgb(128, 128, 0),
        "maroon" => Color::rgb(128, 0, 0),
        "silver" => Color::rgb(192, 192, 192),
        "gray" | "grey" => Color::GRAY,
        "light_gray" | "lightgray" | "light_grey" | "lightgrey" => Color::LIGHT_GRAY,
        "dark_gray" | "darkgray" | "dark_grey" | "darkgrey" => Color::DARK_GRAY,
        _ => return None,
    })
}

/// Parse a colour written as `"#rgb"`, `"#rrggbb"`, `"#rrggbbaa"`, a colour name, or an
/// object `{"r":…, "g":…, "b":…, "a":…}`.
pub fn parse_color(value: &JsonValue) -> Result<Color> {
    match value {
        JsonValue::String(text) => {
            let trimmed = text.trim();
            if let Some(hex) = trimmed.strip_prefix('#') {
                let bytes = hex.as_bytes();
                let nibble = |b: u8| -> Result<u8> {
                    (b as char)
                        .to_digit(16)
                        .map(|d| d as u8)
                        .ok_or_else(|| anyhow!("'{trimmed}' is not a valid hex colour"))
                };
                return match bytes.len() {
                    3 => {
                        let (r, g, b) = (nibble(bytes[0])?, nibble(bytes[1])?, nibble(bytes[2])?);
                        Ok(Color::rgb(r * 17, g * 17, b * 17))
                    }
                    6 | 8 => {
                        let mut channels = [255u8; 4];
                        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
                            channels[i] = nibble(chunk[0])? * 16 + nibble(chunk[1])?;
                        }
                        Ok(Color::rgba(
                            channels[0],
                            channels[1],
                            channels[2],
                            channels[3],
                        ))
                    }
                    other => bail!(
                        "hex colour '{trimmed}' has {other} digits; use #rgb, #rrggbb or #rrggbbaa"
                    ),
                };
            }
            named_color(&trimmed.to_ascii_lowercase()).ok_or_else(|| {
                anyhow!(
                    "unknown colour '{trimmed}'. Use a hex string such as \"#1e293b\" or one of: \
                     black, white, red, green, blue, yellow, cyan, magenta, orange, purple, navy, \
                     teal, olive, maroon, silver, gray, light_gray, dark_gray"
                )
            })
        }
        JsonValue::Object(_) => {
            let channel = |key: &str, default: u32| -> Result<u8> {
                let v = u32_field_or(value, key, default)?;
                if v > 255 {
                    bail!("colour channel '{key}' is {v}; each channel is 0-255");
                }
                Ok(v as u8)
            };
            Ok(Color::rgba(
                channel("r", 0)?,
                channel("g", 0)?,
                channel("b", 0)?,
                channel("a", 255)?,
            ))
        }
        other => bail!(
            "a colour must be a hex string (\"#1e293b\"), a colour name (\"blue\") or an object \
             {{\"r\":30,\"g\":41,\"b\":59}}, got {}",
            json_type(other)
        ),
    }
}

/// Optional colour field with a fallback.
fn color_field_or(obj: &JsonValue, key: &str, default: Color) -> Result<Color> {
    match obj.get(key) {
        None | Some(JsonValue::Null) => Ok(default),
        Some(value) => parse_color(value).with_context(|| format!("field '{key}'")),
    }
}

/// Turn the model's `commands` array into renderable [`DisplayCommand`]s.
///
/// Every failure is reported rather than skipped: a screen half-drawn because one command was
/// silently dropped is indistinguishable from one the model meant to draw.
pub fn parse_display_commands(value: &JsonValue) -> Result<Vec<DisplayCommand>> {
    parse_command_array(value, 0)
}

fn parse_command_array(value: &JsonValue, depth: usize) -> Result<Vec<DisplayCommand>> {
    let array = value.as_array().ok_or_else(|| {
        anyhow!(
            "'commands' must be an array of drawing commands, got {}",
            json_type(value)
        )
    })?;
    if array.len() > MAX_DISPLAY_COMMANDS {
        bail!(
            "{} drawing commands were given; at most {MAX_DISPLAY_COMMANDS} are accepted",
            array.len()
        );
    }
    array
        .iter()
        .enumerate()
        .map(|(index, command)| {
            parse_display_command(command, depth).with_context(|| format!("command #{index}"))
        })
        .collect()
}

fn parse_display_command(value: &JsonValue, depth: usize) -> Result<DisplayCommand> {
    if depth > MAX_NESTING_DEPTH {
        bail!("window content is nested more than {MAX_NESTING_DEPTH} levels deep");
    }
    if !value.is_object() {
        bail!(
            "a drawing command must be an object such as \
             {{\"type\":\"text\",\"x\":10,\"y\":20,\"text\":\"hi\"}}, got {}",
            json_type(value)
        );
    }
    let command_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("drawing command has no \"type\" field"))?;

    Ok(match command_type {
        "background" => DisplayCommand::SetBackground {
            color: color_field_or(value, "color", Color::BLACK)?,
        },
        "clear" => DisplayCommand::Clear,
        "rectangle" | "rect" => DisplayCommand::DrawRectangle {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            width: u32_field(value, "width")?,
            height: u32_field(value, "height")?,
            color: color_field_or(value, "color", Color::WHITE)?,
            filled: bool_field_or(value, "filled", true)?,
        },
        "text" => DisplayCommand::DrawText {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            text: string_field(value, "text")?,
            font_size: u32_field_or(value, "size", 16)?.clamp(6, 256),
            color: color_field_or(value, "color", Color::WHITE)?,
        },
        "line" => DisplayCommand::DrawLine {
            x1: u32_field(value, "x1")?,
            y1: u32_field(value, "y1")?,
            x2: u32_field(value, "x2")?,
            y2: u32_field(value, "y2")?,
            color: color_field_or(value, "color", Color::WHITE)?,
            width: u32_field_or(value, "width", 1)?.clamp(1, 64),
        },
        "circle" => DisplayCommand::DrawCircle {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            radius: u32_field(value, "radius")?,
            color: color_field_or(value, "color", Color::WHITE)?,
            filled: bool_field_or(value, "filled", true)?,
        },
        "window" => DisplayCommand::DrawWindow {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            width: u32_field(value, "width")?,
            height: u32_field(value, "height")?,
            title: string_field(value, "title")?,
            content: match value.get("content") {
                None | Some(JsonValue::Null) => Vec::new(),
                Some(content) => parse_command_array(content, depth + 1)?,
            },
        },
        "button" => DisplayCommand::DrawButton {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            width: u32_field(value, "width")?,
            height: u32_field(value, "height")?,
            label: string_field(value, "label")?,
        },
        "textbox" => DisplayCommand::DrawTextBox {
            x: u32_field(value, "x")?,
            y: u32_field(value, "y")?,
            width: u32_field(value, "width")?,
            height: u32_field(value, "height")?,
            text: optional_string_field(value, "text")?.unwrap_or_default(),
            placeholder: optional_string_field(value, "placeholder")?,
        },
        "ascii_art" => DisplayCommand::RenderAsciiArt {
            text: string_field(value, "text")?,
            font_size: u32_field_or(value, "size", 14)?.clamp(6, 256),
            fg_color: color_field_or(value, "color", Color::WHITE)?,
            bg_color: color_field_or(value, "background", Color::BLACK)?,
        },
        other => bail!(
            "unknown drawing command \"{other}\". Valid types are: background, clear, rectangle, \
             text, line, circle, window, button, textbox, ascii_art"
        ),
    })
}

/// Validate a framebuffer dimension pair supplied at startup.
pub fn validate_framebuffer_size(width: u32, height: u32) -> Result<(u16, u16)> {
    for (name, value) in [("width", width), ("height", height)] {
        if !(MIN_FRAMEBUFFER_DIMENSION..=MAX_FRAMEBUFFER_DIMENSION).contains(&value) {
            bail!(
                "{name} must be between {MIN_FRAMEBUFFER_DIMENSION} and \
                 {MAX_FRAMEBUFFER_DIMENSION}, got {value}"
            );
        }
    }
    let pixels = width as u64 * height as u64;
    if pixels > MAX_FRAMEBUFFER_PIXELS {
        bail!(
            "{width}x{height} is {pixels} pixels, above the {MAX_FRAMEBUFFER_PIXELS} pixel limit \
             (each frame is 4 bytes per pixel, uncompressed, on every update)"
        );
    }
    // Both are <= MAX_FRAMEBUFFER_DIMENSION (4096), so the casts cannot truncate.
    Ok((width as u16, height as u16))
}

// ============================================================================
// Action definitions
// ============================================================================

fn render_display_action() -> ActionDefinition {
    ActionDefinition {
        name: "vnc_render_display".to_string(),
        description:
            "Draw the whole screen and send it to the client. Describe the screen structurally \
             with drawing commands - never pixels. Each command is an object with a \"type\": \
             \"background\" {color}, \"clear\", \"rectangle\" {x,y,width,height,color,filled}, \
             \"text\" {x,y,text,size,color}, \"line\" {x1,y1,x2,y2,color,width}, \"circle\" \
             {x,y,radius,color,filled}, \"window\" {x,y,width,height,title,content:[...]}, \
             \"button\" {x,y,width,height,label}, \"textbox\" \
             {x,y,width,height,text,placeholder}, \"ascii_art\" {text,size,color,background}. \
             Commands are drawn in order, so start with a \"background\". Colours are hex \
             strings (\"#1e293b\"), colour names (\"blue\") or {\"r\":30,\"g\":41,\"b\":59}. \
             Coordinates are pixels from the top-left of the framebuffer"
                .to_string(),
        parameters: vec![Parameter {
            name: "commands".to_string(),
            type_hint: "array".to_string(),
            description:
                "Ordered list of drawing commands making up the entire screen. The framebuffer \
                 is redrawn from scratch, so include everything that should be visible"
                    .to_string(),
            required: true,
        }],
        example: json!({
            "type": "vnc_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "Hello from NetGet", "size": 28, "color": "white"},
                {"type": "rectangle", "x": 40, "y": 100, "width": 240, "height": 80, "color": "#38bdf8", "filled": true}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("VNC screen redrawn")
                .with_debug("VNC render: {commands_len} command(s)")
                .with_trace("VNC render: {json_pretty(.)}"),
        ),
    }
}

fn no_change_action() -> ActionDefinition {
    ActionDefinition {
        name: "vnc_no_change".to_string(),
        description:
            "The screen is unchanged - send no update. Use this for input the display does not \
             react to (a key release, a click on empty space) so the client keeps showing what \
             it already has instead of receiving a redundant full frame"
                .to_string(),
        parameters: Vec::new(),
        example: json!({"type": "vnc_no_change"}),
        log_template: Some(LogTemplate::new().with_debug("VNC: screen unchanged")),
    }
}

fn set_clipboard_action() -> ActionDefinition {
    ActionDefinition {
        name: "vnc_set_clipboard".to_string(),
        description:
            "Put text on the client's clipboard (RFB ServerCutText). Latin-1 only per the RFB \
             specification; characters outside it are replaced with '?'"
                .to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "Text to copy to the client's clipboard".to_string(),
            required: true,
        }],
        example: json!({"type": "vnc_set_clipboard", "text": "copied from NetGet"}),
        log_template: Some(
            LogTemplate::new()
                .with_debug("VNC clipboard set")
                .with_trace("VNC clipboard: {preview(text,200)}"),
        ),
    }
}

fn disconnect_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "vnc_disconnect_client".to_string(),
        description: "Close this VNC connection immediately".to_string(),
        parameters: Vec::new(),
        example: json!({"type": "vnc_disconnect_client"}),
        log_template: Some(LogTemplate::new().with_info("VNC connection closed by decision")),
    }
}

pub static VNC_RENDER_DISPLAY_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(render_display_action);
pub static VNC_NO_CHANGE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(no_change_action);
pub static VNC_SET_CLIPBOARD_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(set_clipboard_action);
pub static VNC_DISCONNECT_CLIENT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(disconnect_client_action);

// ============================================================================
// Event types
// ============================================================================

/// A client asked for a full repaint of the framebuffer.
///
/// Only *non-incremental* requests raise this. An incremental request is the client saying
/// "tell me when something changes", and RFB lets the server hold it open until something
/// does; answering every one of them with a model call would spend one LLM round-trip per
/// poll on a screen nobody touched. Held requests are answered by the next event that
/// redraws the screen.
pub static VNC_FRAMEBUFFER_UPDATE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_framebuffer_update_request",
        "A VNC client asked for a full framebuffer update - draw the whole screen",
        json!({
            "type": "vnc_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "NetGet", "size": 32, "color": "white"}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "width".to_string(),
            type_hint: "number".to_string(),
            description: "Framebuffer width in pixels - draw within this".to_string(),
            required: true,
        },
        Parameter {
            name: "height".to_string(),
            type_hint: "number".to_string(),
            description: "Framebuffer height in pixels - draw within this".to_string(),
            required: true,
        },
        Parameter {
            name: "first_request".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when this is the first frame this client has ever asked for"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        VNC_RENDER_DISPLAY_ACTION.clone(),
        VNC_NO_CHANGE_ACTION.clone(),
        VNC_DISCONNECT_CLIENT_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("VNC full framebuffer requested ({width}x{height})")
            .with_debug("VNC framebuffer update request, first={first_request}")
            .with_trace("VNC framebuffer update request: {json_pretty(.)}"),
    )
});

/// A key went down or up on the client keyboard.
pub static VNC_KEY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_key_event",
        "A VNC client pressed or released a key - redraw the screen if it should react",
        json!({
            "type": "vnc_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "text", "x": 40, "y": 60, "text": "You typed: a", "size": 24, "color": "white"}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "down".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for a key press, false for a key release".to_string(),
            required: true,
        },
        Parameter {
            name: "keysym".to_string(),
            type_hint: "number".to_string(),
            description: "X11 keysym code of the key".to_string(),
            required: true,
        },
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description:
                "Human readable key name: the character for printable keys, otherwise a name \
                 such as Return, BackSpace, Tab, Escape, Left, F1"
                    .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        VNC_RENDER_DISPLAY_ACTION.clone(),
        VNC_NO_CHANGE_ACTION.clone(),
        VNC_SET_CLIPBOARD_ACTION.clone(),
        VNC_DISCONNECT_CLIENT_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "vnc_no_change"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("VNC key {key} ({down})")
            .with_debug("VNC KeyEvent: down={down}, keysym={keysym}, key={key}")
            .with_trace("VNC KeyEvent: {json_pretty(.)}"),
    )
});

/// A mouse button changed state on the client.
///
/// Bare movement does not raise this: a viewer emits a PointerEvent for every pixel the mouse
/// travels, and one model round-trip per pixel is not a feature. Movement is dual-logged, and
/// the coordinates of the press/release that *does* raise the event are carried in it.
pub static VNC_POINTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_pointer_event",
        "A VNC client pressed or released a mouse button - redraw the screen if it should react",
        json!({
            "type": "vnc_render_display",
            "commands": [
                {"type": "background", "color": "#1e293b"},
                {"type": "circle", "x": 100, "y": 100, "radius": 20, "color": "#f97316", "filled": true}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "x".to_string(),
            type_hint: "number".to_string(),
            description: "Pointer X position in framebuffer pixels".to_string(),
            required: true,
        },
        Parameter {
            name: "y".to_string(),
            type_hint: "number".to_string(),
            description: "Pointer Y position in framebuffer pixels".to_string(),
            required: true,
        },
        Parameter {
            name: "pressed".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when a button went down, false when one came up".to_string(),
            required: true,
        },
        Parameter {
            name: "buttons".to_string(),
            type_hint: "array".to_string(),
            description:
                "Buttons currently held, by name: left, middle, right, scroll_up, scroll_down"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "button_mask".to_string(),
            type_hint: "number".to_string(),
            description: "Raw RFB button mask, bit 0 = left, bit 1 = middle, bit 2 = right"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        VNC_RENDER_DISPLAY_ACTION.clone(),
        VNC_NO_CHANGE_ACTION.clone(),
        VNC_DISCONNECT_CLIENT_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "vnc_no_change"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("VNC pointer at {x},{y} pressed={pressed}")
            .with_debug("VNC PointerEvent: x={x}, y={y}, mask={button_mask}")
            .with_trace("VNC PointerEvent: {json_pretty(.)}"),
    )
});

/// The client copied text to its clipboard and sent it to us.
pub static VNC_CLIENT_CUT_TEXT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_client_cut_text",
        "A VNC client copied text to its clipboard and sent it to the server",
        json!({"type": "vnc_set_clipboard", "text": "NetGet received your clipboard"}),
    )
    .with_parameters(vec![Parameter {
        name: "text".to_string(),
        type_hint: "string".to_string(),
        description: "Text the client copied".to_string(),
        required: true,
    }])
    .with_actions(vec![
        VNC_SET_CLIPBOARD_ACTION.clone(),
        VNC_RENDER_DISPLAY_ACTION.clone(),
        VNC_NO_CHANGE_ACTION.clone(),
        VNC_DISCONNECT_CLIENT_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "vnc_no_change"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("VNC clipboard received from client")
            .with_debug("VNC ClientCutText: {text_len} bytes")
            .with_trace("VNC ClientCutText: {preview(text,200)}"),
    )
});

/// Every event type this protocol can raise. All four are raised by
/// `VncServer::message_loop`.
pub fn get_vnc_event_types() -> Vec<EventType> {
    vec![
        VNC_FRAMEBUFFER_UPDATE_REQUEST_EVENT.clone(),
        VNC_KEY_EVENT.clone(),
        VNC_POINTER_EVENT.clone(),
        VNC_CLIENT_CUT_TEXT_EVENT.clone(),
    ]
}

// ============================================================================
// Protocol trait
// ============================================================================

impl Protocol for VncProtocol {
    fn protocol_name(&self) -> &'static str {
        "VNC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>VNC"
    }
    fn description(&self) -> &'static str {
        "VNC remote desktop server (RFB 3.8) whose screen contents are drawn by the LLM"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a VNC server on port 5900 showing a blue desktop with a welcome message"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["vnc", "rfb", "remote desktop", "framebuffer"]
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(5900)
            // ClientCutText is the one client message a peer sizes; its u32 length is refused
            // against this before the buffer is allocated. Tested in
            // tests/server/vnc/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::vnc::MAX_CUT_TEXT_LEN as usize)
            .implementation(
                "Hand-written RFB 3.8 over TCP (no crate), Raw encoding, tiny-skia display canvas",
            )
            .llm_control(
                "Screen contents and reactions to input: the model answers \
                 vnc_framebuffer_update_request, vnc_key_event, vnc_pointer_event and \
                 vnc_client_cut_text with structured drawing commands, clipboard text or a \
                 disconnect",
            )
            .e2e_testing("custom RFB 3.8 client in tests/server/vnc/test.rs, decoding real pixels")
            .notes(
                "Security type 'None' only - any client is admitted, there is no VNC-Auth and no \
                 password. Raw encoding only (no CopyRect/Hextile/ZRLE/Tight), so every update is \
                 width*height*4 bytes uncompressed. SetPixelFormat is parsed and ignored: the \
                 server always sends 32bpp BGRX, so a client that negotiates 8- or 16-bit colour \
                 renders garbage. Framebuffer size is fixed at startup (width/height parameters, \
                 default 800x600); there is no DesktopSize pseudo-encoding, so it cannot change \
                 afterwards. Incremental update requests are held open until an event redraws the \
                 screen rather than triggering a model call each. Pointer movement without a \
                 button change is logged, not sent to the model. Each connection has its own \
                 framebuffer; the ClientInit shared flag is read and ignored.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    /// Declared because both are read in `spawn`. Nothing else is accepted.
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "width".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Framebuffer width in pixels ({MIN_FRAMEBUFFER_DIMENSION}-\
                     {MAX_FRAMEBUFFER_DIMENSION}, default {DEFAULT_FRAMEBUFFER_WIDTH}). Fixed for \
                     the life of the server"
                ),
                required: false,
                example: json!(1024),
                default: None,
            },
            ParameterDefinition {
                name: "height".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Framebuffer height in pixels ({MIN_FRAMEBUFFER_DIMENSION}-\
                     {MAX_FRAMEBUFFER_DIMENSION}, default {DEFAULT_FRAMEBUFFER_HEIGHT}). Fixed \
                     for the life of the server"
                ),
                required: false,
                example: json!(768),
                default: None,
            },
            ParameterDefinition {
                name: "desktop_name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Desktop name announced in ServerInit and shown in the viewer's title bar"
                        .to_string(),
                required: false,
                example: json!("NetGet Desktop"),
                default: None,
            },
        ]
    }

    /// None: the server keeps no registry of live connections, so there is nothing a
    /// user-triggered action could address. Everything happens in response to an event.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            render_display_action(),
            no_change_action(),
            set_clipboard_action(),
            disconnect_client_action(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_vnc_event_types()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model draws every frame.
            json!({
                "type": "open_server",
                "port": 5900,
                "base_stack": "vnc",
                "startup_params": {
                    "width": 1024,
                    "height": 768,
                    "desktop_name": "NetGet Desktop"
                },
                "instruction": "Show a dark blue desktop with a window titled 'Terminal' \
                                containing the text 'NetGet VNC'. React to typed keys by \
                                appending the character to the window."
            }),
            // Script mode: deterministic, no LLM call per frame.
            json!({
                "type": "open_server",
                "port": 5900,
                "base_stack": "vnc",
                "event_handlers": [{
                    "event_pattern": "vnc_framebuffer_update_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'vnc_render_display', 'commands': [\
            {'type': 'background', 'color': '#1e293b'}, \
            {'type': 'text', 'x': 40, 'y': 60, 'text': 'NetGet %dx%d' % (event['width'], event['height']), \
            'size': 28, 'color': 'white'}]}])"
                    }
                }]
            }),
            // Static mode: one fixed screen, no LLM call ever.
            json!({
                "type": "open_server",
                "port": 5900,
                "base_stack": "vnc",
                "event_handlers": [{
                    "event_pattern": "vnc_framebuffer_update_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "vnc_render_display",
                            "commands": [
                                {"type": "background", "color": "#1e293b"},
                                {"type": "text", "x": 40, "y": 60, "text": "NetGet VNC",
                                 "size": 28, "color": "white"}
                            ]
                        }]
                    }
                }]
            }),
        )
    }
}

// ============================================================================
// Server trait
// ============================================================================

impl Server for VncProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::vnc::VncServer;

            let (width, height, desktop_name) = match ctx.startup_params.as_ref() {
                Some(params) => {
                    let width = params
                        .get_optional_u32("width")?
                        .unwrap_or(DEFAULT_FRAMEBUFFER_WIDTH as u32);
                    let height = params
                        .get_optional_u32("height")?
                        .unwrap_or(DEFAULT_FRAMEBUFFER_HEIGHT as u32);
                    (width, height, params.get_optional_string("desktop_name")?)
                }
                None => (
                    DEFAULT_FRAMEBUFFER_WIDTH as u32,
                    DEFAULT_FRAMEBUFFER_HEIGHT as u32,
                    None,
                ),
            };
            let (width, height) = validate_framebuffer_size(width, height)?;

            VncServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                width,
                height,
                desktop_name,
            )
            .await
        })
    }

    fn execute_action(&self, action: JsonValue) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;

        match action_type {
            "vnc_render_display" => {
                let commands = action.get("commands").ok_or_else(|| {
                    anyhow!(
                        "vnc_render_display requires a 'commands' array describing the screen, \
                         e.g. [{{\"type\":\"background\",\"color\":\"#1e293b\"}}]"
                    )
                })?;
                let parsed = parse_display_commands(commands)
                    .context("invalid 'commands' in vnc_render_display")?;
                let count = parsed.len();
                Ok(ActionResult::Custom {
                    name: RESULT_DISPLAY.to_string(),
                    data: json!({
                        "commands": serde_json::to_value(parsed)
                            .context("failed to serialise display commands")?,
                        "count": count,
                    }),
                })
            }
            "vnc_no_change" => Ok(ActionResult::Custom {
                name: RESULT_NO_CHANGE.to_string(),
                data: json!({}),
            }),
            "vnc_set_clipboard" => {
                let text = action
                    .get("text")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("vnc_set_clipboard requires a 'text' string"))?;
                if text.len() > MAX_CLIPBOARD_LEN {
                    bail!(
                        "vnc_set_clipboard text is {} bytes, above the {MAX_CLIPBOARD_LEN} byte \
                         limit",
                        text.len()
                    );
                }
                Ok(ActionResult::Custom {
                    name: RESULT_CLIPBOARD.to_string(),
                    data: json!({ "text": text }),
                })
            }
            "vnc_disconnect_client" => Ok(ActionResult::CloseConnection),
            // The dashboard's "[ disconnect this peer ]" row injects `close_connection`, the
            // generic verb the peer task understands; map it to the same result as the VNC-named
            // disconnect so the operator can drop a connection from the rail.
            "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow!(
                "Unknown VNC action '{other}'. Valid actions: vnc_render_display, \
                 vnc_no_change, vnc_set_clipboard, vnc_disconnect_client"
            )),
        }
    }
}
