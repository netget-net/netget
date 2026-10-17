//! What the model does as a Guacamole client of guacd: type, press keys, click, move the
//! pointer and set the remote clipboard. The handshake, sync acknowledgements and stream
//! acks are Rust's.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::guacamole::{actions::p, wire};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The display size asked for when none is configured.
pub const DEFAULT_WIDTH: u32 = 1024;
pub const DEFAULT_HEIGHT: u32 = 768;
/// The remote protocol guacd is asked for when none is configured.
pub const DEFAULT_PROTOCOL: &str = "vnc";

#[derive(Default)]
pub struct GuacamoleClientProtocol;
impl GuacamoleClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<crate::llm::actions::Parameter>,
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

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action("guacamole_type", "Type text on the remote desktop (each character pressed and released; \\n presses Enter).",
            vec![p("text", "string", "The text to type", true)],
            json!({"type": "guacamole_type", "text": "echo hello\n"})),
        action("guacamole_key", "Press and release one key.",
            vec![p("key", "string", "Return, Escape, Tab, BackSpace, Up/Down/Left/Right, Home, End, F1-F35, a character, or 0x<keysym>", true)],
            json!({"type": "guacamole_key", "key": "Escape"})),
        action("guacamole_click", "Move the pointer and click a mouse button.",
            vec![
                p("x", "number", "Horizontal position in pixels", true),
                p("y", "number", "Vertical position in pixels", true),
                p("button", "string", "left (default), middle or right", false),
            ],
            json!({"type": "guacamole_click", "x": 100, "y": 50})),
        action("guacamole_move", "Move the pointer without clicking.",
            vec![p("x", "number", "Horizontal position in pixels", true), p("y", "number", "Vertical position in pixels", true)],
            json!({"type": "guacamole_move", "x": 10, "y": 10})),
        action("guacamole_clipboard", "Set the remote desktop's clipboard to this text.",
            vec![p("text", "string", "The clipboard's new contents", true)],
            json!({"type": "guacamole_clipboard", "text": "pasted by NetGet"})),
        action("disconnect", "End the session.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": "guacamole_type", "text": "hello\n"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "guacamole_ready",
        "guacd connected to the remote desktop and drew its first frame.",
        vec![
            p(
                "connection_id",
                "string",
                "guacd's id for this connection",
                true,
            ),
            p(
                "protocol",
                "string",
                "The remote protocol (vnc, rdp, ssh, …)",
                true,
            ),
            p("width", "number", "Display width in pixels", true),
            p("height", "number", "Display height in pixels", true),
            p(
                "name",
                "string",
                "The remote desktop's name, when guacd sent one",
                false,
            ),
        ],
    )
});

pub static CLIPBOARD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "guacamole_clipboard_received",
        "The remote desktop's clipboard changed.",
        vec![
            p("text", "string", "The remote clipboard's new text", true),
            p(
                "display_updates",
                "number",
                "Drawing operations received so far",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "guacamole_error",
        "guacd reported an error (the session usually ends after it).",
        vec![
            p("message", "string", "guacd's message", true),
            p(
                "status",
                "number",
                "Guacamole status code, e.g. 519 upstream not found, 769 unauthorized",
                true,
            ),
        ],
    )
});

/// The instructions one action sends.
pub fn instructions(v: &Value) -> Result<String> {
    let mut out = String::new();
    let key = |out: &mut String, k: u32| {
        out.push_str(&wire::encode("key", &[&k.to_string(), "1"]));
        out.push_str(&wire::encode("key", &[&k.to_string(), "0"]));
    };
    let xy = |k: &str| -> Result<String> {
        let n = v[k].as_u64().with_context(|| format!("{k} is required"))?;
        ensure!(n <= 16384, "{k} is off any display");
        Ok(n.to_string())
    };
    match v["type"].as_str().unwrap_or_default() {
        "guacamole_type" => {
            let text = v["text"].as_str().context("text is required")?;
            ensure!(
                text.chars().count() <= 4096,
                "type at most 4096 characters at once"
            );
            for c in text.chars() {
                key(&mut out, wire::keysym_of_char(c));
            }
        }
        "guacamole_key" => key(
            &mut out,
            wire::keysym_of_name(v["key"].as_str().context("key is required")?)?,
        ),
        "guacamole_click" => {
            let bit = match v["button"].as_str().unwrap_or("left") {
                "left" => 1,
                "middle" => 2,
                "right" => 4,
                b => bail!("button must be left, middle or right, not {b:?}"),
            };
            let (x, y) = (xy("x")?, xy("y")?);
            out.push_str(&wire::encode("mouse", &[&x, &y, &bit.to_string()]));
            out.push_str(&wire::encode("mouse", &[&x, &y, "0"]));
        }
        "guacamole_move" => out.push_str(&wire::encode("mouse", &[&xy("x")?, &xy("y")?, "0"])),
        "guacamole_clipboard" => {
            let text = v["text"].as_str().context("text is required")?;
            ensure!(text.len() <= wire::MAX_CLIPBOARD, "clipboard text too long");
            // Stream index 0 is never in use by a client before this.
            out.push_str(&wire::encode("clipboard", &["0", "text/plain"]));
            out.push_str(&wire::blobs("0", text.as_bytes()));
            out.push_str(&wire::encode("end", &["0"]));
        }
        t => bail!("Unknown Guacamole client action {t:?}"),
    }
    Ok(out)
}

impl Protocol for GuacamoleClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Guacamole"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Guacamole"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["guacamole", "guacd", "remote desktop", "vnc through guacd"]
    }
    fn description(&self) -> &'static str {
        "Guacamole client of guacd: opens a VNC/RDP/SSH session through it, types, clicks and exchanges the clipboard"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            CLIPBOARD_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "protocol".into(),
                type_hint: "string".into(),
                description: "The remote protocol guacd should speak: vnc, rdp, ssh or telnet".into(),
                required: false,
                example: json!("vnc"),
                default: Some(json!(DEFAULT_PROTOCOL)),
            },
            ParameterDefinition {
                name: "arguments".into(),
                type_hint: "object".into(),
                description: "Connection parameters by the names guacd asks for, e.g. {hostname, port, password}".into(),
                required: true,
                example: json!({"hostname": "127.0.0.1", "port": "5901"}),
                default: None,
            },
            ParameterDefinition {
                name: "width".into(),
                type_hint: "number".into(),
                description: "Display width in pixels to ask for".into(),
                required: false,
                example: json!(800),
                default: Some(json!(DEFAULT_WIDTH)),
            },
            ParameterDefinition {
                name: "height".into(),
                type_hint: "number".into(),
                description: "Display height in pixels to ask for".into(),
                required: false,
                example: json!(600),
                default: Some(json!(DEFAULT_HEIGHT)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's Guacamole framing as a client: select, args, size/audio/video/image/timezone, connect with the parameters guacd names; sync acknowledged and blobs acked in Rust; key, mouse and clipboard streams sent")
            .llm_control("What to type, which keys and buttons to press, what to put on the remote clipboard, and how to answer the remote clipboard and errors")
            .e2e_testing("tests/client/guacamole: guacd 1.3 (Apache's own daemon) driving TigerVNC's Xvnc, read back with xclip and an xterm writing what it is typed to a file")
            .notes("Images are counted, not decoded: the handler cannot see the screen. No audio, file transfer or multi-touch. Instructions are bounded as guacd bounds them (8192 bytes, 128 elements).")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Open a VNC session to 127.0.0.1:5901 through guacd at 127.0.0.1:4822 and type 'hello'"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"guacamole","remote_addr":"127.0.0.1:4822",
            "startup_params":{"protocol":"vnc","arguments":{"hostname":"127.0.0.1","port":"5901"}},
            "instruction":"Type 'hello' and press Enter"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"guacamole_ready","handler":{"type":"static","actions":[{"type":"guacamole_type","text":"hello\n"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\na=[{'type':'guacamole_type','text':'hello\\n'}] if i['event_type_id']=='guacamole_ready' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for GuacamoleClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        instructions(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
