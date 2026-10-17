//! What the model can do as an RDP client: type, press keys, move and click the mouse, and
//! read the screen back as colours.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DEFAULT_WIDTH: u16 = 1024;
pub const DEFAULT_HEIGHT: u16 = 768;
pub const MIN_SIDE: u16 = 200;
/// The largest desktop side this client asks for, and the largest it accepts from the server.
pub const MAX_SIDE: u16 = 4096;
/// The `security` setting when none is given: NLA only, so the password is proven through
/// CredSSP and never sent to a server that has not proven it knows it.
pub const DEFAULT_SECURITY: &str = "nla";
/// Most characters one rdp_type sends.
pub const MAX_TEXT_CHARS: usize = 4096;
/// Most key combinations one rdp_keys sends.
pub const MAX_KEYS: usize = 64;
pub const DEFAULT_GRID: u64 = 4;
pub const MAX_GRID: u64 = 16;
/// How long the screen must be quiet before rdp_read_screen answers, by default.
pub const DEFAULT_SETTLE_MS: u64 = 500;
/// The longest a read waits for the screen to settle; past it, the screen is read as it is.
pub const MAX_SETTLE_WAIT_MS: u64 = 10_000;

#[derive(Default)]
pub struct RdpClientProtocol;
impl RdpClientProtocol {
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
            LogTemplate::new().with_info(format!("-> rdp {}", name.trim_start_matches("rdp_"))),
        ),
    }
}

fn type_action() -> ActionDefinition {
    action(
        "rdp_type",
        "Type text on the remote desktop, as keystrokes (US layout; other characters as Unicode key events).",
        vec![p("text", "string", "The text to type; a newline presses Enter", true)],
        json!({"type":"rdp_type","text":"hello world"}),
    )
}

fn keys_action() -> ActionDefinition {
    action(
        "rdp_keys",
        "Press keys or key combinations in order, e.g. enter, tab, ctrl+a, alt+f4, ctrl+alt+delete, f5, up, a.",
        vec![p("keys", "array", "Key names; join modifiers with + (ctrl, shift, alt, win)", true)],
        json!({"type":"rdp_keys","keys":["ctrl+a","backspace","enter"]}),
    )
}

fn mouse_action() -> ActionDefinition {
    action(
        "rdp_mouse",
        "Move the mouse to a point on the remote desktop and act there.",
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
        json!({"type":"rdp_mouse","x":100,"y":200,"action":"click","button":"left"}),
    )
}

fn read_screen_action() -> ActionDefinition {
    action(
        "rdp_read_screen",
        "Look at the remote desktop: once it has been quiet for settle_ms, its size, most common colour and a grid of each cell's most common colour arrive as rdp_screen.",
        vec![
            p("grid", "number", "Cells per side of the colour grid (1-16, default 4)", false),
            p(
                "settle_ms",
                "number",
                "How long the screen must go without updates first (default 500)",
                false,
            ),
        ],
        json!({"type":"rdp_read_screen","grid":4}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Log off politely (shutdown request) and close the connection.",
        vec![],
        json!({"type":"disconnect"}),
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
        "rdp_connected",
        "The RDP connection sequence finished: the session is live and accepts input.",
        vec![
            p("server", "string", "The server's address", true),
            p(
                "security",
                "string",
                "tls or nla (CredSSP), as the server selected",
                true,
            ),
            p("width", "number", "Desktop width the server granted", true),
            p(
                "height",
                "number",
                "Desktop height the server granted",
                true,
            ),
        ],
    )
});

pub static SCREEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "rdp_screen",
        "What the remote desktop looks like now, as colours.",
        vec![
            p(
                "width",
                "number",
                "Width in pixels of the desktop this reading covers; an rdp_mouse x must be below it",
                true,
            ),
            p(
                "height",
                "number",
                "Height in pixels of the desktop this reading covers; an rdp_mouse y must be below it",
                true,
            ),
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
                "Rows top to bottom, each cell's most common colour (#rrggbb) left to right",
                true,
            ),
            p(
                "graphics_updates",
                "number",
                "Screen regions the server has drawn since connecting",
                true,
            ),
            p(
                "settled",
                "boolean",
                "False when the screen kept changing past the wait",
                true,
            ),
        ],
    )
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "rdp_disconnected",
        "The session ended.",
        vec![p(
            "reason",
            "string",
            "Why: the server's reason, or the error",
            true,
        )],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "rdp_error",
        "An action could not be carried out.",
        vec![
            p("action", "string", "The action's type", true),
            p("message", "string", "What went wrong", true),
        ],
    )
});

/// An input action, validated.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    Text(String),
    Keys(Vec<String>),
    Mouse {
        x: u16,
        y: u16,
        action: String,
        button: String,
    },
    ReadScreen {
        grid: u64,
        settle_ms: u64,
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

pub fn check(v: &Value) -> Result<Input> {
    match v["type"].as_str().unwrap_or_default() {
        "rdp_type" => {
            let text = v["text"].as_str().context("text is required")?;
            ensure!(
                text.chars().count() <= MAX_TEXT_CHARS,
                "text is at most {MAX_TEXT_CHARS} characters"
            );
            Ok(Input::Text(text.to_string()))
        }
        "rdp_keys" => {
            let keys: Vec<String> = v["keys"]
                .as_array()
                .context("keys is an array of key names")?
                .iter()
                .map(|k| {
                    k.as_str()
                        .map(str::to_string)
                        .context("each key is a string")
                })
                .collect::<Result<_>>()?;
            ensure!(
                !keys.is_empty() && keys.len() <= MAX_KEYS,
                "keys holds 1 to {MAX_KEYS} entries"
            );
            for k in &keys {
                super::keys::combo(k)?;
            }
            Ok(Input::Keys(keys))
        }
        "rdp_mouse" => {
            let coord = |k: &str| -> Result<u16> {
                let n = v[k]
                    .as_u64()
                    .with_context(|| format!("{k} is a number of pixels"))?;
                ensure!(n < u64::from(MAX_SIDE), "{k} is off the desktop");
                Ok(n as u16)
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
        "rdp_read_screen" => {
            let grid = v["grid"].as_u64().unwrap_or(DEFAULT_GRID);
            ensure!((1..=MAX_GRID).contains(&grid), "grid is 1 to {MAX_GRID}");
            let settle_ms = v["settle_ms"].as_u64().unwrap_or(DEFAULT_SETTLE_MS);
            ensure!(
                settle_ms <= MAX_SETTLE_WAIT_MS,
                "settle_ms is at most {MAX_SETTLE_WAIT_MS}"
            );
            Ok(Input::ReadScreen { grid, settle_ms })
        }
        other => bail!("unknown RDP action {other:?}"),
    }
}

impl Protocol for RdpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RDP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>RDP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rdp", "rdp client", "remote desktop", "mstsc", "3389"]
    }
    fn description(&self) -> &'static str {
        "RDP client: connects to a remote desktop (TLS or NLA), types, presses keys, clicks, and reads the screen back as colours"
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
            SCREEN_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let s = |name: &str, description: &str, example: Value, default: Option<Value>| {
            ParameterDefinition {
                name: name.into(),
                type_hint: if example.is_number() {
                    "number"
                } else {
                    "string"
                }
                .into(),
                description: description.into(),
                required: false,
                example,
                default,
            }
        };
        vec![
            s(
                "username",
                "Account to log on as",
                json!("alice"),
                None,
            ),
            s(
                "password",
                "That account's password. Under nla (the default) it is proven through CredSSP; only security tls sends the password itself, inside TLS to a server whose certificate is not verified",
                json!("s3cret"),
                None,
            ),
            s(
                "domain",
                "Windows domain, if the account has one",
                json!("CORP"),
                None,
            ),
            s(
                "security",
                "nla (default: CredSSP/NTLM proves the password without handing it over), tls (the password is sent in the Client Info PDU inside TLS; the server's certificate is not verified, so anyone able to intercept the connection receives it — use only on a trusted network, or with no password to reach a login screen), or any (offer both; while a password is set, a server that selects TLS-only is refused)",
                json!("nla"),
                Some(json!(DEFAULT_SECURITY)),
            ),
            s(
                "width",
                "Desktop width to ask for (200-4096)",
                json!(1280),
                Some(json!(DEFAULT_WIDTH)),
            ),
            s(
                "height",
                "Desktop height to ask for (200-4096)",
                json!(800),
                Some(json!(DEFAULT_HEIGHT)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("IronRDP (ironrdp-connector 0.10, ironrdp-session 0.11): X.224 negotiation, TLS upgrade (rustls, the server's certificate is not verified, as with mstsc's first-use prompt answered yes), CredSSP/NTLM for NLA, MCS/GCC, licensing, capability exchange and finalization, deactivation-reactivation, and fast-path and slow-path graphics decoded into a framebuffer. Input goes out as fast-path scancode, Unicode and mouse events through ironrdp-input")
            .llm_control("What to type, which keys to press, where to click, and when to look at the screen; the screen comes back as its size, most common colour and a grid of each cell's most common colour")
            .e2e_testing("tests/client/rdp: two independent servers — FreeRDP's shadow server (freerdp-shadow-cli3) sharing an Xvfb display, with NLA against an NTLM SAM file, where the model's clicks and keystrokes are read back from xev on that display and the screen colours are checked against xsetroot; and xrdp 0.9 with TLS, whose login screen colour is checked")
            .notes("No certificate verification and no Kerberos (NTLM only). security defaults to nla, so the password is proven through CredSSP; security tls sends it in the Client Info PDU to a server whose certificate is not verified, which an interceptor can read, and security any refuses a server selecting TLS-only while a password is set. A desktop size the server grants above 4096 pixels a side is refused, at connection and at reactivation. No clipboard, audio, drive or other virtual channels. The screen is described by colour, not text. Standard RDP security (RC4) is not offered.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the remote desktop at 10.0.0.5, open the Start menu and tell me what colour the screen is"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"RDP","remote_addr":"127.0.0.1:3389",
            "startup_params":{"username":"alice","password":"s3cret","security":"nla"},
            "instruction":"Once connected, read the screen and report its main colour"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"rdp_connected","handler":{"type":"static","actions":[read_screen_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0] = json!({"event_pattern":"rdp_connected","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'rdp_mouse','x':e['width']//2,'y':e['height']//2}]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Remote Access"
    }
}

impl Client for RdpClientProtocol {
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
