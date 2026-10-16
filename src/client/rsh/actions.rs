//! What the model does as an rsh, rexec or rlogin client: run a command and read what it
//! printed, or drive a terminal session.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::rsh::{actions::p, wire};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const RSH_RUN: &str = "rsh_run";
pub const REXEC_RUN: &str = "rexec_run";
pub const SEND_LINE: &str = "rlogin_send_line";
pub const SEND_TEXT: &str = "rlogin_send_text";
pub const SEND_KEY: &str = "rlogin_send_key";
pub const SET_WINDOW: &str = "rlogin_set_window";

/// The keys `rlogin_send_key` names, and the bytes a terminal in raw mode sends for each.
pub const KEYS: &[(&str, &[u8])] = &[
    ("enter", b"\r"),
    ("ctrl-c", b"\x03"),
    ("ctrl-d", b"\x04"),
    ("ctrl-z", b"\x1a"),
    ("ctrl-u", b"\x15"),
    ("escape", b"\x1b"),
    ("tab", b"\t"),
    ("backspace", b"\x7f"),
];

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
        log_template: Some(LogTemplate::new().with_info(format!("-> {name}"))),
    }
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this client.",
        vec![],
        json!({"type": "disconnect"}),
    )
}

fn run_action(name: &str, service: &str) -> ActionDefinition {
    action(
        name,
        &format!(
            "Run a command on the {service} server. Each command is its own connection; the \
             answer comes back as {service}_result with stdout, stderr and whether the server \
             accepted it."
        ),
        vec![
            p("command", "string", "The command line to run", true),
            p(
                "stdin",
                "string",
                "Text to give the command on standard input (it then sees end of input); \
                 without it the command's input is empty, as with rsh -n",
                false,
            ),
        ],
        json!({"type": name, "command": "uname -a"}),
    )
}

pub fn rsh_actions() -> Vec<ActionDefinition> {
    vec![run_action(RSH_RUN, "rsh"), disconnect_action()]
}

pub fn rexec_actions() -> Vec<ActionDefinition> {
    vec![run_action(REXEC_RUN, "rexec"), disconnect_action()]
}

pub fn rlogin_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            SEND_LINE,
            "Type a line and press Enter.",
            vec![p("line", "string", "What to type", true)],
            json!({"type": SEND_LINE, "line": "ls -l"}),
        ),
        action(
            SEND_TEXT,
            "Type text without pressing Enter (a password prompt answered by send_line is the \
             usual way; this is for partial input).",
            vec![p("text", "string", "What to type", true)],
            json!({"type": SEND_TEXT, "text": "y"}),
        ),
        action(
            SEND_KEY,
            "Press a key: enter, ctrl-c (interrupt), ctrl-d (end of input / logout), ctrl-z, \
             ctrl-u (erase the line), escape, tab or backspace.",
            vec![p("key", "string", "The key's name", true)],
            json!({"type": SEND_KEY, "key": "ctrl-c"}),
        ),
        action(
            SET_WINDOW,
            "Resize the terminal: the server is sent the new size, as a real rlogin does on \
             SIGWINCH (only once the server has asked for window sizes).",
            vec![
                p("rows", "number", "Rows", true),
                p("cols", "number", "Columns", true),
            ],
            json!({"type": SET_WINDOW, "rows": 40, "cols": 120}),
        ),
        disconnect_action(),
    ]
}

fn result_params(user_field: &str) -> Vec<Parameter> {
    vec![
        p("command", "string", "The command that ran", true),
        p(
            "accepted",
            "boolean",
            "Whether the server sent the go-ahead byte (\\0). false: it refused, see error",
            true,
        ),
        p(
            "error",
            "string",
            "The server's refusal line, or why no answer came",
            false,
        ),
        p("stdout", "string", "Standard output", true),
        p(
            "stderr",
            "string",
            "Standard error (from the second connection)",
            true,
        ),
        p(
            "truncated",
            "boolean",
            "Whether output past 1 MiB per stream was cut off",
            true,
        ),
        p(user_field, "string", "Who the command ran as", true),
        p(
            "source_port",
            "number",
            "The port this client connected from",
            true,
        ),
        p(
            "reserved_source_port",
            "boolean",
            "Whether that port is reserved (512-1023). A stock rshd refuses any other",
            true,
        ),
    ]
}

pub static RSH_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rsh_connected",
        "The rsh client is ready. rsh has one connection per command: run one with rsh_run.",
        json!({"type": RSH_RUN, "command": "uname -a"}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The rsh server", true),
        p(
            "local_user",
            "string",
            "The user name this client claims on its own host",
            true,
        ),
        p(
            "remote_user",
            "string",
            "The account commands run as on the server",
            true,
        ),
        p(
            "reserved_ports",
            "boolean",
            "Whether this process can bind reserved source ports. Without them a stock rshd \
             refuses every command",
            true,
        ),
    ])
    .with_actions(rsh_actions())
});

pub static RSH_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rsh_result",
        "The rsh server answered a command.",
        json!({"type": RSH_RUN, "command": "hostname"}),
    )
    .with_parameters(result_params("remote_user"))
    .with_actions(rsh_actions())
});

pub static REXEC_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rexec_connected",
        "The rexec client is ready. rexec has one connection per command: run one with \
         rexec_run (the configured user and password go with each).",
        json!({"type": REXEC_RUN, "command": "uname -a"}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The rexec server", true),
        p("user", "string", "The account commands run as", true),
    ])
    .with_actions(rexec_actions())
});

pub static REXEC_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rexec_result",
        "The rexec server answered a command.",
        json!({"type": REXEC_RUN, "command": "hostname"}),
    )
    .with_parameters(result_params("user"))
    .with_actions(rexec_actions())
});

pub static RLOGIN_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rlogin_connected",
        "The rlogin server accepted the handshake; the session is open. What it prints next \
         (a password prompt, a banner, a shell prompt) arrives as rlogin_output, so there is \
         usually nothing to do yet: answer with no actions.",
        json!({"type": SET_WINDOW, "rows": 24, "cols": 80}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The rlogin server", true),
        p(
            "remote_user",
            "string",
            "The account being logged into",
            true,
        ),
        p(
            "source_port",
            "number",
            "The port this client connected from",
            true,
        ),
        p(
            "reserved_source_port",
            "boolean",
            "Whether that port is reserved (512-1023); without one a stock rlogind refuses",
            true,
        ),
    ])
    .with_actions(rlogin_actions())
});

pub static RLOGIN_OUTPUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rlogin_output",
        "The rlogin server printed something (gathered until it paused). Answer by typing, or \
         with no actions to wait for more.",
        json!({"type": SEND_LINE, "line": "uptime"}),
    )
    .with_parameters(vec![
        p(
            "data",
            "string",
            "What the server printed (escape sequences removed)",
            true,
        ),
        p(
            "control",
            "array",
            "Urgent control bytes the server sent meanwhile: window_size_requested (answered \
             with the configured size), flush_output, flow_control_local, flow_control_remote",
            false,
        ),
        p(
            "closed",
            "boolean",
            "Whether the server has closed the session",
            true,
        ),
    ])
    .with_actions(rlogin_actions())
});

fn user_param(name: &str, description: &str) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "string".into(),
        description: description.into(),
        required: false,
        example: json!("alice"),
        default: None,
    }
}

fn stderr_param() -> ParameterDefinition {
    ParameterDefinition {
        name: "stderr".into(),
        type_hint: "boolean".into(),
        description: "Ask the server for a separate standard-error connection (it connects back \
                      to this host). Without it stderr arrives mixed into stdout"
            .into(),
        required: false,
        example: json!(true),
        default: Some(json!(true)),
    }
}

/// Validate a run action's fields, and return (command, stdin).
pub fn run_fields(v: &Value) -> Result<(String, Option<String>)> {
    let command = v["command"]
        .as_str()
        .context("command must be text")?
        .to_string();
    wire::check_field(&command, wire::MAX_COMMAND, "command")?;
    let stdin = match &v["stdin"] {
        Value::Null => None,
        Value::String(s) if s.len() <= crate::server::rsh::MAX_OUTPUT => Some(s.clone()),
        Value::String(_) => bail!("stdin is longer than 1 MiB"),
        _ => bail!("stdin must be text"),
    };
    Ok((command, stdin))
}

/// Bytes an rlogin action types, or `None` for one that sends nothing itself.
pub fn rlogin_bytes(v: &Value) -> Result<Option<Vec<u8>>> {
    match v["type"].as_str().unwrap_or_default() {
        SEND_LINE => {
            let line = v["line"].as_str().context("line must be text")?;
            anyhow::ensure!(
                line.len() <= wire::MAX_LINE_BYTES,
                "line is longer than 8 KiB"
            );
            let mut out = line.trim_end_matches(['\r', '\n']).as_bytes().to_vec();
            out.push(b'\r');
            Ok(Some(out))
        }
        SEND_TEXT => {
            let text = v["text"].as_str().context("text must be text")?;
            anyhow::ensure!(
                text.len() <= wire::MAX_LINE_BYTES,
                "text is longer than 8 KiB"
            );
            Ok(Some(text.as_bytes().to_vec()))
        }
        SEND_KEY => {
            let key = v["key"].as_str().context("key must be text")?;
            let bytes = KEYS
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, b)| b.to_vec())
                .with_context(|| {
                    format!(
                        "unknown key {key:?}: one of {}",
                        KEYS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    )
                })?;
            Ok(Some(bytes))
        }
        SET_WINDOW => {
            window_of(v)?;
            Ok(None)
        }
        other => bail!("Unknown rlogin action {other:?}"),
    }
}

/// The size a `rlogin_set_window` action names.
pub fn window_of(v: &Value) -> Result<wire::WindowSize> {
    let dim = |k: &str| -> Result<u16> {
        let n = v[k]
            .as_u64()
            .with_context(|| format!("{k} must be a number"))?;
        anyhow::ensure!((1..=9999).contains(&n), "{k} must be between 1 and 9999");
        Ok(n as u16)
    };
    Ok(wire::WindowSize {
        rows: dim("rows")?,
        cols: dim("cols")?,
        xpixel: 0,
        ypixel: 0,
    })
}

#[derive(Default, Clone)]
pub struct RshClientProtocol;
impl RshClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
#[derive(Default, Clone)]
pub struct RexecClientProtocol;
impl RexecClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
#[derive(Default, Clone)]
pub struct RloginClientProtocol;
impl RloginClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for RshClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RSH"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RSH"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rsh", "rshd", "rcmd", "bsd remote shell"]
    }
    fn description(&self) -> &'static str {
        "BSD rsh client: run commands on an rshd, which trusts the claimed user and a reserved \
         source port"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        rsh_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RSH_CONNECTED_EVENT.clone(), RSH_RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            user_param(
                "local_user",
                "The user name this client claims on its own host (rsh's first user field; \
                 the server's .rhosts must list it). Default: the user running NetGet",
            ),
            user_param(
                "remote_user",
                "The account to run commands as on the server. Default: local_user",
            ),
            stderr_param(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The rcmd handshake as a caller (src/server/rsh/wire.rs): a connection from a reserved source port when NetGet may bind one (1023 down to 512, as rresvport(3)), an ordinary port otherwise; a listener for the stderr connection (reserved too when possible) that accepts only the server's own address; all fields sent at once; the status byte and refusal line; stdout and stderr read together to EOF, each capped")
            .llm_control("Which commands to run, with what on standard input, and what to do with each result")
            .e2e_testing("tests/client/rsh: NetGet's own server for the handshake shapes and bounds, a test-owned listener for a refusal and a missing stderr connection; inetutils rshd and rsh-redone's rshd under a one-line inetd in real_server_test.rs (Linux, as root)")
            .notes(concat!("Experimental: two server families (inetutils and rsh-redone), on Linux as root only, and the pair job had not run in CI when it landed. A stock rshd refuses a connection from an ordinary source port, so unprivileged NetGet (on Linux) is refused; the connected event says whether reserved ports are available and each result names the port used. One command per connection; a command waits at most 60 s; output is capped at 1 MiB per stream; a handler chain stops after 8 follow-ups. ", crate::r_services_security!()))
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rsh to 10.0.0.5 as alice and report uname -a and uptime"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "rsh", "remote_addr": "127.0.0.1:514",
            "startup_params": {"local_user": "alice", "remote_user": "alice"},
            "instruction": "Run uname -a, then uptime, and report both"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern": "rsh_connected", "handler": {"type": "static", "actions": [{"type": RSH_RUN, "command": "uname -a"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\na=[{'type':'rsh_run','command':'hostname'}] if i['event_type_id']=='rsh_connected' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for RshClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect_exec(ctx, super::Service::Rsh))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        execute_run(v, RSH_RUN)
    }
}

fn execute_run(v: Value, run: &str) -> Result<ClientActionResult> {
    let name = v["type"].as_str().unwrap_or_default().to_string();
    if name == "disconnect" {
        return Ok(ClientActionResult::Disconnect);
    }
    anyhow::ensure!(
        name == run,
        "Unknown action {name:?}: this client runs {run}"
    );
    run_fields(&v)?;
    Ok(ClientActionResult::Custom { name, data: v })
}

impl Protocol for RexecClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "REXEC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>REXEC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rexec", "rexecd", "bsd remote execution"]
    }
    fn description(&self) -> &'static str {
        "BSD rexec client: run commands on an rexecd with a user name and password"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        rexec_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REXEC_CONNECTED_EVENT.clone(), REXEC_RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "The account to log in as".into(),
                required: true,
                example: json!("alice"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "Its password. rexec sends it in clear text with every command; \
                              the model never sees it"
                    .into(),
                required: true,
                example: json!("wonderland"),
                default: None,
            },
            stderr_param(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The rexec handshake as a caller (src/server/rsh/wire.rs): a listener for the stderr connection that accepts only the server's own address, the stderr port, user, password and command sent at once, the status byte and refusal line, stdout and stderr read together to EOF, each capped. The password comes from the startup parameters and is never part of an action or event")
            .llm_control("Which commands to run, with what on standard input, and what to do with each result")
            .e2e_testing("tests/client/rsh: NetGet's own rexec server for the handshake and password refusal, bounds and the stderr connection; inetutils rexecd under a one-line inetd in real_server_test.rs (Linux, as root)")
            .notes(concat!("Experimental: one server family (inetutils rexecd; no other is packaged), on Linux as root only, and the pair job had not run in CI when it landed. One command per connection; a command waits at most 60 s; output is capped at 1 MiB per stream; a handler chain stops after 8 follow-ups. ", crate::r_services_security!()))
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rexec to 10.0.0.5 as alice with password wonderland and report df -h"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "rexec", "remote_addr": "127.0.0.1:512",
            "startup_params": {"user": "alice", "password": "wonderland"},
            "instruction": "Run df -h and report it"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern": "rexec_connected", "handler": {"type": "static", "actions": [{"type": REXEC_RUN, "command": "df -h"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\na=[{'type':'rexec_run','command':'id'}] if i['event_type_id']=='rexec_connected' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for RexecClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect_exec(ctx, super::Service::Rexec))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        execute_run(v, REXEC_RUN)
    }
}

impl Protocol for RloginClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RLOGIN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RLOGIN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rlogin", "rlogind", "bsd remote login"]
    }
    fn description(&self) -> &'static str {
        "BSD rlogin client: an interactive terminal session on an rlogind, driven by the model"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        rlogin_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RLOGIN_CONNECTED_EVENT.clone(), RLOGIN_OUTPUT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            user_param(
                "local_user",
                "The user name this client claims on its own host. Default: the user running \
                 NetGet",
            ),
            user_param(
                "remote_user",
                "The account to log into. Default: local_user",
            ),
            ParameterDefinition {
                name: "terminal".into(),
                type_hint: "string".into(),
                description: "The terminal type sent to the server".into(),
                required: false,
                example: json!("xterm"),
                default: Some(json!(super::DEFAULT_TERMINAL)),
            },
            ParameterDefinition {
                name: "speed".into(),
                type_hint: "number".into(),
                description: "The terminal speed sent to the server".into(),
                required: false,
                example: json!(38400),
                default: Some(json!(super::DEFAULT_SPEED)),
            },
            ParameterDefinition {
                name: "rows".into(),
                type_hint: "number".into(),
                description: "Terminal rows, sent when the server asks for the window size".into(),
                required: false,
                example: json!(24),
                default: Some(json!(super::DEFAULT_WINDOW.rows)),
            },
            ParameterDefinition {
                name: "cols".into(),
                type_hint: "number".into(),
                description: "Terminal columns".into(),
                required: false,
                example: json!(80),
                default: Some(json!(super::DEFAULT_WINDOW.cols)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The rlogin handshake as a caller (src/server/rsh/wire.rs): a reserved source port when NetGet may bind one, the empty stderr field, local user, remote user and terminal/speed, the status byte; then keystrokes out (Enter is CR) and output in, gathered until the server pauses; urgent bytes read out of band (TIOCPKT_WINDOW answered with the window-size message)")
            .llm_control("What to type and when, keys such as ^C and ^D, the window size, when to leave")
            .e2e_testing("tests/client/rsh: NetGet's own rlogin server for the handshake, password prompt, window size and line editing; inetutils rlogind and rsh-redone's rlogind under a one-line inetd in real_server_test.rs (Linux, as root)")
            .notes(concat!("Experimental: two server families (inetutils and rsh-redone), on Linux as root only, and the pair job had not run in CI when it landed. A stock rlogind refuses an ordinary source port. Output is raised to the model after 300 ms of quiet or 16 KiB, escape sequences removed; a session's handler chain stops after 32 model turns without an operator's input. ", crate::r_services_security!()))
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rlogin to 10.0.0.5 as alice, run w, then log out"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "rlogin", "remote_addr": "127.0.0.1:513",
            "startup_params": {"local_user": "alice", "remote_user": "alice"},
            "instruction": "Log in, run w, report who is logged in, then log out with exit"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern": "rlogin_output", "handler": {"type": "static", "actions": [{"type": SEND_LINE, "line": "exit"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']\na=[{'type':'rlogin_send_line','line':'exit'}] if i['event_type_id']=='rlogin_output' and e['data'].rstrip().endswith('$') else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for RloginClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::rlogin::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        match rlogin_bytes(&v)? {
            Some(bytes) => Ok(ClientActionResult::SendData(bytes)),
            None => Ok(ClientActionResult::Custom { name, data: v }),
        }
    }
}
