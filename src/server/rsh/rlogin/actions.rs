//! What the model decides as an rlogin server: whether a login is trusted, needs a password or
//! is refused, then everything the session prints. NetGet checks a password itself, echoes
//! keystrokes, edits lines and handles the window-size and urgent-data control.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::server::rsh::{actions::p, wire};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const TRUST: &str = "rlogin_trust";
pub const ASK_PASSWORD: &str = "rlogin_ask_password";
pub const REFUSE: &str = "rlogin_refuse";
pub const SEND_LINE: &str = "rlogin_send_line";
pub const SEND_TEXT: &str = "rlogin_send_text";
pub const SET_ECHO: &str = "rlogin_set_echo";

fn banner() -> crate::llm::actions::Parameter {
    p(
        "banner",
        "string",
        "Text shown when the session starts (after the password, if one is asked): a motd, \
         a last-login line. Newlines are sent as CRLF",
        false,
    )
}
fn prompt() -> crate::llm::actions::Parameter {
    p(
        "prompt",
        "string",
        "The shell prompt to print after the banner, e.g. \"alice@files:~$ \"",
        false,
    )
}

pub fn trust_action() -> ActionDefinition {
    ActionDefinition {
        name: TRUST.into(),
        description: "Trust the login, as rlogind does when hosts.equiv or the server user's \
                      .rhosts lists the client user and host: no password, the session \
                      starts at once."
            .into(),
        parameters: vec![banner(), prompt()],
        example: json!({"type": TRUST, "banner": "Last login: Fri Oct 16 09:12 from gateway\n", "prompt": "alice@files:~$ "}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin trusted")),
    }
}

pub fn ask_password_action() -> ActionDefinition {
    ActionDefinition {
        name: ASK_PASSWORD.into(),
        description: "Not trusted: ask for the server user's password, as rlogind does when \
                      no .rhosts entry matches. NetGet prompts (echo off) and checks the answer \
                      against its configured accounts itself — you never see it — allowing three \
                      tries; then the banner and prompt are shown."
            .into(),
        parameters: vec![
            banner(),
            prompt(),
            p(
                "password_prompt",
                "string",
                "The password prompt (default \"Password: \")",
                false,
            ),
        ],
        example: json!({"type": ASK_PASSWORD, "prompt": "$ "}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin password required")),
    }
}

pub fn refuse_action() -> ActionDefinition {
    ActionDefinition {
        name: REFUSE.into(),
        description: "Refuse the login outright (no such user, root not allowed): the client \
                      prints this line and the connection closes."
            .into(),
        parameters: vec![p(
            "message",
            "string",
            "The line the client prints (default \"Permission denied.\")",
            false,
        )],
        example: json!({"type": REFUSE, "message": "rlogind: Permission denied."}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin refused")),
    }
}

pub fn send_line_action() -> ActionDefinition {
    ActionDefinition {
        name: SEND_LINE.into(),
        description: "Print a line on the client's terminal (CRLF added).".into(),
        parameters: vec![p("line", "string", "The text of the line", true)],
        example: json!({"type": SEND_LINE, "line": "Linux files 6.8.0 x86_64"}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin: {preview(line,60)}")),
    }
}

pub fn send_text_action() -> ActionDefinition {
    ActionDefinition {
        name: SEND_TEXT.into(),
        description: "Print text exactly where the cursor is, with no line ending added: \
                      command output followed by the next prompt, or a prompt alone. \
                      Newlines are sent as CRLF."
            .into(),
        parameters: vec![p(
            "text",
            "string",
            "The text to print on the client's terminal",
            true,
        )],
        example: json!({"type": SEND_TEXT, "text": "total 0\nalice@files:~$ "}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin: {preview(text,60)}")),
    }
}

pub fn set_echo_action() -> ActionDefinition {
    ActionDefinition {
        name: SET_ECHO.into(),
        description: "Turn the echo of what the user types off (before asking for a secret) or \
                      back on. NetGet does the echoing; the client's terminal shows nothing \
                      of its own."
            .into(),
        parameters: vec![p("echo", "boolean", "true to echo keystrokes", true)],
        example: json!({"type": SET_ECHO, "echo": false}),
        log_template: Some(LogTemplate::new().with_info("-> rlogin echo {echo}")),
    }
}

pub fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".into(),
        description: "Print nothing and wait for the next line.".into(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(LogTemplate::new().with_info("rlogin waiting")),
    }
}

pub fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".into(),
        description: "End the session (after anything printed in the same answer), as a shell \
                      does on exit or logout."
            .into(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(LogTemplate::new().with_info("rlogin session closed")),
    }
}

fn session_actions() -> Vec<ActionDefinition> {
    vec![
        send_line_action(),
        send_text_action(),
        set_echo_action(),
        wait_for_more_action(),
        close_connection_action(),
    ]
}

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rlogin_login",
        "An rlogin client asks for a terminal session as server_user, claiming to be \
         client_user on its host. A real rlogind trusts the pair when hosts.equiv or \
         server_user's .rhosts lists it (and only from a reserved source port, 512-1023, that \
         only root on the client could bind); otherwise it asks for the password. Answer \
         rlogin_trust, rlogin_ask_password or rlogin_refuse.",
        trust_action().example,
    )
    .with_parameters(vec![
        p("client_user", "string", "The user on the client host", true),
        p(
            "server_user",
            "string",
            "The account the session is to log into",
            true,
        ),
        p(
            "terminal",
            "string",
            "The client's terminal type, e.g. xterm",
            true,
        ),
        p(
            "speed",
            "number",
            "The terminal speed the client sent, if any",
            false,
        ),
        p(
            "client_address",
            "string",
            "The IP address the connection came from",
            true,
        ),
        p("client_port", "number", "The client's source port", true),
        p(
            "reserved_source_port",
            "boolean",
            "Whether client_port is reserved (512-1023); a stock rlogind refuses anything else",
            true,
        ),
    ])
    .with_actions(vec![trust_action(), ask_password_action(), refuse_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("rlogin login {client_user}@{client_address} as {server_user} ({terminal})"),
    )
});

pub static LINE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rlogin_line",
        "The user typed a line in the rlogin session and pressed Enter (NetGet already echoed \
         it). Answer as the remote host would: the command's output and the next prompt. \
         interrupt is true when they pressed ^C instead (the line was discarded). Nothing \
         earlier in the session is repeated here: keep what later lines need in memory.",
        send_text_action().example,
    )
    .with_parameters(vec![
        p("line", "string", "The line, without its line ending", true),
        p("user", "string", "The account logged in", true),
        p("terminal", "string", "The client's terminal type", true),
        p(
            "window",
            "object",
            "The terminal size the client last reported, {rows, cols}, if it has",
            false,
        ),
        p(
            "interrupt",
            "boolean",
            "true when this is a ^C, not a line",
            true,
        ),
    ])
    .with_actions(session_actions())
    .with_log_template(LogTemplate::new().with_info("rlogin {user}: {preview(line,80)}"))
});

#[derive(Default, Clone)]
pub struct RloginProtocol;
impl RloginProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn text_field(action: &Value, key: &str, max: usize) -> Result<Option<String>> {
    match &action[key] {
        Value::Null => Ok(None),
        Value::String(s) if s.len() <= max => Ok(Some(s.clone())),
        Value::String(_) => bail!("{key} is longer than {max} bytes"),
        _ => bail!("{key} must be text"),
    }
}

impl Protocol for RloginProtocol {
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
        "BSD rlogin server (rlogind, TCP 513): the model decides trust (rhosts-style), a \
         password NetGet checks, or refusal, then plays the remote host's interactive session"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut all = vec![trust_action(), ask_password_action(), refuse_action()];
        all.extend(session_actions());
        all
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOGIN_EVENT.clone(), LINE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![crate::server::rsh::actions::accounts_param()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(513))
            .well_known_port(513)
            .implementation("Hand-written rlogin (src/server/rsh/wire.rs, src/server/rsh/rlogin/): the rcmd handshake (an empty stderr port, client user, server user, terminal/speed, each NUL-terminated and capped), the \\0 / \\1 status byte, the urgent TIOCPKT_WINDOW request after login and TIOCPKT_FLUSHWRITE on ^C, the in-band window-size message (FF FF 's' 's' + rows, cols, x and y pixels) parsed across reads, and a line editor standing in for the pty: echo (off for passwords), DEL/BS, ^U, ^C, ^D, CR/CRLF/CR-NUL line ends; passwords checked against the accounts startup parameter")
            .llm_control("Whether a login is trusted, needs a password or is refused, the banner and prompt, and every line of the session: what each command prints, echo on or off, when to close")
            .e2e_testing("tests/server/rsh: raw-socket rlogin handshakes, the password path, window-size messages split across reads, line editing, bounds, fail-closed paths and the pcap oracle (tshark's rlogin dissector) in e2e_test.rs; the real clients through a pty in real_client_test.rs (Linux, as root): inetutils rlogin and rsh-redone's rlogin")
            .notes(concat!("Experimental: two client families (inetutils and rsh-redone), exercised only as root on Linux, and the pair job had not run in CI when it landed. NetGet does not refuse a non-reserved source port, it reports it. A model that fails at login is refused with \\1 and a fixed line; one that fails mid-session prints a one-line notice and the session stays open; a wrong password three times closes it. No pty: line editing is NetGet's, so full-screen programs cannot be played. Bounds: handshake fields ≤ 256 bytes (terminal ≤ 64) within 60 s, lines ≤ 8 KiB, 300 s for the first line and 600 s between lines, ≤ 256 connections. ", crate::r_services_security!()))
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_LINE_BYTES)
            // rlogin is an interactive login: each line is read against the session so far.
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rlogin server on port 513 that trusts alice and plays a small Linux shell"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "rlogin", "port": 513,
            "startup_params": {"accounts": [{"user": "bob", "password": "builder"}]},
            "instruction": "Trust alice without a password, ask everyone else for one. Play a Linux shell on host files with prompt user@files:~$ ."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "rlogin_login", "handler": {"type": "static", "actions": [{"type": ASK_PASSWORD, "prompt": "$ "}]}},
            {"event_pattern": "rlogin_line", "handler": {"type": "static", "actions": [{"type": SEND_TEXT, "text": "command not found\n$ "}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']\nif i['event_type_id']=='rlogin_login':\n  a=[{'type':'rlogin_trust','prompt':'$ '}] if e['client_user']=='alice' else [{'type':'rlogin_ask_password','prompt':'$ '}]\nelif e['line'] in ('exit','logout'):\n  a=[{'type':'rlogin_send_line','line':'logout'},{'type':'close_connection'}]\nelse:\n  a=[{'type':'rlogin_send_text','text':'you typed '+e['line']+'\\n$ '}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for RloginProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let accounts = crate::server::rsh::parse_accounts(&ctx)?;
            crate::server::rsh::serve(ctx, "RLOGIN", move |conn| {
                super::session(conn, accounts.clone())
            })
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let name = action["type"]
            .as_str()
            .context("Missing 'type' field in action")?
            .to_string();
        match name.as_str() {
            TRUST | ASK_PASSWORD => {
                text_field(&action, "banner", super::MAX_BANNER)?;
                text_field(&action, "prompt", wire::MAX_LINE_BYTES)?;
                text_field(&action, "password_prompt", wire::MAX_LINE_BYTES)?;
                Ok(ActionResult::Custom { name, data: action })
            }
            REFUSE => {
                text_field(&action, "message", wire::MAX_ERROR_LINE * 4)?;
                Ok(ActionResult::Custom { name, data: action })
            }
            SEND_LINE => {
                let line = text_field(&action, "line", super::MAX_BANNER)?
                    .context("Missing 'line' parameter")?;
                let mut out = wire::crlf(line.trim_end_matches(['\r', '\n']));
                out.extend_from_slice(b"\r\n");
                Ok(ActionResult::Output(out))
            }
            SEND_TEXT => {
                let text = text_field(&action, "text", super::MAX_BANNER)?
                    .context("Missing 'text' parameter")?;
                Ok(ActionResult::Output(wire::crlf(&text)))
            }
            SET_ECHO => {
                action["echo"]
                    .as_bool()
                    .context("echo must be true or false")?;
                Ok(ActionResult::Custom { name, data: action })
            }
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            other => bail!("Unknown rlogin action: {other}"),
        }
    }
}
