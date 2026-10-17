//! What the model decides as an rsh or rexec server: whether an rsh request is trusted, and
//! what each command prints. rexec's password is checked in Rust before the model is asked.
use super::{wire, ExecService};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};

pub const RSH_OUTPUT: &str = "rsh_output";
pub const RSH_REFUSE: &str = "rsh_refuse";
pub const REXEC_OUTPUT: &str = "rexec_output";
pub const REXEC_REFUSE: &str = "rexec_refuse";

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn output_action(name: &str, service: &str) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: format!(
            "Run the command: answer with what it prints. NetGet sends the go-ahead byte, \
             writes stdout on the connection and stderr on the client's stderr connection (or \
             after stdout when it asked for none), then closes. {service} carries no exit \
             status: a failing command is one that prints its error on stderr."
        ),
        parameters: vec![
            p(
                "stdout",
                "string",
                "What the command writes to standard output, with its newlines (at most 1 MiB)",
                false,
            ),
            p(
                "stderr",
                "string",
                "What it writes to standard error (at most 1 MiB)",
                false,
            ),
        ],
        example: json!({"type": name, "stdout": "Linux files 6.8.0 x86_64\n", "stderr": ""}),
        log_template: Some(LogTemplate::new().with_info(format!("-> {service} output"))),
    }
}

fn refuse_action(name: &str, service: &str, default: &str) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: format!(
            "Refuse the request: nothing runs. The client gets the error byte and this one \
             line, as {service}d sends it."
        ),
        parameters: vec![p(
            "message",
            "string",
            &format!("The line the client prints (default \"{default}\")"),
            false,
        )],
        example: json!({"type": name, "message": default}),
        log_template: Some(LogTemplate::new().with_info(format!("-> {service} refused"))),
    }
}

pub fn rsh_output_action() -> ActionDefinition {
    output_action(RSH_OUTPUT, "rsh")
}
pub fn rsh_refuse_action() -> ActionDefinition {
    refuse_action(RSH_REFUSE, "rsh", "Permission denied.")
}
pub fn rexec_output_action() -> ActionDefinition {
    output_action(REXEC_OUTPUT, "rexec")
}
pub fn rexec_refuse_action() -> ActionDefinition {
    refuse_action(REXEC_REFUSE, "rexec", "Permission denied.")
}

fn client_address() -> Parameter {
    p(
        "client_address",
        "string",
        "The IP address the request came from",
        true,
    )
}
fn client_port() -> Parameter {
    p("client_port", "number", "The client's source port", true)
}
fn stderr_channel() -> Parameter {
    p(
        "stderr_channel",
        "boolean",
        "Whether the client asked for a separate standard-error connection (NetGet has already \
         opened it, to the client's own address)",
        true,
    )
}
fn command() -> Parameter {
    p(
        "command",
        "string",
        "The command line, as the client's user typed it",
        true,
    )
}

pub static RSH_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rsh_command",
        "An rsh client asks to run a command as server_user, claiming to be client_user on its \
         host. rsh has no password: a real rshd trusts the request when the pair is listed in \
         hosts.equiv or server_user's .rhosts, and only from a reserved source port (512-1023) \
         that only root on the client could bind. Decide whether this request is trusted; if \
         it is, answer rsh_output with what the command prints, otherwise rsh_refuse.",
        rsh_output_action().example,
    )
    .with_parameters(vec![
        p(
            "client_user",
            "string",
            "The user on the client host who is asking (rsh's first user field)",
            true,
        ),
        p(
            "server_user",
            "string",
            "The account on this server the command is to run as",
            true,
        ),
        command(),
        client_address(),
        client_port(),
        p(
            "reserved_source_port",
            "boolean",
            "Whether client_port is reserved (512-1023). A stock rshd refuses anything else; \
             an unprivileged client cannot bind one",
            true,
        ),
        stderr_channel(),
    ])
    .with_actions(vec![rsh_output_action(), rsh_refuse_action()])
    .with_log_template(
        LogTemplate::new().with_info(
            "rsh {client_user}@{client_address} as {server_user}: {preview(command,80)}",
        ),
    )
});

pub static REXEC_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rexec_command",
        "An rexec client logged in as user (NetGet checked the password against its configured \
         accounts before asking you) and asks to run a command. Answer rexec_output with what \
         the command prints, or rexec_refuse.",
        rexec_output_action().example,
    )
    .with_parameters(vec![
        p(
            "user",
            "string",
            "The account the client logged in as",
            true,
        ),
        command(),
        client_address(),
        client_port(),
        stderr_channel(),
    ])
    .with_actions(vec![rexec_output_action(), rexec_refuse_action()])
    .with_log_template(
        LogTemplate::new().with_info("rexec {user}@{client_address}: {preview(command,80)}"),
    )
});

/// The shape of an answer.
pub fn check(v: &Value) -> Result<()> {
    let t = v["type"].as_str().unwrap_or_default();
    match t {
        RSH_OUTPUT | REXEC_OUTPUT => {
            for stream in ["stdout", "stderr"] {
                match &v[stream] {
                    Value::Null => {}
                    Value::String(s) => ensure!(
                        s.len() <= super::MAX_OUTPUT,
                        "{stream} is longer than {} bytes",
                        super::MAX_OUTPUT
                    ),
                    _ => bail!("{stream} must be text"),
                }
            }
        }
        RSH_REFUSE | REXEC_REFUSE => match &v["message"] {
            Value::Null | Value::String(_) => {}
            _ => bail!("message must be text"),
        },
        other => bail!("Unknown r-service action {other:?}"),
    }
    Ok(())
}

fn custom(action: Value, allowed: [&str; 2]) -> Result<ActionResult> {
    let name = action["type"].as_str().unwrap_or_default().to_string();
    ensure!(
        allowed.contains(&name.as_str()),
        "Unknown action {name:?}: this server answers {} or {}",
        allowed[0],
        allowed[1]
    );
    check(&action)?;
    Ok(ActionResult::Custom { name, data: action })
}

pub fn accounts_param() -> ParameterDefinition {
    ParameterDefinition {
        name: "accounts".into(),
        type_hint: "array".into(),
        description: "The accounts whose passwords this server accepts, as [{\"user\": …, \
                      \"password\": …}]. Checked by NetGet; the model never sees a password. \
                      With none, every login is refused. The r-services send passwords in clear \
                      text: use throwaway ones."
            .into(),
        required: false,
        example: json!([{"user": "alice", "password": "wonderland"}]),
        default: None,
    }
}

/// The security note every r-service's metadata ends with, server and client.
#[macro_export]
macro_rules! r_services_security {
    () => {
        "SECURITY: the r-services predate any notion of a hostile network. rexec and rlogin \
         send passwords in clear text; rsh and rlogin trust the client's word about who it is, \
         backed only by its address and a reserved source port. NetGet implements them as they \
         are, to study and mock, not to make them safe"
    };
}

#[derive(Default, Clone)]
pub struct RshProtocol;
impl RshProtocol {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Default, Clone)]
pub struct RexecProtocol;
impl RexecProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for RshProtocol {
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
        "BSD rsh server (rshd, TCP 514): the model decides whether each client/server user pair \
         is trusted, rhosts-style, and what the command prints"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![rsh_output_action(), rsh_refuse_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RSH_COMMAND_EVENT.clone()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(514))
            .well_known_port(514)
            .implementation("Hand-written rcmd handshake (src/server/rsh/wire.rs): the stderr port field (decimal, at most 5 digits), the connection back to the client's own address on that port (from a reserved port when NetGet may bind one, as rcmd(3) requires), client user, server user and command, each NUL-terminated and capped; the \\0 / \\1 status byte; stdout on the main connection and stderr on the second (or the main one when the client asked for none); half-close and drain before closing")
            .llm_control("Whether the request is trusted (the client and server user names, the client's address and source port, and whether that port is reserved, are all in the event) and everything the command prints")
            .e2e_testing("tests/server/rsh: raw-socket handshakes for every bound and refusal, the stderr connection's target and content, fail-closed paths and the pcap oracle (tshark's rsh dissector) in e2e_test.rs; the real clients in real_client_test.rs (Linux, as root): inetutils rsh and rsh-redone's rsh")
            .notes(concat!("Experimental: two client families (inetutils and rsh-redone), exercised only as root on Linux, and the pair job had not run in CI when it landed. The model applies the rhosts check itself; NetGet does not refuse a non-reserved source port, it reports it. A model that fails or answers nothing is refused with \\1 and a fixed line — the command never runs as if trusted. No exit status exists in rsh, and stdin is not read: a command answers from its command line. Bounds: user names ≤ 256 bytes, command ≤ 64 KiB, handshake within 60 s, ≤ 256 connections, output ≤ 1 MiB per stream. ", crate::r_services_security!()))
            .answers_on_failure()
            .request_only("Every rsh connection carries exactly one command and its answer")
            .max_inbound_bytes(wire::MAX_HANDSHAKE)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rsh server on port 514 that trusts alice from any host and answers uname, hostname and uptime like a small Linux box"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "rsh", "port": 514,
            "instruction": "Trust client user alice running as server user alice, refuse everyone else with Permission denied. Answer commands like a Linux host named files."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern": "rsh_command", "handler": {"type": "static", "actions": [{"type": RSH_REFUSE, "message": "Permission denied."}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "rsh_command", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nif e['client_user']=='alice' and e['server_user']=='alice':\n  a=[{'type':'rsh_output','stdout':'you ran: '+e['command']+'\\n'}]\nelse:\n  a=[{'type':'rsh_refuse','message':'Permission denied.'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for RshProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let accounts = Arc::new(Vec::new());
            super::serve(ctx, "RSH", move |conn| {
                super::exec_connection(
                    conn,
                    ExecService::Rsh,
                    Arc::new(RshProtocol),
                    accounts.clone(),
                )
            })
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        custom(action, [RSH_OUTPUT, RSH_REFUSE])
    }
}

impl Protocol for RexecProtocol {
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
        "BSD rexec server (rexecd, TCP 512): NetGet checks the user and password against \
         configured accounts, then the model answers the command"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![rexec_output_action(), rexec_refuse_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REXEC_COMMAND_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![accounts_param()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(512))
            .well_known_port(512)
            .implementation("Hand-written rexec handshake (src/server/rsh/wire.rs): the stderr port field, the connection back to the client's own address, user, password and command, each NUL-terminated and capped; the password compared in Rust against the accounts startup parameter (every account compared, without an early exit); the \\0 / \\1 status byte; stdout and stderr; half-close and drain before closing")
            .llm_control("What each command prints, and whether to refuse it. Authentication is NetGet's: the model is asked only after the password matched, and never sees it")
            .e2e_testing("tests/server/rsh: raw-socket handshakes for the password check, every bound, the stderr connection and fail-closed paths, and the pcap oracle (tshark's exec dissector) in e2e_test.rs; inetutils rexec in real_client_test.rs (on macOS too, where Homebrew installs it as grexec)")
            .notes(concat!("Experimental: one client family (inetutils rexec; no other rexec client is packaged for Linux or macOS), and the pair job had not run in CI when it landed. A wrong user or password and a server with no accounts both answer \\1 Login incorrect. without asking the model; a model that fails or answers nothing is refused with \\1 and a fixed line. No exit status exists in rexec, and stdin is not read. Bounds: user and password ≤ 256 bytes, command ≤ 64 KiB, handshake within 60 s, ≤ 256 connections, output ≤ 1 MiB per stream. ", crate::r_services_security!()))
            .answers_on_failure()
            .request_only("Every rexec connection carries exactly one command and its answer")
            .max_inbound_bytes(wire::MAX_HANDSHAKE)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "rexec server on port 512 with account alice / wonderland that answers commands like a small Linux box"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "rexec", "port": 512,
            "startup_params": {"accounts": [{"user": "alice", "password": "wonderland"}]},
            "instruction": "Answer commands like a Linux host named files; refuse rm."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern": "rexec_command", "handler": {"type": "static", "actions": [{"type": REXEC_OUTPUT, "stdout": "ok\n"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "rexec_command", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nif e['command'].startswith('rm'):\n  a=[{'type':'rexec_refuse','message':'Permission denied.'}]\nelse:\n  a=[{'type':'rexec_output','stdout':e['user']+' ran '+e['command']+'\\n'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for RexecProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let accounts = super::parse_accounts(&ctx)?;
            super::serve(ctx, "REXEC", move |conn| {
                super::exec_connection(
                    conn,
                    ExecService::Rexec,
                    Arc::new(RexecProtocol),
                    accounts.clone(),
                )
            })
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        custom(action, [REXEC_OUTPUT, REXEC_REFUSE])
    }
}
