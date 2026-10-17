//! Reverse-shell listener actions.
//!
//! This protocol *emulates* the operator side of a reverse shell for authorized security
//! testing, CTF and lab work: NetGet is the listener an operator connects back to, and the LLM
//! plays the role of the shell on the far end, deciding what each command "prints". **NetGet
//! never executes the operator's commands on this host** — the model supplies the pretend
//! output, which is the whole NetGet premise and also the safe default. See
//! `src/server/reverse_shell/CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Reverse-shell listener protocol handler.
///
/// Stateless: it only describes actions/events and executes sync actions. The running listener
/// lives in [`crate::server::reverse_shell::ReverseShellServer`].
#[derive(Default)]
pub struct ReverseShellProtocol;

impl ReverseShellProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for ReverseShellProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // No startup parameters: the banner, the prompt and every command's output are decided
        // by the model per event, so declaring anything here would be a dead parameter the
        // model would try to use.
        Vec::new()
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions: the server keeps no addressable connection registry, so an
        // async action would have nothing to talk to. Declaring one would be a promise the code
        // does not keep.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_shell_output_action(),
            send_shell_prompt_action(),
            end_shell_session_action(),
            no_shell_output_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Reverse Shell"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_reverse_shell_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>REVSHELL"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately multi-word / distinctive: never a bare "shell" or "remote", which would
        // collide with SSH and the Bluetooth "remote" profile.
        vec![
            "reverse_shell",
            "reverse shell",
            "revshell",
            "reverse-shell listener",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Raw TCP listener; line-buffered operator input; the model role-plays the shell",
            )
            .llm_control(
                "Shell banner, per-command output, the prompt, and when to end the session",
            )
            .e2e_testing("Raw TCP client (nc/socat equivalent) asserting model-supplied output")
            .notes(
                "Emulation only for authorized red-team/CTF/lab use: NetGet NEVER runs the \
                 operator's commands on this host, the model supplies fictional output. Real \
                 command execution is available only through the separate, opt-in, unsandboxed \
                 scripting layer (see CLAUDE.md). Verified with a raw TCP client; no framing, so \
                 nc/socat connect directly.",
            )
            .max_inbound_bytes(crate::server::reverse_shell::MAX_LINE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Reverse-shell listener emulation (red-team/CTF): the model role-plays the shell"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a reverse-shell listener on port 4444 emulating a compromised Ubuntu box for a CTF"
    }

    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: emulate a minimal shell — answer every command with a
        // canned line and a fresh prompt, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "reverse_shell_command":
    actions = [{"type": "send_shell_output", "output": "command not found\n",
                "append_prompt": True, "prompt": "$ "}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 4444,
                "base_stack": "reverse-shell",
                "instruction": "Emulate a shell on a compromised Ubuntu host for a CTF lab"
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 4444,
                "base_stack": "reverse-shell",
                "event_handlers": [{
                    "event_pattern": "reverse_shell_command",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 4444,
                "base_stack": "reverse-shell",
                "event_handlers": [
                    {
                        "event_pattern": "reverse_shell_session_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_shell_prompt",
                                "prompt": "www-data@web01:/var/www$ "
                            }]
                        }
                    },
                    {
                        "event_pattern": "reverse_shell_command",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_shell_output",
                                "output": "bash: command not found\n",
                                "append_prompt": true,
                                "prompt": "www-data@web01:/var/www$ "
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for ReverseShellProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Validate that no undeclared startup parameter was supplied.
            if let Some(params) = ctx.startup_params.as_ref() {
                // No parameters are declared; construction already rejected unknown keys, but
                // touch it so an accidental future param is not silently ignored.
                let _ = params.allowed_parameters();
            }

            use crate::server::reverse_shell::ReverseShellServer;
            let listen_addr = ctx.legacy_listen_addr();
            ReverseShellServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_shell_output" => {
                let output = action
                    .get("output")
                    .and_then(|v| v.as_str())
                    .context("Missing 'output' parameter")?;

                let mut bytes = output.as_bytes().to_vec();

                // Optional trailing prompt, so one action can print output and re-prompt.
                let append_prompt = action
                    .get("append_prompt")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if append_prompt {
                    let prompt = action
                        .get("prompt")
                        .and_then(|v| v.as_str())
                        .unwrap_or(DEFAULT_PROMPT);
                    bytes.extend_from_slice(prompt.as_bytes());
                }
                Ok(ActionResult::Output(bytes))
            }
            "send_shell_prompt" => {
                let prompt = action
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_PROMPT);
                Ok(ActionResult::Output(prompt.as_bytes().to_vec()))
            }
            "end_shell_session" => Ok(ActionResult::CloseConnection),
            // Injected by the dashboard's [ disconnect this peer ] row (not an LLM verb).
            // Without this arm the generic peer task would answer "Unknown action" instead of
            // half-closing the connection. Same effect as end_shell_session: FIN, then teardown.
            "close_connection" => Ok(ActionResult::CloseConnection),
            "no_shell_output" => Ok(ActionResult::WaitForMore),
            other => Err(anyhow::anyhow!("Unknown reverse-shell action: {other}")),
        }
    }
}

/// Prompt used when the model asks for a prompt without supplying its own text.
pub const DEFAULT_PROMPT: &str = "$ ";

// ============================================================================
// Action definitions
// ============================================================================

fn send_shell_output_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_shell_output".to_string(),
        description: "Send the text a command would print back to the operator's terminal. This \
            is fictional output you decide as the role-played shell — NetGet does not run the \
            command. Include a trailing newline. Set append_prompt=true to re-print the shell \
            prompt after the output so the operator sees a fresh prompt line."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "output".to_string(),
                type_hint: "string".to_string(),
                description: "The command's fictional stdout/stderr as plain text, e.g. a \
                    directory listing or 'bash: foo: command not found'. Sent verbatim as UTF-8; \
                    include \\n line endings yourself."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "append_prompt".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "When true, the shell prompt is written after the output. Default false."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "prompt".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Prompt text to append when append_prompt is true. Defaults to \"$ \"."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_shell_output",
            "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
            "append_prompt": true,
            "prompt": "www-data@web01:/var/www$ "
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> shell {output_bytes}B")
                .with_debug("reverse-shell output {output_bytes}B")
                .with_trace("reverse-shell output: {preview(output,200)}"),
        ),
    }
}

fn send_shell_prompt_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_shell_prompt".to_string(),
        description: "Write just the shell prompt (no command output). Use it on \
            reverse_shell_session_opened to greet the operator with an initial prompt."
            .to_string(),
        parameters: vec![Parameter {
            name: "prompt".to_string(),
            type_hint: "string".to_string(),
            description: "Prompt text, e.g. \"www-data@web01:/var/www$ \". Defaults to \"$ \"."
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_shell_prompt",
            "prompt": "www-data@web01:/var/www$ "
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> shell prompt")
                .with_debug("reverse-shell prompt {output_bytes}B"),
        ),
    }
}

fn end_shell_session_action() -> ActionDefinition {
    ActionDefinition {
        name: "end_shell_session".to_string(),
        description: "Close the connection to the operator (the emulated session exited, or the \
            operator ran 'exit'/Ctrl-D). Emit any farewell with send_shell_output first, in the \
            same response."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "end_shell_session" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("reverse-shell session ended")
                .with_debug("reverse-shell end_shell_session"),
        ),
    }
}

fn no_shell_output_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_shell_output".to_string(),
        description: "Produce no output for this command (as a real command that prints nothing \
            would). The session stays open for the next command."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "no_shell_output" }),
        log_template: Some(LogTemplate::new().with_debug("reverse-shell no output")),
    }
}

// ============================================================================
// Action constants
// ============================================================================

pub static SEND_SHELL_OUTPUT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_shell_output_action);
pub static SEND_SHELL_PROMPT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_shell_prompt_action);
pub static END_SHELL_SESSION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(end_shell_session_action);
pub static NO_SHELL_OUTPUT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(no_shell_output_action);

// ============================================================================
// Event types — both are emitted by mod.rs, and both declare actions.
// ============================================================================

/// Raised once when an operator connects to the listener.
pub static REVERSE_SHELL_SESSION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "reverse_shell_session_opened",
        "An operator connected to the reverse-shell listener (like a red-teamer's `nc` catching \
         a callback). Greet them with an initial shell prompt, or stay silent and wait for their \
         first command.",
        json!({
            "type": "send_shell_prompt",
            "prompt": "www-data@web01:/var/www$ "
        }),
    )
    // NO_SHELL_OUTPUT belongs here because the description above offers "stay silent and wait
    // for their first command" as a choice, and without this action there was no way to say it:
    // `call_llm` builds the tool list from the event, so a model taking the description at its
    // word answered with zero actions — which `consult` reads as FailClosed::NoUsableAnswer and
    // `apply` turns into a failure notice and a FIN. Following the documentation dropped the
    // session. The alternative example below named the same verb the model had not been given.
    .with_actions(vec![
        SEND_SHELL_PROMPT_ACTION.clone(),
        SEND_SHELL_OUTPUT_ACTION.clone(),
        NO_SHELL_OUTPUT_ACTION.clone(),
        END_SHELL_SESSION_ACTION.clone(),
    ])
    .with_alternative_example(json!({ "type": "no_shell_output" }))
    .with_log_template(
        LogTemplate::new()
            .with_info("reverse-shell operator connected from {client_ip}:{client_port}")
            .with_debug("reverse-shell session opened from {client_ip}:{client_port}"),
    )
});

/// Raised for each newline-terminated command line the operator sends.
pub static REVERSE_SHELL_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "reverse_shell_command",
        "The operator typed a command line (terminated by Enter). Answer with send_shell_output \
         containing the fictional output that command would print on the emulated host. This is \
         role-play: NetGet does not execute anything.",
        json!({
            "type": "send_shell_output",
            "output": "total 8\ndrwxr-xr-x 2 www-data www-data 4096 config.php\n",
            "append_prompt": true,
            "prompt": "www-data@web01:/var/www$ "
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The command line the operator typed, without the trailing newline."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "first_command".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for the first command of this session.".to_string(),
            required: true,
        },
        Parameter {
            name: "empty".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the operator pressed Enter on an empty line. Usually answer \
                with no_shell_output or just a prompt."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_SHELL_OUTPUT_ACTION.clone(),
        SEND_SHELL_PROMPT_ACTION.clone(),
        NO_SHELL_OUTPUT_ACTION.clone(),
        END_SHELL_SESSION_ACTION.clone(),
    ])
    .with_alternative_example(json!({ "type": "end_shell_session" }))
    .with_log_template(
        LogTemplate::new()
            .with_info("reverse-shell cmd: {command}")
            .with_debug("reverse-shell command '{command}' from {client_ip}:{client_port}")
            .with_trace("reverse-shell command: {json_pretty(.)}"),
    )
});

/// All event types this protocol can emit.
pub fn get_reverse_shell_event_types() -> Vec<EventType> {
    vec![
        REVERSE_SHELL_SESSION_OPENED_EVENT.clone(),
        REVERSE_SHELL_COMMAND_EVENT.clone(),
    ]
}
