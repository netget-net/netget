//! SSH commands and authenticated read-only SFTP actions.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::AppState;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
fn field(name: &str, hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required,
    }
}
fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log_template: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log_template)),
    }
}
fn event(id: &str, description: &str, fields: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type":"wait_for_more"}))
        .with_parameters(fields)
        .with_actions(SshClientProtocol.get_sync_actions())
}
pub static SSH_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ssh_connected",
        "SSH session authenticated",
        vec![
            field("remote_addr", "string", "Remote SSH server", true),
            field("username", "string", "Authenticated username", true),
            field(
                "host_key_verified",
                "boolean",
                "Whether the configured SHA256 host-key pin matched",
                true,
            ),
        ],
    )
});
pub static SSH_CLIENT_OUTPUT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ssh_output_received",
        "SSH command completed",
        vec![
            field("command", "string", "Executed command", true),
            field(
                "output",
                "string",
                "Captured standard output from the completed command",
                true,
            ),
            field("stderr", "string", "Command stderr when present", false),
            field(
                "exit_code",
                "number",
                "Exit status when supplied by the peer",
                false,
            ),
        ],
    )
});
pub static SSH_SFTP_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ssh_sftp_result",
        "SFTP v3 operation completed",
        vec![
            field(
                "operation",
                "string",
                "stat, list_directory or read_file",
                true,
            ),
            field(
                "path",
                "string",
                "Remote file or directory path selected for SFTP",
                true,
            ),
            field(
                "attributes",
                "object",
                "File size, permissions, type, owners and timestamps when supplied",
                false,
            ),
            field(
                "entries",
                "array",
                "Directory entries with name and typed attributes",
                false,
            ),
            field("offset", "number", "Read window start", false),
            field("bytes_read", "number", "Bytes in the UTF-8 window", false),
            field(
                "eof",
                "boolean",
                "Whether the server reported EOF before the window filled",
                false,
            ),
            field("text", "string", "UTF-8 file window", false),
        ],
    )
});
pub static SSH_OPERATION_FAILED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ssh_operation_failed",
        "SSH command or SFTP operation failed",
        vec![
            field(
                "action_type",
                "string",
                "Name of the rejected SSH or SFTP action",
                true,
            ),
            field("path", "string", "Remote path for SFTP", false),
            field("command", "string", "Command for exec", false),
            field(
                "error",
                "string",
                "Transport, status, framing or local validation error",
                true,
            ),
        ],
    )
});
#[derive(Default)]
pub struct SshClientProtocol;
impl SshClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for SshClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SSH"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SSH"
    }
    fn description(&self) -> &'static str {
        "SSH commands and pinned SFTP v3 stat, directory listing and UTF-8 file reads"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ssh", "secure shell", "sftp", "connect to ssh"]
    }
    fn group_name(&self) -> &'static str {
        "Network Infrastructure"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect with a trusted SHA256 host-key pin and list /reports over SFTP"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            action(
                "execute_command",
                "Execute a shell command; bounded stdout/stderr and exit status become ssh_output_received",
                vec![field("command", "string", "Shell command, 1..4096 bytes", true)],
                json!({"type":"execute_command","command":"pwd"}),
                "Execute SSH command: {command}",
            ),
            action(
                "sftp_stat",
                "Inspect remote file or directory attributes using pinned SFTP v3",
                vec![
                    field("path", "string", "Remote path, 1..4096 bytes without NUL", true),
                    field("follow_symlinks", "boolean", "Use STAT instead of LSTAT; default false", false),
                ],
                json!({"type":"sftp_stat","path":"/reports"}),
                "Inspect SFTP path {path}",
            ),
            action(
                "sftp_list_directory",
                "List a remote directory, at most 1024 entries, with typed attributes",
                vec![field("path", "string", "Remote directory, 1..4096 bytes without NUL", true)],
                json!({"type":"sftp_list_directory","path":"/reports"}),
                "List SFTP directory {path}",
            ),
            action(
                "sftp_read_file",
                "Read a bounded UTF-8 window from a remote file; no local file is created",
                vec![
                    field("path", "string", "Remote path, 1..4096 bytes without NUL", true),
                    field("offset", "number", "Unsigned starting byte offset, default 0", false),
                    field("length", "number", "Maximum bytes, 1..1048576, default 65536", false),
                ],
                json!({"type":"sftp_read_file","path":"/reports/today.txt","offset":0,"length":65536}),
                "Read SFTP file window from {path}",
            ),
            action(
                "disconnect",
                "Disconnect SSH and cancel every command, SFTP operation and response handler",
                vec![],
                json!({"type":"disconnect"}),
                "Disconnect SSH and cancel active operations",
            ),
            action(
                "wait_for_more",
                "Take no action and wait for another result",
                vec![],
                json!({"type":"wait_for_more"}),
                "Wait for SSH command or SFTP result",
            ),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SSH_CLIENT_CONNECTED_EVENT.clone(),
            SSH_CLIENT_OUTPUT_RECEIVED_EVENT.clone(),
            SSH_SFTP_RESULT_EVENT.clone(),
            SSH_OPERATION_FAILED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p = |name: &str,
                 hint: &str,
                 description: &str,
                 required: bool,
                 example: Value,
                 default: Option<Value>| ParameterDefinition {
            name: name.into(),
            type_hint: hint.into(),
            description: description.into(),
            required,
            example,
            default,
        };
        vec![
            p("username","string","SSH account used to authenticate this connection",true,json!("user"),None),
            p("password","string","Password for password authentication",false,json!("password"),None),
            p("private_key_path","string","Operator's OpenSSH private-key file; read only at connect",false,json!("/home/user/.ssh/id_ed25519"),None),
            p("private_key_passphrase","string","Passphrase for the private key",false,json!("passphrase"),None),
            p("auth_method","string","password or publickey; defaults to publickey when private_key_path is set",false,json!("publickey"),None),
            p("host_key_sha256","string","Trusted OpenSSH SHA256: host-key fingerprint. Required for SFTP; when supplied a mismatch fails the SSH handshake",false,json!("SHA256:<trusted fingerprint>"),None),
            p("handshake_timeout_secs","number","Resolution, TCP, SSH handshake and authentication deadline, 1..60 seconds",false,json!(10),Some(json!(super::HANDSHAKE_TIMEOUT.as_secs()))),
            p("operation_timeout_secs","number","Whole command or SFTP exchange deadline, 1..300 seconds",false,json!(30),Some(json!(super::OPERATION_TIMEOUT.as_secs()))),
            p("idle_timeout_secs","number","SSH inactivity deadline, 1..3600 seconds",false,json!(300),Some(json!(super::IDLE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental)
            .implementation("russh 0.45 SSH transport with owned socket shutdown; bounded SFTP v3 request/response codec without detached library session tasks")
            .llm_control("Shell command and stdout/stderr/exit status; SFTP stat, list_directory and read_file with structured attributes, directory entries and UTF-8 file windows. Shared handlers, memory, command injection and four follow-up levels")
            .e2e_testing("Independent OpenSSH sshd command and SFTP sessions, host-key pin negatives and direct NetGet pairing; tests under tests/client/ssh. No tests skip missing peers")
            .notes("SFTP requires an explicit SHA256 host-key pin. Command-only legacy sessions without a pin accept the peer key and are vulnerable to active attackers. SFTP packets 64 KiB, paths 4 KiB, read windows 1 MiB, directories 1024 entries and 16 empty batches, whole response budget 2 MiB; 16 total active operations/handlers. SSH stdout/stderr 1 MiB combined; channel payload 3 MiB and 4096 messages, at most 16 channels until peer CLOSE. A transport bound closes SSH; callback checks may include one extra upstream packet capped at 256 KiB. No SFTP writes, binary file action, protocol extensions, known_hosts, SSH agent, keyboard-interactive, certificate auth, PTY or forwarding. Experimental: no second independent SFTP server, pcap oracle or fuzz target")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Commands run concurrently; output that finishes while a handler is asking the
            // model is held and, with batching on, answered together when that call ends.
            // SFTP results and failures are never batched.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = || json!({"type":"open_client","protocol":"ssh","remote_addr":"localhost:22","startup_params":{"username":"user","private_key_path":"/home/user/.ssh/id_ed25519","host_key_sha256":"SHA256:<trusted fingerprint>"}});
        let mut llm = base();
        llm["instruction"] = json!("On ssh_connected, list /reports with sftp_list_directory. Inspect the resulting entries, then disconnect. Disconnect if the operation fails. Use only read-only SFTP actions.");
        let mut script = base();
        script["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":r#"import json, sys
event_type = json.load(sys.stdin)['event_type_id']
actions = []
if event_type == 'ssh_connected':
    actions = [{'type': 'sftp_list_directory', 'path': '/reports'}]
elif event_type in ('ssh_sftp_result', 'ssh_operation_failed'):
    actions = [{'type': 'disconnect'}]
print(json.dumps({'actions': actions}))"#}}]);
        let mut static_handler = base();
        static_handler["event_handlers"] = json!([
            {"event_pattern":"ssh_connected","handler":{"type":"static","actions":[{"type":"sftp_list_directory","path":"/reports"}]}},
            {"event_pattern":"ssh_sftp_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}},
            {"event_pattern":"ssh_operation_failed","handler":{"type":"static","actions":[{"type":"disconnect"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        StartupExamples::new(llm, script, static_handler)
    }
}
impl Client for SshClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::SshClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"]
            .as_str()
            .context("Missing 'type' field in action")?
        {
            "execute_command" => {
                let command = action["command"]
                    .as_str()
                    .context("Missing 'command' field")?;
                ensure!(
                    !command.is_empty() && command.len() <= super::sftp::MAX_PATH,
                    "command must contain 1..4096 bytes"
                );
                Ok(ClientActionResult::Custom {
                    name: "execute_command".into(),
                    data: json!({"command":command}),
                })
            }
            "sftp_stat" | "sftp_list_directory" | "sftp_read_file" => {
                super::sftp::validate_action(&action)?;
                Ok(ClientActionResult::Custom {
                    name: "sftp_operation".into(),
                    data: action,
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            other => anyhow::bail!("Unknown SSH client action: {other}"),
        }
    }
}
