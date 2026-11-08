//! FTP protocol actions implementation
//!
//! Implements RFC 959 FTP command responses with LLM control.

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
use tracing::debug;

/// FTP protocol action handler
pub struct FtpProtocol;

impl FtpProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_ftp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = parse_ftp_code(&action)?;

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter (the human-readable text after the code)")?;
        reject_line_breaks("message", message)?;

        let response = format!("{} {}\r\n", code, message);

        debug!("FTP sending response: {} {}", code, message);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_ftp_multiline(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = parse_ftp_code(&action)?;

        let lines = action
            .get("lines")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        if lines.is_empty() {
            // Degenerate case: a multiline response with no lines is just a single-line
            // response. Fall back to 'message' so the client still gets a valid reply
            // rather than a bare code.
            let message = action
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("OK");
            reject_line_breaks("message", message)?;
            let response = format!("{} {}\r\n", code, message);
            return Ok(ActionResult::Output(response.as_bytes().to_vec()));
        }

        for line in &lines {
            reject_line_breaks("lines", line)?;
        }

        // Build multiline response
        let mut response = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i == lines.len() - 1 {
                // Last line uses space separator
                response.push_str(&format!("{} {}\r\n", code, line));
            } else {
                // Intermediate lines use dash separator
                response.push_str(&format!("{}-{}\r\n", code, line));
            }
        }

        debug!("FTP sending multiline response: code {}", code);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_ftp_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter (the file's contents, as text)")?;

        debug!("FTP data-connection payload: {} bytes", data.len());
        Ok(transfer_result(data.as_bytes()))
    }

    fn execute_send_ftp_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let entries = action.get("entries").and_then(|v| v.as_array()).context(
            "Missing 'entries' parameter (an array of listing lines; [] for an empty directory)",
        )?;
        let entries = entries
            .iter()
            .map(|v| {
                v.as_str()
                    .context("every element of 'entries' must be a string (one listing line)")
            })
            .collect::<Result<Vec<_>>>()?;

        for entry in &entries {
            reject_line_breaks("entries", entry)?;
        }

        // A listing is ASCII whatever TYPE says (RFC 959 §4.1.3): CRLF after every line.
        let mut listing = String::new();
        for entry in &entries {
            listing.push_str(entry);
            listing.push_str("\r\n");
        }

        debug!("FTP listing: {} entries", entries.len());
        Ok(transfer_result(listing.as_bytes()))
    }
}

/// The `ActionResult::Custom` name carrying bytes for the data connection.
pub const TRANSFER_RESULT: &str = "ftp_transfer";

/// Wrap a data-connection payload. The session (`mod.rs`) writes it on the data connection of
/// the transfer being answered, never on the control connection.
fn transfer_result(bytes: &[u8]) -> ActionResult {
    ActionResult::Custom {
        name: TRANSFER_RESULT.to_string(),
        data: json!({ "hex": hex::encode(bytes) }),
    }
}

/// The bytes inside a [`TRANSFER_RESULT`], if `result` is one.
pub fn transfer_bytes(result: &ActionResult) -> Option<Vec<u8>> {
    match result {
        ActionResult::Custom { name, data } if name == TRANSFER_RESULT => {
            hex::decode(data.get("hex")?.as_str()?).ok()
        }
        _ => None,
    }
}

impl Default for FtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject CR or LF inside a piece of reply text the handler supplied.
///
/// FTP is line-oriented: a reply is terminated by CRLF and the client reads the next line as
/// a *new* reply. So a `message`, listing entry or multiline element containing CR or LF does
/// not produce a longer reply - it forges additional ones, and the client's reply-code state
/// machine is then reading text the handler never meant as a code. With `send_ftp_response`
/// that is a full response-splitting primitive: `"ok\r\n230 Logged in"` turns a 331 into a
/// successful login.
///
/// All three action descriptions already promised this ("Must not contain CR or LF", "Do not
/// include line endings", "the code and separators are added for you"). Nothing enforced it,
/// so the promise held only for as long as the model chose to keep it. Erroring is right
/// rather than stripping: a handler that meant several lines wants `send_ftp_multiline`, and
/// silently rewriting its text would hide the mistake.
fn reject_line_breaks(field: &str, value: &str) -> Result<()> {
    if let Some(pos) = value.find(['\r', '\n']) {
        return Err(anyhow::anyhow!(
            "FTP '{field}' must not contain CR or LF (found one at byte {pos}): a reply is \
             terminated by CRLF, so an embedded line break forges a second reply rather than \
             continuing this one. Use send_ftp_multiline for a reply spanning several lines."
        ));
    }
    Ok(())
}

/// Read and validate the `code` field of an FTP reply action.
///
/// RFC 959 replies are always a three-digit code, so anything outside 100-599 is a
/// mistake the client cannot interpret. Returning an error (rather than silently
/// substituting 500) makes the failure visible instead of shipping a wrong reply.
fn parse_ftp_code(action: &serde_json::Value) -> Result<u64> {
    let code = action
        .get("code")
        .and_then(|v| v.as_u64())
        .context("Missing 'code' parameter (a three-digit RFC 959 reply code, e.g. 220)")?;

    if !(100..=599).contains(&code) {
        return Err(anyhow::anyhow!(
            "Invalid FTP reply code {code}: RFC 959 codes are three digits in the range 100-599 \
             (e.g. 220 ready, 230 logged in, 331 need password, 550 not found)."
        ));
    }

    Ok(code)
}

// Implement Protocol trait (common functionality)
impl Protocol for FtpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // The server always sends the 220 greeting itself, so it declares no `send_first`.
        // Passive listeners take an OS-assigned port on the server's own host, so there is no
        // passive port range either.
        //
        // What it does declare are its bounds. The right value of each is a property of who is
        // on the other end, which only the operator knows: the read defaults serve NetGet's own
        // FTP client parked at the dashboard waiting for a person, and a listener exposed to
        // strangers wants the first one much lower.
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "max_upload_bytes".to_string(),
                type_hint: "number".to_string(),
                description: "Largest STOR/APPE upload the server reads, in bytes as they cross \
                              the data connection. The whole upload is handed to the handler in \
                              one ftp_command event, so this bounds what one event can carry. \
                              A larger upload is answered 552 without consulting the handler."
                    .to_string(),
                required: false,
                example: json!(65536),
                default: Some(serde_json::json!(super::data::MAX_UPLOAD_BYTES)),
            },
            crate::llm::actions::ParameterDefinition {
                name: "data_connect_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a transfer waits for its data connection to open - the \
                              client connecting to the PASV/EPSV port, or the server's connect \
                              to the PORT/EPRT address - before answering 425."
                    .to_string(),
                required: false,
                example: json!(60),
                default: Some(serde_json::json!(
                    super::data::DATA_CONNECT_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "data_idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds one read or write on an open data connection may make no \
                              progress before the transfer is aborted with 426. vsftpd's \
                              data_connection_timeout default."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::data::DATA_IDLE_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no command at all - not even \
                              a USER after the 220 greeting - before the server closes it. \
                              Default 300, matching the window a `manual` rule gives a human \
                              to answer one event. The peer is often NetGet's own FTP client, \
                              which reads the greeting in its read loop and writes nothing \
                              until an action or [ send message ] says to. Lower it (60 was \
                              the old value) for a listener exposed to strangers."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::FIRST_COMMAND_READ_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established control connection may go without a \
                              further command before the server closes it. Default 300, which \
                              is vsftpd's `idle_session_timeout` default; the silence between \
                              two commands of an interactive session is someone typing, so \
                              this is on a human timescale rather than a machine one."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_COMMANDS_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // FTP doesn't need async actions for now
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_ftp_response_action(),
            send_ftp_multiline_action(),
            send_ftp_data_action(),
            send_ftp_list_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "FTP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_ftp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FTP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ftp", "file transfer", "ftp server"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(21))
            .well_known_port(21)
            .implementation(
                "Manual line-based parsing with tokio; passive (PASV, EPSV) and active (PORT, \
                 EPRT) data connections, TYPE A/I",
            )
            .llm_control(
                "Every control-connection reply but the data-connection setup verbs and TYPE; \
                 every listing (LIST/NLST/MLSD) and file (RETR); the verdict on every upload \
                 (STOR/APPE)",
            )
            .e2e_testing(
                "python3 stdlib ftplib and curl (libcurl) complete real sessions in \
                 tests/server/ftp/real_client_test.rs and fail rather than skip without their \
                 client: login, PWD, LIST, NLST, MLSD, RETR in TYPE A and I, STOR in both, \
                 APPE, SIZE, refused downloads, over PASV, EPSV, PORT and EPRT. The pcap oracle \
                 reads ftplib's control connection. data_connection_test.rs holds each \
                 data-connection bound from both sides.",
            )
            .notes(
                "Beta for the surface it implements, which is RFC 959 stream mode, file \
                 structure, types A and I, with RFC 2428's EPSV/EPRT. Not implemented: FTPS / \
                 AUTH TLS, REST, STOU, ABOR during a transfer, block and compressed modes, \
                 TYPE E. File contents are text, so a binary download can carry only what a \
                 UTF-8 string can; a binary upload reaches the handler as its size. No storage: \
                 the handler supplies every listing and file.",
            )
            .max_inbound_bytes(crate::server::ftp::MAX_COMMAND_LINE)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Supported, off by default: a pipelined batch of command lines is one call, but
            // each command owes exactly one completion reply matched by position alone, so a
            // batch is written only when the handler gave exactly one per command and is
            // refused with 421 otherwise (`write_batch_answer` in mod.rs).
            .batching(crate::protocol::metadata::BatchingMode::Off)
            .build()
    }

    fn description(&self) -> &'static str {
        "FTP file transfer server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an FTP server on port 21 that allows anonymous login and lists files"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: acknowledge every command with a 200 reply, no LLM
        // call. The connect event arrives as command="CONNECTION_ESTABLISHED".
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ftp_command":
    actions = [{"type": "send_ftp_response", "code": 200, "message": "Command okay"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        // NOTE: no `send_first` here. The server always emits ftp_command with
        // command="CONNECTION_ESTABLISHED" on connect so the handler can produce the 220
        // greeting; passing send_first would only produce an "unsupported" warning.
        StartupExamples::new(
            // LLM mode: LLM handles all FTP responses intelligently
            json!({
                "type": "open_server",
                "port": 21,
                "base_stack": "ftp",
                "instruction": "FTP server that allows anonymous login and responds to FTP commands"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 21,
                "base_stack": "ftp",
                "event_handlers": [{
                    "event_pattern": "ftp_command",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 21,
                "base_stack": "ftp",
                "event_handlers": [{
                    "event_pattern": "ftp_command",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_ftp_response",
                            "code": 500,
                            "message": "Command not recognized"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for FtpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ftp::FtpServer;
            #[allow(deprecated)]
            let listen_addr = ctx.socket_addr().unwrap_or(ctx.legacy_listen_addr());
            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;
            let data_limits = crate::server::ftp::data::DataLimits::resolve(
                secs("data_connect_timeout_secs")?,
                secs("data_idle_timeout_secs")?,
                secs("max_upload_bytes")?,
            );

            FtpServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
                data_limits,
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
            "send_ftp_response" => self.execute_send_ftp_response(action),
            "send_ftp_multiline" => self.execute_send_ftp_multiline(action),
            "send_ftp_data" => self.execute_send_ftp_data(action),
            "send_ftp_list" => self.execute_send_ftp_list(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown FTP action: {}", action_type)),
        }
    }
}

// Action definitions

fn send_ftp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ftp_response".to_string(),
        description: "Send a single-line RFC 959 reply on the FTP control connection. The bytes \
            put on the wire are exactly \"<code> <message>\\r\\n\" - do not include the code in \
            'message' and do not add your own line ending. This is the normal way to answer every \
            FTP command."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Three-digit RFC 959 reply code, 100-599. 220 ready, 221 goodbye, \
                    230 logged in, 250 command ok, 257 the current directory (the answer to PWD, \
                    with the path in double quotes: code 257, message \"\\\"/pub\\\" is the \
                    current directory\"), 331 need password, 500 syntax error, 530 not logged \
                    in, 550 file unavailable. Any value outside 100-599 is rejected"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable text placed after the code on the same line. Must \
                    not contain CR or LF - use send_ftp_multiline for a reply spanning several \
                    lines"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_ftp_response",
            "code": 220,
            "message": "FTP Server Ready"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FTP {code} {message}")
                .with_debug("FTP send_ftp_response: {code} {message}"),
        ),
    }
}

fn send_ftp_multiline_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ftp_multiline".to_string(),
        description: "Send a multi-line RFC 959 reply, used for FEAT, HELP, STAT and similar. \
            Every line but the last is written as \"<code>-<line>\\r\\n\" and the last as \
            \"<code> <line>\\r\\n\", which is what tells the client the reply has ended. Supply \
            only the text of each line; the code and separators are added for you."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Three-digit RFC 959 reply code, 100-599, repeated on every line of \
                    the reply (e.g. 211 for FEAT, 214 for HELP)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "lines".to_string(),
                type_hint: "array".to_string(),
                description: "Array of strings, one per line of the reply, in order. Include the \
                    closing line (e.g. \"End\") yourself. If this is omitted or empty the action \
                    falls back to sending a single-line reply using the 'message' field"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_ftp_multiline",
            "code": 211,
            "lines": ["Features:", "UTF8", "End"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FTP {code} multiline")
                .with_debug("FTP send_ftp_multiline: code={code}, lines={lines_len}"),
        ),
    }
}

fn send_ftp_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ftp_data".to_string(),
        description: "Answer RETR with the file's contents. The server sends them on the data \
            connection the client opened with PASV/EPSV/PORT/EPRT, writing the 150 before and the \
            226 after itself - send no reply of your own beside it. In TYPE A (ascii) every line \
            ending is sent as CRLF; in TYPE I (binary) the text's bytes go out unchanged. Use it \
            only to answer RETR; to refuse, send send_ftp_response with 550 instead."
            .to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The complete contents of the file, as text, exactly as the client \
                should receive it. Nothing is appended"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_ftp_data",
            "data": "Hello from FTP\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FTP file {data_len}B")
                .with_debug("FTP send_ftp_data: {data_len}B")
                .with_trace("FTP data: {preview(data,200)}"),
        ),
    }
}

fn send_ftp_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ftp_list".to_string(),
        description: "Answer LIST, NLST or MLSD with a directory listing. The server sends it on \
            the data connection, one CRLF-terminated line per entry, writing the 150 before and \
            the 226 after itself - send no reply of your own beside it. An empty array is an \
            empty directory. Use it only to answer LIST/NLST/MLSD; to refuse, send \
            send_ftp_response with 550 instead."
            .to_string(),
        parameters: vec![Parameter {
            name: "entries".to_string(),
            type_hint: "array".to_string(),
            description: "Array of strings, one per directory entry, in the format the command \
                asks for: LIST takes `ls -l` lines (\"-rw-r--r-- 1 ftp ftp 1024 Jan 01 00:00 \
                file.txt\"), NLST bare names (\"file.txt\"), MLSD RFC 3659 fact lines \
                (\"type=file;size=1024;modify=20260101000000; file.txt\" - facts, one space, the \
                name). No line endings"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_ftp_list",
            "entries": [
                "-rw-r--r-- 1 ftp ftp 1024 Jan 01 00:00 file.txt",
                "drwxr-xr-x 2 ftp ftp 4096 Jan 01 00:00 subdir"
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FTP listing {entries_len} entries")
                .with_debug("FTP send_ftp_list: {entries_len} entries"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(LogTemplate::new().with_debug("FTP waiting for more data")),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the FTP connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("FTP connection closed")
                .with_debug("FTP close_connection"),
        ),
    }
}

// ============================================================================
// FTP Action Constants
// ============================================================================

pub static SEND_FTP_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_ftp_response_action);
pub static SEND_FTP_MULTILINE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_ftp_multiline_action);
pub static SEND_FTP_DATA_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_ftp_data_action);
pub static SEND_FTP_LIST_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_ftp_list_action);
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(wait_for_more_action);
pub static CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_connection_action);

// ============================================================================
// FTP Event Type Constants
// ============================================================================

/// FTP command event - triggered on connect and for every command line thereafter
pub static FTP_COMMAND_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "ftp_command",
        "A client connected, or sent a command line on the FTP control connection. This is the \
         only FTP event: the connect case is signalled by the literal command \
         'CONNECTION_ESTABLISHED', for which you must reply with a 220 greeting before the client \
         will send anything else. The server itself answers PASV, EPSV, PORT, EPRT, TYPE, MODE \
         and STRU and runs the data connection: answer LIST/NLST/MLSD with send_ftp_list, RETR \
         with send_ftp_data, and STOR/APPE (whose upload arrives in this event) with one \
         completion reply.",
        json!({"type": "send_ftp_response", "code": 220, "message": "FTP Server Ready"}),
    )
    .with_parameters(vec![Parameter {
        name: "command".to_string(),
        type_hint: "string".to_string(),
        description: "The command line as sent by the client, with the trailing CRLF stripped \
            (e.g. 'USER anonymous', 'PASS x@y.z', 'SYST', 'PWD', 'LIST', 'RETR file.txt', \
            'QUIT'). The verb is NOT upper-cased or split out for you. One exception: the \
            literal value 'CONNECTION_ESTABLISHED' is not from the client - it means the TCP \
            connection has just been accepted and the server is waiting for your 220 greeting"
            .to_string(),
        required: true,
    },
    Parameter {
        name: "answer_with".to_string(),
        type_hint: "string".to_string(),
        description: "The reply RFC 959 expects for this command, derived by the server from \
            its verb. Absent for a verb the server does not classify."
            .to_string(),
        required: false,
    },
    Parameter {
        name: "transfer_type".to_string(),
        type_hint: "string".to_string(),
        description: "On LIST, NLST, MLSD, RETR, STOR and APPE only: the representation type \
            the client set with TYPE, \"ascii\" or \"binary\". The server answers PASV, EPSV, \
            PORT, EPRT, TYPE, MODE and STRU itself, so those never reach you"
            .to_string(),
        required: false,
    },
    Parameter {
        name: "upload_bytes".to_string(),
        type_hint: "number".to_string(),
        description: "On STOR and APPE only: the size of the file the client uploaded, after \
            ASCII line-ending conversion in TYPE A"
            .to_string(),
        required: false,
    },
    Parameter {
        name: "upload_text".to_string(),
        type_hint: "string".to_string(),
        description: "On STOR and APPE only: the uploaded file's contents, present when they \
            are valid UTF-8 text (upload_is_text true). A binary upload is described by \
            upload_bytes alone"
            .to_string(),
        required: false,
    },
    Parameter {
        name: "upload_is_text".to_string(),
        type_hint: "boolean".to_string(),
        description: "On STOR and APPE only: whether upload_text carries the contents"
            .to_string(),
        required: false,
    }])
    .with_actions(vec![
        SEND_FTP_RESPONSE_ACTION.clone(),
        SEND_FTP_MULTILINE_ACTION.clone(),
        SEND_FTP_DATA_ACTION.clone(),
        SEND_FTP_LIST_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("FTP {client_ip}: {command}")
            .with_debug("FTP command from {client_ip}:{client_port}: {command}")
            .with_trace("FTP: {json_pretty(.)}"),
    )
    });

/// The `answer_with` event field: the reply RFC 959 expects for `command`, by its verb.
///
/// The real-model eval saw llama3.1:8b answer `USER` with `331` *and* `230` in one reply (the
/// first is what the client gets), answer `PASS` with another `331`, and answer `PWD` with
/// `200 Connected`. The server knows the verb exactly, so it says which reply completes it.
/// Exactly one completion reply per command is also enforced on the wire (`OneReply` in
/// `mod.rs`).
pub fn answer_with_for_command(command: &str) -> Option<&'static str> {
    let verb = command
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    Some(match verb.as_str() {
        "CONNECTION_ESTABLISHED" => "one 220 greeting",
        "USER" => {
            "one reply: 331 to ask for a password, or 230 if this user is logged in with no \
             password - not both"
        }
        "PASS" => "one reply: 230 if the login succeeds, 530 if it does not",
        "PWD" | "XPWD" => {
            "one 257 reply whose message starts with the directory in double quotes, e.g. \
             \"/pub\" is the current directory"
        }
        "CWD" | "XCWD" | "CDUP" => {
            "one reply: 250 if the directory changed, 550 if it does not exist"
        }
        "SYST" => "one 215 reply naming the system type, e.g. UNIX Type: L8",
        "NOOP" => "one 200 reply",
        "QUIT" => "one 221 reply, then the server closes",
        "FEAT" => {
            "a multi-line 211 reply listing features (this server implements EPSV, PASV, EPRT \
             and MLST type*;size*;modify*;), or 502 if there are none"
        }
        "LIST" => {
            "send_ftp_list with one `ls -l` line per entry; the server opens the data connection \
             and sends 150 and 226 itself. Or one 450/550 reply if the directory cannot be listed"
        }
        "NLST" => {
            "send_ftp_list with one bare file name per entry; the server opens the data \
             connection and sends 150 and 226 itself. Or one 450/550 reply if the directory \
             cannot be listed"
        }
        "MLSD" => {
            "send_ftp_list with one RFC 3659 fact line per entry \
             (type=file;size=12;modify=20260101000000; notes.txt); the server opens the data \
             connection and sends 150 and 226 itself. Or one 501/550 reply"
        }
        "RETR" => {
            "send_ftp_data with the file's complete contents; the server opens the data \
             connection and sends 150 and 226 itself. Or one 450/550 reply if the file does not \
             exist"
        }
        "STOR" | "APPE" => {
            "the upload has been received in full (upload_bytes, upload_text): one 226 reply to \
             confirm it, or 451/552 to refuse it"
        }
        "SIZE" => "one 213 reply whose message is the file's size in bytes, or 550",
        "MDTM" => "one 213 reply whose message is the modification time as YYYYMMDDHHMMSS, or 550",
        "REST" | "STOU" => "one 502 reply: this server does not implement it",
        "ABOR" => "one 225 reply: no transfer is in progress",
        _ => return None,
    })
}

/// Get FTP event types
pub fn get_ftp_event_types() -> Vec<EventType> {
    vec![FTP_COMMAND_EVENT.clone()]
}
