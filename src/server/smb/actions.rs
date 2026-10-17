//! SMB protocol actions implementation

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

/// SMB protocol action handler
pub struct SmbProtocol;

impl Default for SmbProtocol {
    fn default() -> Self {
        Self
    }
}

impl SmbProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SmbProtocol {
    /// The three read deadlines, and nothing else. Each defaults to the constant the server
    /// uses, so the form, `get_protocol_docs` and the model all show the number in force.
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Seconds a connected peer may send nothing before any session is \
                              admitted; the server then closes it without a reply. SMB2 is \
                              client-speaks-first and every real client sends NEGOTIATE as it \
                              connects."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::FIRST_MESSAGE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Seconds a peer holding an admitted session may send nothing \
                              before the server closes it. Default 900, Windows' \
                              `autodisconnect`: a mounted share with no I/O is idle for long \
                              stretches."
                    .to_string(),
                required: false,
                example: json!(900),
                default: Some(json!(super::IDLE_BETWEEN_MESSAGES_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "body_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Seconds a peer may stall part-way through a message whose \
                              length its Direct TCP header has already announced."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::BODY_READ_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![disconnect_client_action()]
    }
    /// SMB raises exactly one event, and it must be declared here as well as emitted.
    ///
    /// This was missing, so the trait default applied and returned an empty vec: SMB_OPERATION_EVENT
    /// was built and dispatched at runtime, but invisible to anything that walks the registry.
    /// `tests/event_action_declarations_test.rs` audits every registered protocol's events and
    /// therefore audited none of SMB's, and `tests/mock_event_ids_test.rs` reported all nineteen
    /// of this protocol's own mock rules as naming an unknown event.
    fn get_event_types(&self) -> Vec<crate::protocol::EventType> {
        vec![SMB_OPERATION_EVENT.clone()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Every action listed here has an executor branch in src/server/smb/mod.rs and is
        // attached to SMB_OPERATION_EVENT below, so the model can both see it and have it
        // take effect.
        //
        // `smb_delete_file` and `smb_delete_directory` used to be listed and were removed:
        // SMB2 has no DELETE command. A client deletes by opening the file and issuing
        // SET_INFO with FileDispositionInformation (MS-SMB2 2.2.39 / 2.2.21), and this
        // server does not implement SET_INFO at all - the command falls through to the
        // "Unknown SMB2 command" arm. Advertising a delete action the server can never be
        // asked to perform only gave the model a response that did nothing.
        vec![
            smb_auth_success_action(),
            smb_auth_deny_action(),
            smb_list_directory_action(),
            smb_read_file_action(),
            smb_write_file_action(),
            smb_get_file_info_action(),
            smb_create_file_action(),
            smb_create_directory_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SMB"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["smb", "cifs"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Stable on the six conditions in the root CLAUDE.md, each re-derived against
            // source on 30 September 2026; "Maturity: the six conditions" at the foot of
            // src/server/smb/CLAUDE.md says what each rests on and what the rating does not
            // cover.
            .state(DevelopmentState::Stable)
            .well_known_port(445)
            // The Direct TCP frame length is the one peer-chosen size this server allocates
            // for; a frame over MAX_MESSAGE_BYTES is refused after its 64-byte header, and a
            // WRITE over the negotiated MaxWriteSize inside a legal frame is refused before the
            // model. Both tested in tests/server/smb/inbound_limit_test.rs; every other bound
            // in tests/server/smb/bounds_test.rs.
            .max_inbound_bytes(crate::server::smb::MAX_MESSAGE_BYTES)
            .implementation(
                "Hand-written SMB2 (dialects 0x0202 and 0x0210) over Direct TCP (MS-SMB2 2.1), \
                 with compound requests. SESSION_SETUP walks SPNEGO/NTLMSSP so real clients \
                 finish the login; no password is verified and no session is signed. Every \
                 request is parsed by a pure function in wire.rs.",
            )
            .llm_control(
                "Authentication (allow/deny, on the user name the NTLMSSP AUTHENTICATE carries), \
                 directory listings, file metadata, file content on read, file-vs-directory on \
                 create, deletes (a create carrying delete_on_close), and write authorisation. \
                 File payloads carry an explicit `encoding` field (utf8/base64/hex) in both \
                 directions, so binary content survives a read and a written binary payload is \
                 shown to the model losslessly.",
            )
            .e2e_testing(
                "Condition 1: two independent real clients against a mocked model \
                 (tests/server/smb/real_client_test.rs), neither linked by the server, both \
                 failing rather than skipping when absent, counted verb by verb from the \
                 recorded bytes. Samba's smbclient 4.24 logs in anonymously over \
                 SPNEGO/NTLMSSP and runs ls, get of a 70 000-byte binary file, put of a \
                 100 000-byte one in two WRITEs, mkdir, rm (a delete-on-close open the model is \
                 told about), echo, tdis and logoff; smbprotocol 1.17 logs in as a named guest \
                 over bare NTLMSSP and runs listdir, read, stat (a related compound of CREATE, \
                 five QUERY_INFOs and CLOSE), a two-WRITE upload, FLUSH, mkdir, echo, \
                 TREE_DISCONNECT and LOGOFF. Every answered verb is driven by both clients \
                 except FLUSH (smbclient has no command for it). The model's write events must \
                 reassemble to exactly the uploaded bytes. Condition 2: both sessions and a raw \
                 session of every command the server answers (header_layout_test.rs) read \
                 clean in Wireshark's nbss/smb2 dissectors. Condition 3: fuzz targets \
                 smb2_request and ntlmssp_token, 300s each clean against a corpus with a \
                 nested-DER depth bomb and a 14 000-request compound chain. Condition 4: every \
                 declared bound tested at and past the bound and verified by removal \
                 (bounds_test.rs, inbound_limit_test.rs). failure_modes_test.rs asserts all \
                 eighteen refusal paths on the wire and in the log. Not verified against \
                 Windows Explorer, mount_smbfs or mount.cifs.",
            )
            .notes(
                "Stable covers the surface implemented, a small subset of MS-SMB2: SMB \
                 2.0.2/2.1 only; no SMB 3.x, signing, encryption, oplocks, leases, durable \
                 handles, DFS or named pipes (IPC$ connects, every open on it is refused). \
                 Sessions are guest or null: NTLMSSP is walked, never verified. No SET_INFO (so \
                 no rename, truncate or set-times; delete only through FILE_DELETE_ON_CLOSE), \
                 no LOCK, no CHANGE_NOTIFY, IOCTL refused, CANCEL unanswered. The volume size \
                 is a fixed report, not a measurement. Per connection: 16 sessions, 64 trees, \
                 1024 open handles, 32 acted-on requests per compound. Adjacent operations \
                 share no state beyond the per-connection session, tree and handle tables: the \
                 model is the filesystem.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SMB/CIFS file server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an SMB/CIFS file server on port 8445"
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: accept every session on this share, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "smb_operation":
    actions = [{"type": "smb_auth_success",
                "username": event.get("username", "guest")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 445,
                "base_stack": "smb",
                "instruction": "SMB file server. Accept all guest connections. Provide /documents directory with sample files. Return file content on reads."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 445,
                "base_stack": "smb",
                "event_handlers": [{
                    "event_pattern": "smb_operation",
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
                "port": 445,
                "base_stack": "smb",
                "event_handlers": [{
                    "event_pattern": "smb_operation",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "smb_auth_success",
                            "username": "guest"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SmbProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::smb::{Deadlines, SmbServer};
            // Propagate, never unwrap: these values come from the model or an MCP caller. A
            // zero deadline would close every connection before it could speak, so it is
            // refused rather than honoured.
            let secs = |name: &str, default: std::time::Duration| -> Result<std::time::Duration> {
                let value = match ctx.startup_params.as_ref() {
                    Some(p) => p.get_optional_u64(name)?,
                    None => None,
                };
                match value {
                    None => Ok(default),
                    Some(0) => anyhow::bail!("{name} must be at least 1 second, got 0"),
                    Some(n) => Ok(std::time::Duration::from_secs(n)),
                }
            };
            let defaults = Deadlines::default();
            let deadlines = Deadlines {
                first_message: secs("first_byte_timeout_secs", defaults.first_message)?,
                idle: secs("idle_timeout_secs", defaults.idle)?,
                body: secs("body_timeout_secs", defaults.body)?,
            };
            SmbServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                deadlines,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        // `close_connection` is the one action this executor resolves itself, and it is
        // deliberately NOT advertised in `get_sync_actions()` / the event's action list —
        // adding it there would change the model's tool list. It exists for the peer handle:
        // the dashboard's "[ disconnect this peer ]" injects a bare
        // `{"type": "close_connection"}` whatever the protocol calls its own close verb, and
        // `server::peer_support` turns `ActionResult::CloseConnection` into the half-close.
        // Without this arm the button would come back "executed" having done nothing, because
        // the fall-through below answers every name with a `Custom` result.
        if action_type == "close_connection" {
            return Ok(ActionResult::CloseConnection);
        }

        // Return Custom result with the action data for SMB server to handle
        Ok(ActionResult::Custom {
            name: action_type.to_string(),
            data: action,
        })
    }
}

// Event type for SMB operations
pub static SMB_OPERATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_operation",
        "An SMB2 client asked for a filesystem operation. You are the filesystem: nothing is \
         read from or written to disk, so invent a consistent virtual tree and keep it in memory \
         across operations. Answer with the action matching 'operation': session_setup -> \
         smb_auth_success or smb_auth_deny, create -> smb_create_file or smb_create_directory \
         (which one decides whether the client is told the handle is a directory; a create \
         with delete_on_close true is the client deleting that path, and answering either \
         action approves the delete), read -> \
         smb_read_file, write -> smb_write_file (the write is REFUSED with STATUS_ACCESS_DENIED \
         unless you return it), query_info -> smb_get_file_info, query_directory -> \
         smb_list_directory.",
        json!({
            "type": "smb_read_file",
            "path": "/documents/file.txt",
            "content": "Sample file content",
            "encoding": "utf8"
        }),
    )
    // Every action here has an executor branch in src/server/smb/mod.rs. `call_llm` builds the
    // model's tool list from this list, not from get_sync_actions(), so anything missing here is
    // invisible to the model and anything here without an executor branch is a no-op it can emit.
    // Keep the two in sync.
    .with_actions(vec![
        smb_auth_success_action(),
        smb_auth_deny_action(),
        smb_create_file_action(),
        smb_create_directory_action(),
        smb_read_file_action(),
        smb_write_file_action(),
        smb_get_file_info_action(),
        smb_list_directory_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Which request this is: \"session_setup\" (authentication), \"create\" \
                          (open), \"read\", \"write\", \"query_info\" (stat) or \
                          \"query_directory\" (list)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "The file or directory path being accessed".to_string(),
            required: false,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "write only: the bytes the client wrote, rendered according to the \
                          'encoding' field of this event. Absent for every other operation."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "write only: how to read 'data'. \"utf8\" means 'data' is the written \
                          bytes as literal text; \"base64\" means 'data' is the written bytes \
                          base64-encoded, used whenever they are not all printable ASCII. To \
                          hand the same bytes back on a later read, pass this 'data' and this \
                          'encoding' straight into smb_read_file's 'content' and 'encoding'."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "delete_on_close".to_string(),
            type_hint: "boolean".to_string(),
            description: "create only, and present only when true: the client opened the path \
                          in order to delete it (SMB2 has no DELETE command; `rm` opens with \
                          delete-on-close and closes). smb_create_file or smb_create_directory \
                          approves the delete, so forget the path; answering neither refuses it \
                          with STATUS_ACCESS_DENIED."
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SMB {operation} {path}")
            .with_debug("SMB {operation}: {path}")
            .with_trace("SMB: {json_pretty(.)}"),
    )
});

// ============================================================================
// Payload encoding
//
// SMB carries file *contents*, which are routinely not text. Both directions
// therefore carry an explicit `encoding` field next to the payload string, and
// there is deliberately no sniffing: "SGVsbG8=" is simultaneously valid text and
// valid base64, and only the sender knows which it means. This is the same shape
// as `send_tcp_data`'s `encoding` field (d70bb5b5); the defect fixed here was
// that `smb_read_file.content` was documented as "base64 encoded for binary"
// while the executor did `.as_bytes()`, so a model that followed the
// documentation put literal base64 ASCII into the file.
// ============================================================================

/// Turn an outbound payload string into the exact bytes the server writes into an
/// SMB2 response, honouring the action's optional `encoding` field.
///
/// - absent or `"utf8"`: the string's UTF-8 bytes, verbatim (default, backwards compatible)
/// - `"base64"`: standard base64, so `"SGVsbG8="` yields the 5 bytes `Hello`
/// - `"hex"`: two hex digits per byte, so `"48656c6c6f"` yields the same 5 bytes
pub fn decode_smb_payload(payload: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    use base64::Engine as _;

    match encoding.unwrap_or("utf8") {
        "utf8" | "text" => Ok(payload.as_bytes().to_vec()),
        "base64" => {
            // Models frequently wrap long base64 across lines; tolerate whitespace.
            let cleaned: String = payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid base64 in payload ({payload:?}): {e}. To send this string as \
                         literal text instead, omit 'encoding' or set it to \"utf8\"."
                    )
                })
        }
        "hex" => {
            let cleaned: String = payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in payload: expected an even number of hex digits, got {} \
                     ({payload:?}). Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
                    cleaned.len()
                ));
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in payload ({payload:?}): {e}. Use only 0-9/a-f, two digits per \
                     byte. To send this string as literal text instead, omit 'encoding' or set \
                     it to \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, the \
             string's characters as-is), \"base64\" and \"hex\"."
        )),
    }
}

/// Render bytes received from the client for the model, together with the `encoding`
/// name that says how to read them back.
///
/// Printable ASCII is passed through as text so ordinary text files stay readable in
/// prompts and logs; anything else is base64-encoded rather than lossily converted.
/// The pair is symmetric with [`decode_smb_payload`]: feeding the returned string and
/// encoding back through it reproduces the original bytes exactly.
pub fn encode_smb_payload(bytes: &[u8]) -> (String, &'static str) {
    use base64::Engine as _;

    if bytes
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(bytes).to_string(), "utf8")
    } else {
        (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            "base64",
        )
    }
}

/// Shared `encoding` parameter for every action carrying an outbound payload string.
fn encoding_parameter(payload_field: &str) -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: format!(
            "How to turn '{payload_field}' into the bytes the client receives. \"utf8\" (the \
             default when omitted) uses the characters of '{payload_field}' unchanged - use it \
             for text files. \"base64\" decodes '{payload_field}' as standard base64 and \
             \"hex\" as hex digits - use one of those for binary files, e.g. \
             {{\"{payload_field}\": \"SGVsbG8=\", \"encoding\": \"base64\"}} delivers the 5 \
             bytes 'Hello', whereas the same value without \"encoding\" delivers the 8 \
             characters S-G-V-s-b-G-8-=. There is no auto-detection. No other values are \
             accepted"
        ),
        required: false,
    }
}

// Action definitions

fn disconnect_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect_client".to_string(),
        description: "Disconnect an SMB client".to_string(),
        parameters: vec![Parameter {
            name: "client".to_string(),
            type_hint: "string".to_string(),
            description: "Client address to disconnect".to_string(),
            required: true,
        }],
        example: json!({
            "type": "disconnect_client",
            "client": "192.168.1.100:54321"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("SMB disconnect {client}")
                .with_debug("SMB disconnect_client: {client}"),
        ),
    }
}

fn smb_list_directory_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_list_directory".to_string(),
        description: "List files in a directory".to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "Directory path to list".to_string(),
                required: true,
            },
            Parameter {
                name: "files".to_string(),
                type_hint: "array".to_string(),
                description: "Array of file objects with name, size, is_directory, modified_time"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "smb_list_directory",
            "path": "/documents",
            "files": [
                {
                    "name": "report.pdf",
                    "size": 524288,
                    "is_directory": false,
                    "modified_time": "2025-01-15T10:30:00Z"
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB DIR {path} ({files_len} files)")
                .with_debug("SMB smb_list_directory: path={path}, {files_len} files"),
        ),
    }
}

fn smb_read_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_read_file".to_string(),
        description: "Answer a 'read' operation with the file's contents. The bytes in 'content' \
                      (interpreted according to 'encoding') become the body of the SMB2 READ \
                      response."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "File path to read".to_string(),
                required: true,
            },
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "File content. Interpreted according to 'encoding': by default the \
                              characters of this string are delivered as-is (UTF-8)."
                    .to_string(),
                required: true,
            },
            encoding_parameter("content"),
        ],
        example: json!({
            "type": "smb_read_file",
            "path": "/documents/file.txt",
            "content": "Hello, World!",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB READ {path}")
                .with_debug("SMB smb_read_file: path={path}"),
        ),
    }
}

fn smb_write_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_write_file".to_string(),
        description: "Accept a 'write' operation. The client has already sent the bytes - they \
                      are in the event's 'data' field - so this action does not carry them back; \
                      it authorises the write and the server answers STATUS_SUCCESS. If you do \
                      NOT return this action for a 'write' operation the write is refused with \
                      STATUS_ACCESS_DENIED, so silence is a denial, not an approval."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "File path being written (echo the event's 'path')".to_string(),
                required: true,
            },
            Parameter {
                name: "bytes_written".to_string(),
                type_hint: "number".to_string(),
                description: "How many bytes to report as written. Omit to report all the bytes \
                              the client sent, which is what a normal filesystem does. A smaller \
                              number tells the client the write was partial."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "smb_write_file",
            "path": "/documents/file.txt"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB WRITE OK {path}")
                .with_debug("SMB smb_write_file: path={path}"),
        ),
    }
}

fn smb_get_file_info_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_get_file_info".to_string(),
        description: "Get file metadata".to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "File path".to_string(),
                required: true,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "File size in bytes".to_string(),
                required: true,
            },
            Parameter {
                name: "is_directory".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether path is a directory".to_string(),
                required: true,
            },
            Parameter {
                name: "modified_time".to_string(),
                type_hint: "string".to_string(),
                description: "Last modified time (ISO 8601)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "smb_get_file_info",
            "path": "/documents/file.txt",
            "size": 1024,
            "is_directory": false,
            "modified_time": "2025-01-15T10:30:00Z"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB INFO {path}")
                .with_debug("SMB smb_get_file_info: path={path}, size={size}"),
        ),
    }
}

fn smb_create_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_create_file".to_string(),
        description: "Answer a 'create' operation: the path is (or becomes) a regular file. The \
                      handle the client receives is marked FILE_ATTRIBUTE_NORMAL, so the client \
                      will follow up with read/write rather than query_directory. Returning \
                      neither create action is NOT a default: it refuses the open with \
                      STATUS_ACCESS_DENIED, because silence must not become consent for an \
                      admission decision."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "File path being opened or created".to_string(),
                required: true,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "The file's size in bytes, reported to the client as the open \
                              handle's end of file. Give it whenever the file has content: \
                              some clients read exactly this many bytes and never ask again, \
                              so an open without it reads as an empty file. Omit only for a \
                              file that is empty or being created."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "smb_create_file",
            "path": "/documents/report.txt",
            "size": 1024
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB CREATE {path}")
                .with_debug("SMB smb_create_file: path={path}"),
        ),
    }
}

// `smb_delete_file` and `smb_delete_directory` used to be defined here. SMB2 has no DELETE
// command - deletion is SET_INFO/FileDispositionInformation on an open handle - and this
// server does not implement SET_INFO, so neither action could ever have been requested or
// routed. They were removed rather than left advertised.

fn smb_create_directory_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_create_directory".to_string(),
        description: "Answer a 'create' operation: the path is (or becomes) a directory. The \
                      handle the client receives carries FILE_ATTRIBUTE_DIRECTORY, which is what \
                      makes the client issue query_directory against it instead of read."
            .to_string(),
        parameters: vec![Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Directory path being opened or created".to_string(),
            required: true,
        }],
        example: json!({
            "type": "smb_create_directory",
            "path": "/documents/newdir"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB MKDIR {path}")
                .with_debug("SMB smb_create_directory: path={path}"),
        ),
    }
}

fn smb_auth_success_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_auth_success".to_string(),
        description: "Allow SMB authentication for the user (respond to session_setup event)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "Username that was authenticated".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional message explaining why auth was allowed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "smb_auth_success",
            "username": "alice",
            "message": "User alice authenticated successfully"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB AUTH OK {username}")
                .with_debug("SMB smb_auth_success: user={username}"),
        ),
    }
}

fn smb_auth_deny_action() -> ActionDefinition {
    ActionDefinition {
        name: "smb_auth_deny".to_string(),
        description: "Deny SMB authentication for the user (respond to session_setup event)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "Username that was denied".to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Reason for denying authentication".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "smb_auth_deny",
            "username": "hacker",
            "reason": "User not authorized"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMB AUTH DENIED {username}")
                .with_debug("SMB smb_auth_deny: user={username}, reason={reason}"),
        ),
    }
}
