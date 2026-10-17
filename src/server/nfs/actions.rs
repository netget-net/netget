//! NFS protocol actions implementation.
//!
//! The filesystem is entirely LLM-supplied: nothing here stores a file, a directory or an
//! attribute. `LlmNfsFileSystem` (`src/server/nfs/mod.rs`) implements `nfsserve`'s
//! `NFSFileSystem` by turning every NFSv3 procedure into an `nfs_operation` event and reading
//! the answer back out of the model's action. Consistency of file IDs across calls is the
//! model's job, which is why the instruction matters so much for this protocol.
//!
//! **Text only.** `nfs_read_response.data` and the `data` field of a write event are UTF-8
//! strings, because actions must not carry raw bytes or base64 — models cannot reliably
//! produce or parse them. The consequence is real and worth stating: this server cannot serve
//! or faithfully receive binary files. Inbound writes go through `String::from_utf8_lossy`, so
//! any non-UTF-8 byte a client writes reaches the model as U+FFFD and is unrecoverable.

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

/// NFS protocol action handler
pub struct NfsProtocol;

impl NfsProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for NfsProtocol {
    /// No async actions.
    ///
    /// `mount_filesystem` / `unmount_filesystem` used to be declared here. Both parsed a
    /// `path`, discarded it and returned `ActionResult::NoAction`: nothing in `nfsserve` or in
    /// `LlmNfsFileSystem` has any notion of an export to mount, so they could not have done
    /// anything even if something had called them. Removed rather than left as a promise.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        nfs_response_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "NFS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_nfs_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NFS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["nfs", "file server"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(2049)
            // Port 2049 is above 1023, so no privilege is required to bind it. (A client
            // mounting from it may still need privileges of its own; that is the client's
            // problem, not this server's.)
            .implementation(
                "nfsserve v0.10 NFSv3 server; LlmNfsFileSystem implements NFSFileSystem",
            )
            .llm_control(
                "Every filesystem operation: lookup, getattr, setattr, read, write, create, \
                 mkdir, remove, rename, readdir, symlink, readlink. Nothing is stored server-side.",
            )
            .e2e_testing("mount / showmount, and tests/server/nfs/test.rs")
            .notes(
                "NFSv3 over TCP only. File contents are UTF-8 strings in actions, so binary \
                 files cannot be served or received faithfully. The LLM must keep file IDs \
                 stable across calls or clients will misbehave. Every operation costs one \
                 model round-trip, so real workloads are impractically slow - use script or \
                 static handlers for anything beyond a demo.",
            )
            .max_inbound_bytes(crate::server::nfs::guard::MAX_RECORD_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NFS file server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an NFS file server on port 2049"
    }

    fn group_name(&self) -> &'static str {
        "Web & File"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every operation as a getattr on a directory,
        // no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "nfs_operation":
    actions = [{"type": "nfs_getattr_response",
                "file_type": "directory", "mode": 493, "size": 4096}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 2049,
                "base_stack": "nfs",
                "instruction": "NFS file server. On file reads, return content based on the path. On writes, acknowledge with updated attributes. Provide directory listings with sample files."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 2049,
                "base_stack": "nfs",
                "event_handlers": [{
                    "event_pattern": "nfs_operation",
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
                "port": 2049,
                "base_stack": "nfs",
                "event_handlers": [{
                    "event_pattern": "nfs_operation",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "nfs_getattr_response",
                            "file_type": "regular",
                            "mode": 420,
                            "size": 1024,
                            "uid": 1000,
                            "gid": 1000
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for NfsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::nfs::NfsServer;
            NfsServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
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
            "nfs_lookup_response" => self.execute_nfs_lookup_response(action),
            "nfs_read_response" => self.execute_nfs_read_response(action),
            "nfs_write_response" => self.execute_nfs_write_response(action),
            "nfs_getattr_response" => self.execute_nfs_getattr_response(action),
            "nfs_create_response" => self.execute_nfs_create_response(action),
            "nfs_remove_response" => self.execute_nfs_remove_response(action),
            "nfs_mkdir_response" => self.execute_nfs_mkdir_response(action),
            "nfs_readdir_response" => self.execute_nfs_readdir_response(action),
            "nfs_rename_response" => self.execute_nfs_rename_response(action),
            "nfs_setattr_response" => self.execute_nfs_setattr_response(action),
            _ => Err(anyhow::anyhow!("Unknown NFS action: {}", action_type)),
        }
    }
}

impl NfsProtocol {
    /// NFS LOOKUP response
    fn execute_nfs_lookup_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "fileid": action.get("fileid").and_then(|v| v.as_u64()),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS READ response
    fn execute_nfs_read_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "data": action.get("data").and_then(|v| v.as_str()).unwrap_or(""),
            "eof": action.get("eof").and_then(|v| v.as_bool()).unwrap_or(true),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS WRITE response
    fn execute_nfs_write_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "size": action.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            "mode": action.get("mode").and_then(|v| v.as_u64()).unwrap_or(0o644),
            "mtime": action.get("mtime").and_then(|v| v.as_u64()),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS GETATTR response
    fn execute_nfs_getattr_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "file_type": action.get("file_type").and_then(|v| v.as_str()).unwrap_or("regular"),
            "mode": action.get("mode").and_then(|v| v.as_u64()).unwrap_or(0o644),
            "size": action.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            "uid": action.get("uid").and_then(|v| v.as_u64()).unwrap_or(0),
            "gid": action.get("gid").and_then(|v| v.as_u64()).unwrap_or(0),
            "atime": action.get("atime").and_then(|v| v.as_u64()),
            "mtime": action.get("mtime").and_then(|v| v.as_u64()),
            "ctime": action.get("ctime").and_then(|v| v.as_u64()),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS CREATE response
    fn execute_nfs_create_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "fileid": action.get("fileid").and_then(|v| v.as_u64()),
            "size": action.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            "mode": action.get("mode").and_then(|v| v.as_u64()).unwrap_or(0o644),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS REMOVE response
    fn execute_nfs_remove_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "success": action.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS MKDIR response
    fn execute_nfs_mkdir_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "fileid": action.get("fileid").and_then(|v| v.as_u64()),
            "mode": action.get("mode").and_then(|v| v.as_u64()).unwrap_or(0o755),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS READDIR response
    fn execute_nfs_readdir_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "entries": action.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
            "eof": action.get("eof").and_then(|v| v.as_bool()).unwrap_or(true),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS RENAME response
    fn execute_nfs_rename_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "success": action.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }

    /// NFS SETATTR response
    fn execute_nfs_setattr_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response = json!({
            "size": action.get("size").and_then(|v| v.as_u64()),
            "mode": action.get("mode").and_then(|v| v.as_u64()),
            "mtime": action.get("mtime").and_then(|v| v.as_u64()),
            "error": action.get("error").and_then(|v| v.as_str()),
        });
        Ok(ActionResult::Output(serde_json::to_vec(&response)?))
    }
}

/// Every response action, in the order the operations appear in `NFSFileSystem`.
///
/// This is both `get_sync_actions()` and the action list attached to `nfs_operation`. The
/// event carries the operation name, so the model picks the matching response from this set;
/// there is exactly one event type, and splitting the actions per operation would mean
/// splitting the event type too.
fn nfs_response_actions() -> Vec<ActionDefinition> {
    vec![
        nfs_lookup_response_action(),
        nfs_getattr_response_action(),
        nfs_setattr_response_action(),
        nfs_read_response_action(),
        nfs_write_response_action(),
        nfs_create_response_action(),
        nfs_mkdir_response_action(),
        nfs_remove_response_action(),
        nfs_rename_response_action(),
        nfs_readdir_response_action(),
    ]
}

/// Action definitions
fn nfs_lookup_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_lookup_response".to_string(),
        description: "Return file ID for NFS LOOKUP operation".to_string(),
        parameters: vec![
            Parameter {
                name: "fileid".to_string(),
                type_hint: "number".to_string(),
                description: "File ID (unique identifier) if file exists".to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description:
                    "NFS error code if operation failed (e.g. 'NFS3ERR_NOENT', 'NFS3ERR_ACCES')"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_lookup_response",
            "fileid": 42
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS lookup fileid={fileid}")
                .with_debug("NFS nfs_lookup_response: fileid={fileid}"),
        ),
    }
}

fn nfs_read_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_read_response".to_string(),
        description: "Return file data for NFS READ operation".to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description:
                    "File content to return, as text. Sent to the client verbatim as UTF-8 \
                     bytes; there is no binary or encoded form, so binary files cannot be \
                     served."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "eof".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if end of file reached".to_string(),
                required: true,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_read_response",
            "data": "Hello from NFS!",
            "eof": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS read data")
                .with_debug("NFS nfs_read_response: eof={eof}"),
        ),
    }
}

fn nfs_write_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_write_response".to_string(),
        description: "Return file attributes after NFS WRITE operation".to_string(),
        parameters: vec![
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "New file size after write".to_string(),
                required: true,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "number".to_string(),
                description: "File permissions as a decimal number (420 = 0644, 493 = 0755)"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "mtime".to_string(),
                type_hint: "number".to_string(),
                description: "Modification time (Unix timestamp)".to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_write_response",
            "size": 1024,
            "mode": 420
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS write size={size}")
                .with_debug("NFS nfs_write_response: size={size}, mode={mode}"),
        ),
    }
}

fn nfs_getattr_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_getattr_response".to_string(),
        description: "Return file/directory attributes for NFS GETATTR operation".to_string(),
        parameters: vec![
            Parameter {
                name: "file_type".to_string(),
                type_hint: "string".to_string(),
                description: "'regular' for file, 'directory' for dir".to_string(),
                required: true,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Permissions as a decimal number (420 = 0644 for files, 493 = 0755 for dirs)"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "File size in bytes".to_string(),
                required: true,
            },
            Parameter {
                name: "uid".to_string(),
                type_hint: "number".to_string(),
                description: "Owner user ID".to_string(),
                required: false,
            },
            Parameter {
                name: "gid".to_string(),
                type_hint: "number".to_string(),
                description: "Owner group ID".to_string(),
                required: false,
            },
            Parameter {
                name: "atime".to_string(),
                type_hint: "number".to_string(),
                description: "Access time (Unix timestamp)".to_string(),
                required: false,
            },
            Parameter {
                name: "mtime".to_string(),
                type_hint: "number".to_string(),
                description: "Modification time (Unix timestamp)".to_string(),
                required: false,
            },
            Parameter {
                name: "ctime".to_string(),
                type_hint: "number".to_string(),
                description: "Status change time (Unix timestamp)".to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_getattr_response",
            "file_type": "regular",
            "mode": 420,
            "size": 1024,
            "uid": 1000,
            "gid": 1000
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS attr {file_type} size={size}")
                .with_debug("NFS nfs_getattr_response: type={file_type}, size={size}, mode={mode}"),
        ),
    }
}

fn nfs_create_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_create_response".to_string(),
        description: "Return new file ID and attributes for NFS CREATE operation".to_string(),
        parameters: vec![
            Parameter {
                name: "fileid".to_string(),
                type_hint: "number".to_string(),
                description: "New file ID".to_string(),
                required: true,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "Initial file size (usually 0)".to_string(),
                required: false,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "number".to_string(),
                description: "File permissions".to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_create_response",
            "fileid": 123,
            "size": 0,
            "mode": 420
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS create fileid={fileid}")
                .with_debug("NFS nfs_create_response: fileid={fileid}, mode={mode}"),
        ),
    }
}

fn nfs_remove_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_remove_response".to_string(),
        description: "Return success/error for NFS REMOVE operation".to_string(),
        parameters: vec![
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if file was removed successfully".to_string(),
                required: true,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_remove_response",
            "success": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS remove success={success}")
                .with_debug("NFS nfs_remove_response: success={success}"),
        ),
    }
}

fn nfs_mkdir_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_mkdir_response".to_string(),
        description: "Return new directory ID for NFS MKDIR operation".to_string(),
        parameters: vec![
            Parameter {
                name: "fileid".to_string(),
                type_hint: "number".to_string(),
                description: "New directory ID".to_string(),
                required: true,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "number".to_string(),
                description: "Directory permissions as a decimal number (default 493 = 0755)"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_mkdir_response",
            "fileid": 456,
            "mode": 493
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS mkdir fileid={fileid}")
                .with_debug("NFS nfs_mkdir_response: fileid={fileid}, mode={mode}"),
        ),
    }
}

fn nfs_readdir_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_readdir_response".to_string(),
        description: "Return directory listing for NFS READDIR operation".to_string(),
        parameters: vec![
            Parameter {
                name: "entries".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of directory entries [{\"name\": \"file.txt\", \"fileid\": 42}, ...]"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "eof".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if no more entries".to_string(),
                required: true,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_readdir_response",
            "entries": [
                {"name": "file.txt", "fileid": 42},
                {"name": "subdir", "fileid": 43}
            ],
            "eof": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS readdir {entries_len} entries")
                .with_debug("NFS nfs_readdir_response: {entries_len} entries, eof={eof}"),
        ),
    }
}

fn nfs_rename_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_rename_response".to_string(),
        description: "Return success/error for NFS RENAME operation".to_string(),
        parameters: vec![
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if file was renamed successfully".to_string(),
                required: true,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_rename_response",
            "success": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS rename success={success}")
                .with_debug("NFS nfs_rename_response: success={success}"),
        ),
    }
}

fn nfs_setattr_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "nfs_setattr_response".to_string(),
        description: "Return updated attributes for NFS SETATTR operation".to_string(),
        parameters: vec![
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "New file size".to_string(),
                required: false,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "number".to_string(),
                description: "New permissions".to_string(),
                required: false,
            },
            Parameter {
                name: "mtime".to_string(),
                type_hint: "number".to_string(),
                description: "New modification time".to_string(),
                required: false,
            },
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "NFS error code if operation failed".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "nfs_setattr_response",
            "mode": 384
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NFS setattr")
                .with_debug("NFS nfs_setattr_response: mode={mode}"),
        ),
    }
}

// ============================================================================
// NFS Event Type Constants
// ============================================================================

/// NFS operation event - triggered when NFS client requests a filesystem operation
///
/// The action list is the whole protocol. `call_llm` builds the model's vocabulary from
/// `event.event_type.actions`, **not** from `get_sync_actions()`, so the empty
/// `.with_actions(vec![])` this used to carry meant the model was offered `set_memory`,
/// `show_message` and nothing else: every `nfs_*_response` it produced was rejected as an
/// unknown action, retried twice, and failed. No NFS operation could ever be answered.
pub static NFS_OPERATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfs_operation",
        "NFS client requested a filesystem operation",
        json!({"type": "nfs_getattr_response", "file_type": "regular", "mode": 420, "size": 13}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The NFS operation type (lookup, getattr, setattr, read, write, create, mkdir, remove, rename, readdir, symlink, readlink)".to_string(),
            required: true,
        },
        Parameter {
            name: "params".to_string(),
            type_hint: "object".to_string(),
            description: "Operation-specific parameters (fileid, dirid, filename, offset, count, data, ...)".to_string(),
            required: true,
        },
    ])
    // The model must be able to answer every operation, and only the operation field tells it
    // which response to pick, so all response actions are advertised on the one event.
    .with_actions(nfs_response_actions())
    .with_alternative_example(json!({
        "type": "nfs_lookup_response",
        "fileid": 2
    }))
    .with_alternative_example(json!({
        "type": "nfs_read_response",
        "data": "Hello from NFS",
        "eof": true
    }))
    .with_alternative_example(json!({
        "type": "nfs_readdir_response",
        "entries": [{"name": "readme.txt", "fileid": 2}],
        "eof": true
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("NFS {operation}")
            .with_debug("NFS {operation}: {params}")
            .with_trace("NFS: {json_pretty(.)}"),
    )
});

/// Get NFS event types
pub fn get_nfs_event_types() -> Vec<EventType> {
    vec![NFS_OPERATION_EVENT.clone()]
}
