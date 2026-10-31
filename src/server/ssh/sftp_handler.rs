//! SFTP handler with LLM integration
//!
//! This module implements an SFTP server handler that delegates all
//! filesystem operations to the LLM, creating a virtual filesystem
//! entirely controlled by the AI.

use super::actions::SFTP_OPERATION_EVENT;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::SshProtocol;
use crate::state::app_state::AppState;
use crate::utils::WireFailure;
use anyhow::Result;
use russh_sftp::protocol::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

/// LLM-controlled SFTP handler
///
/// This handler implements the russh_sftp::server::Handler trait
/// but delegates all filesystem decisions to the LLM instead of
/// using a real filesystem.
pub struct LlmSftpHandler {
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    protocol: Arc<SshProtocol>,
    status_tx: mpsc::UnboundedSender<String>,
    /// Track handles that the LLM creates
    handles: Arc<Mutex<HashMap<String, HandleInfo>>>,
    /// SFTP protocol version
    version: Option<u32>,
    /// The SSH connection's owner; see `super::until_owner_drops`.
    owner: CancellationToken,
}

/// The action names that count as an answer to an `sftp_operation` event.
fn is_sftp_reply_action(name: &str) -> bool {
    matches!(
        name,
        "sftp_handle"
            | "sftp_directory_listing"
            | "sftp_file_content"
            | "sftp_file_attributes"
            | "sftp_error"
    )
}

/// If the handler answered with `sftp_error`, map its `code` to an SFTP status code.
///
/// Returns `None` when the response is not an error, so callers can carry on.
fn sftp_error_status(response: &serde_json::Value) -> Option<StatusCode> {
    if response.get("type").and_then(|v| v.as_str()) != Some("sftp_error") {
        return None;
    }
    let code = response
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("no_such_file");
    Some(match code {
        "no_such_file" => StatusCode::NoSuchFile,
        "permission_denied" => StatusCode::PermissionDenied,
        "op_unsupported" => StatusCode::OpUnsupported,
        "eof" => StatusCode::Eof,
        _ => StatusCode::Failure,
    })
}

/// What a backend failure is reported to the SFTP client as.
///
/// SFTP v3 defines only OK, EOF, NO_SUCH_FILE, PERMISSION_DENIED, FAILURE, BAD_MESSAGE,
/// NO_CONNECTION, CONNECTION_LOST and OP_UNSUPPORTED — there is no "busy, try again". So both
/// [`WireFailure`] categories land on FAILURE and the distinction is kept in the log, where
/// `llm_sftp_operation` records it alongside the operation name.
///
/// FAILURE rather than NO_SUCH_FILE, which several of these paths used to return: "the handler
/// that answers questions about this tree is unreachable" is a different statement from "this
/// path does not exist", and the second one is a permanent lie about the filesystem that a
/// client may cache and a script will branch on.
const BACKEND_FAILURE_STATUS: StatusCode = StatusCode::Failure;

/// True when the handler produced nothing that could be an SFTP reply.
///
/// `llm_sftp_operation` falls back to `{}` when the response carried zero actions. Every reader
/// below then finds its field missing and substitutes a default — a handle equal to the
/// requested path, `0o100644` attributes, empty content — so silence *invented* a directory, a
/// file or a stat for any path asked about, and a model that said nothing "opened" everything.
/// Silence is not an answer: fail closed, exactly as an unreachable backend does.
///
/// A named action that is not one of the SFTP replies counts as silence too — the fallback in
/// `llm_sftp_operation` hands back the first action when none of them is an SFTP reply, so a
/// lone `notify_operator` would otherwise be read as an answer and defaulted in exactly the same
/// way. A bare object with no `type` is still accepted: that is the shape a script handler
/// returns, and its fields are the answer.
fn sftp_no_answer(response: &serde_json::Value) -> bool {
    let Some(obj) = response.as_object() else {
        return true;
    };
    if obj.is_empty() {
        return true;
    }
    match obj.get("type").and_then(|v| v.as_str()) {
        Some(name) => !is_sftp_reply_action(name),
        None => false,
    }
}

/// Information about an open handle
#[derive(Debug, Clone)]
struct HandleInfo {
    path: String,
    #[allow(dead_code)] // Tracked for correctness but not currently used in logic
    is_directory: bool,
    /// For directories, track if we've completed reading
    dir_read_done: bool,
}

impl LlmSftpHandler {
    /// Create a new LLM-controlled SFTP handler
    pub fn new(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        protocol: Arc<SshProtocol>,
        status_tx: mpsc::UnboundedSender<String>,
        owner: CancellationToken,
    ) -> Self {
        Self {
            connection_id,
            server_id,
            llm_client,
            app_state,
            protocol,
            status_tx,
            handles: Arc::new(Mutex::new(HashMap::new())),
            version: None,
            owner,
        }
    }

    /// Ask the handler/LLM to answer an SFTP operation.
    ///
    /// `params` carries structured fields (`path`, `handle`, `offset`, `length`) that are
    /// merged into the event alongside `operation`. They used to be flattened into a single
    /// `params` string like `"path='/x', id=3"`, which a script handler had to re-parse and
    /// which violated the structured-data rule for event payloads.
    async fn llm_sftp_operation(
        &self,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        // DEBUG: LLM request summary
        debug!(
            "SFTP LLM request: operation={}, params={}",
            operation, params
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP LLM request: operation={}, params={}",
            operation, params
        ));

        // Create SFTP operation event
        let mut event_data = serde_json::json!({ "operation": operation });
        if let Some(fields) = params.as_object() {
            for (key, value) in fields {
                event_data[key] = value.clone();
            }
        }
        let event = Event::new(&SFTP_OPERATION_EVENT, event_data);

        // TRACE: Event details
        trace!("SFTP calling LLM for operation: {}", operation);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP calling LLM for operation: {}",
            operation
        ));

        // Call LLM with Event-based approach
        match super::until_owner_drops(
            &self.owner,
            call_llm(
                &self.llm_client,
                &self.app_state,
                self.server_id,
                Some(self.connection_id),
                &event,
                self.protocol.as_ref(),
            ),
        )
        .await
        {
            Ok(execution_result) => {
                // Display messages from LLM
                for message in &execution_result.messages {
                    info!("{}", message);
                    let _ = self.status_tx.send(format!("[INFO] {}", message));
                }

                // DEBUG: LLM response summary
                debug!(
                    "SFTP LLM returned {} actions for operation: {}",
                    execution_result.raw_actions.len(),
                    operation
                );
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP LLM returned {} actions for operation: {}",
                    execution_result.raw_actions.len(),
                    operation
                ));

                // TRACE: Full response
                if !execution_result.raw_actions.is_empty() {
                    let pretty = serde_json::to_string_pretty(&execution_result.raw_actions[0])
                        .unwrap_or_else(|_| format!("{:?}", execution_result.raw_actions[0]));
                    trace!("SFTP LLM response ({}) JSON:\n{}", operation, pretty);
                    let _ = self.status_tx.send(format!(
                        "[TRACE] SFTP LLM response ({}) JSON:\r\n{}",
                        operation,
                        pretty.replace('\n', "\r\n")
                    ));
                }

                // SFTP expects exactly one reply per request. Prefer the first action that is
                // actually an SFTP reply, so a leading notify_operator/set_memory does not get
                // mistaken for the answer. Fall back to the first action for handlers that
                // return a bare object with no "type".
                let reply = execution_result
                    .raw_actions
                    .iter()
                    .find(|a| {
                        a.get("type")
                            .and_then(|v| v.as_str())
                            .is_some_and(is_sftp_reply_action)
                    })
                    .or_else(|| execution_result.raw_actions.first())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                Ok(reply)
            }
            Err(e) => {
                // Return the error unwrapped. It used to be re-created with
                // `anyhow!("LLM error: {}", e)`, which discards the concrete error type —
                // and `is_overload_error` works by downcasting, so every SFTP failure was
                // classified as a generic one and a saturated backend was indistinguishable
                // from a broken one. `context()`/plain propagation keep the chain intact.
                let failure = WireFailure::classify(&e);
                error!(
                    "SFTP {}: decision=fail_closed_backend_error category={:?}: {}",
                    operation, failure, e
                );
                let _ = self.status_tx.send(format!(
                    "[ERROR] SFTP {}: decision=fail_closed_backend_error category={:?}",
                    operation, failure
                ));
                Err(e)
            }
        }
    }
}

impl russh_sftp::server::Handler for LlmSftpHandler {
    type Error = StatusCode;

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        info!(
            "SFTP init: version={}, extensions={:?}",
            version, extensions
        );
        self.version = Some(version);

        // Send status update
        let _ = self
            .status_tx
            .send(format!("SFTP session initialized (v{})", version));

        // Return version 3 (most widely supported)
        Ok(Version::new())
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        // DEBUG: SFTP request summary
        debug!("SFTP request: SSH_FXP_OPENDIR id={}, path={}", id, path);
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_OPENDIR id={}, path={}",
            id, path
        ));

        // TRACE: Full SFTP request
        trace!("SFTP SSH_FXP_OPENDIR request: id={}, path='{}'", id, path);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_OPENDIR request: id={}, path='{}'",
            id, path
        ));

        let params = serde_json::json!({ "path": path });
        match self.llm_sftp_operation("opendir", params).await {
            Ok(response) => {
                if let Some(status) = sftp_error_status(&response) {
                    debug!("SFTP opendir refused by handler for {}: {:?}", path, status);
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP opendir for {path}: decision=model_reject"
                    ));
                    return Err(status);
                }

                if sftp_no_answer(&response) {
                    error!("SFTP opendir for {}: decision=fail_closed_no_answer", path);
                    let _ = self.status_tx.send(format!(
                        "[ERROR] SFTP opendir for {path}: decision=fail_closed_no_answer"
                    ));
                    return Err(BACKEND_FAILURE_STATUS);
                }

                // LLM should return a handle for this directory
                let handle_str = response
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&path)
                    .to_string();

                // Store handle info
                self.handles.lock().await.insert(
                    handle_str.clone(),
                    HandleInfo {
                        path: path.clone(),
                        is_directory: true,
                        dir_read_done: false,
                    },
                );

                let _ = self
                    .status_tx
                    .send(format!("→ SFTP opened directory: {}", path));

                // DEBUG: SFTP response summary
                debug!(
                    "SFTP response: SSH_FXP_HANDLE id={}, handle_len={} bytes",
                    id,
                    handle_str.len()
                );
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_HANDLE id={}, handle_len={} bytes",
                    id,
                    handle_str.len()
                ));

                // TRACE: Full SFTP response
                trace!(
                    "SFTP SSH_FXP_HANDLE response: id={}, handle='{}'",
                    id,
                    handle_str
                );
                let _ = self.status_tx.send(format!(
                    "[TRACE] SFTP SSH_FXP_HANDLE response: id={}, handle='{}'",
                    id, handle_str
                ));

                Ok(Handle {
                    id,
                    handle: handle_str,
                })
            }
            Err(_) => {
                // Already logged with its category by `llm_sftp_operation`.
                debug!("SFTP response: SSH_FXP_STATUS id={}, status=FAILURE", id);
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=FAILURE (opendir '{}')",
                    id, path
                ));

                Err(BACKEND_FAILURE_STATUS)
            }
        }
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        // DEBUG: SFTP request summary
        debug!(
            "SFTP request: SSH_FXP_READDIR id={}, handle_len={} bytes",
            id,
            handle.len()
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_READDIR id={}, handle_len={} bytes",
            id,
            handle.len()
        ));

        // TRACE: Full SFTP request
        trace!(
            "SFTP SSH_FXP_READDIR request: id={}, handle='{}'",
            id,
            handle
        );
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_READDIR request: id={}, handle='{}'",
            id, handle
        ));

        // Check if we've already read this directory
        let mut handles = self.handles.lock().await;
        if let Some(handle_info) = handles.get_mut(&handle) {
            if handle_info.dir_read_done {
                // DEBUG: SFTP EOF response
                debug!(
                    "SFTP response: SSH_FXP_STATUS id={}, status=EOF (directory already read)",
                    id
                );
                let _ = self.status_tx.send(format!("[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=EOF (directory already read)", id));

                return Err(StatusCode::Eof);
            }

            let path = handle_info.path.clone();
            drop(handles); // Release lock before async operation

            let params = serde_json::json!({ "path": path, "handle": handle });
            match self.llm_sftp_operation("readdir", params).await {
                Ok(response) => {
                    if let Some(status) = sftp_error_status(&response) {
                        debug!(
                            "SFTP readdir for {}: decision=model_reject ({:?})",
                            path, status
                        );
                        return Err(status);
                    }

                    if sftp_no_answer(&response) {
                        // An empty listing is a legitimate answer and looks nothing like this:
                        // it arrives as `sftp_directory_listing` with no `entries`. A reply
                        // with no fields at all means the handler said nothing.
                        error!("SFTP readdir for {}: decision=fail_closed_no_answer", path);
                        let _ = self.status_tx.send(format!(
                            "[ERROR] SFTP readdir for {path}: decision=fail_closed_no_answer"
                        ));
                        return Err(BACKEND_FAILURE_STATUS);
                    }

                    // Parse file list from LLM
                    let files = response
                        .get("entries")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|entry| {
                                    // Only 'name' is load-bearing. is_dir/size used to be
                                    // fetched with `?`, so an entry that omitted either was
                                    // silently dropped from the listing.
                                    let name = entry.get("name")?.as_str()?.to_string();
                                    let is_dir = entry
                                        .get("is_dir")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    let size =
                                        entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

                                    // Set permissions: 0755 for dirs, 0644 for files
                                    let attrs = FileAttributes {
                                        size: Some(size),
                                        permissions: Some(if is_dir { 0o40755 } else { 0o100644 }),
                                        ..Default::default()
                                    };

                                    Some(File::new(name, attrs))
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    // Mark directory as read
                    if let Some(h) = self.handles.lock().await.get_mut(&handle) {
                        h.dir_read_done = true;
                    }

                    let _ = self.status_tx.send(format!(
                        "→ SFTP listed {} items in {}",
                        files.len(),
                        path
                    ));

                    // DEBUG: SFTP response summary
                    debug!(
                        "SFTP response: SSH_FXP_NAME id={}, file_count={}",
                        id,
                        files.len()
                    );
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP response: SSH_FXP_NAME id={}, file_count={}",
                        id,
                        files.len()
                    ));

                    // TRACE: Full SFTP response
                    let file_names: Vec<&str> = files.iter().map(|f| f.filename.as_str()).collect();
                    trace!(
                        "SFTP SSH_FXP_NAME response: id={}, files={:?}",
                        id,
                        file_names
                    );
                    let _ = self.status_tx.send(format!(
                        "[TRACE] SFTP SSH_FXP_NAME response: id={}, files={:?}",
                        id, file_names
                    ));

                    Ok(Name { id, files })
                }
                Err(_) => {
                    // Already logged with its category by `llm_sftp_operation`.
                    debug!("SFTP response: SSH_FXP_STATUS id={}, status=FAILURE", id);
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=FAILURE (readdir '{}')",
                        id, handle
                    ));

                    Err(BACKEND_FAILURE_STATUS)
                }
            }
        } else {
            error!("SFTP readdir: invalid handle {}", handle);
            let _ = self
                .status_tx
                .send(format!("[ERROR] SFTP readdir: invalid handle {}", handle));

            // DEBUG: SFTP error response
            debug!(
                "SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            );
            let _ = self.status_tx.send(format!(
                "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            ));

            Err(StatusCode::BadMessage)
        }
    }

    async fn open(
        &mut self,
        id: u32,
        path: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        // DEBUG: SFTP request summary
        debug!(
            "SFTP request: SSH_FXP_OPEN id={}, path={}, flags={:?}",
            id, path, pflags
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_OPEN id={}, path={}, flags={:?}",
            id, path, pflags
        ));

        // TRACE: Full SFTP request
        trace!(
            "SFTP SSH_FXP_OPEN request: id={}, path='{}', flags={:?}",
            id,
            path,
            pflags
        );
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_OPEN request: id={}, path='{}', flags={:?}",
            id, path, pflags
        ));

        let params = serde_json::json!({ "path": path });
        match self.llm_sftp_operation("open", params).await {
            Ok(response) => {
                if let Some(status) = sftp_error_status(&response) {
                    debug!("SFTP open refused by handler for {}: {:?}", path, status);
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP open for {path}: decision=model_reject"
                    ));
                    return Err(status);
                }

                if sftp_no_answer(&response) {
                    error!("SFTP open for {}: decision=fail_closed_no_answer", path);
                    let _ = self.status_tx.send(format!(
                        "[ERROR] SFTP open for {path}: decision=fail_closed_no_answer"
                    ));
                    return Err(BACKEND_FAILURE_STATUS);
                }

                let handle_str = response
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&path)
                    .to_string();

                // Store handle info
                self.handles.lock().await.insert(
                    handle_str.clone(),
                    HandleInfo {
                        path: path.clone(),
                        is_directory: false,
                        dir_read_done: false,
                    },
                );

                let _ = self.status_tx.send(format!("→ SFTP opened file: {}", path));

                // DEBUG: SFTP response summary
                debug!(
                    "SFTP response: SSH_FXP_HANDLE id={}, handle_len={} bytes",
                    id,
                    handle_str.len()
                );
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_HANDLE id={}, handle_len={} bytes",
                    id,
                    handle_str.len()
                ));

                // TRACE: Full SFTP response
                trace!(
                    "SFTP SSH_FXP_HANDLE response: id={}, handle='{}'",
                    id,
                    handle_str
                );
                let _ = self.status_tx.send(format!(
                    "[TRACE] SFTP SSH_FXP_HANDLE response: id={}, handle='{}'",
                    id, handle_str
                ));

                Ok(Handle {
                    id,
                    handle: handle_str,
                })
            }
            Err(_) => {
                // Already logged with its category by `llm_sftp_operation`.
                debug!("SFTP response: SSH_FXP_STATUS id={}, status=FAILURE", id);
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=FAILURE (open '{}')",
                    id, path
                ));

                Err(BACKEND_FAILURE_STATUS)
            }
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        // DEBUG: SFTP request summary
        debug!(
            "SFTP request: SSH_FXP_READ id={}, offset={}, len={} bytes",
            id, offset, len
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_READ id={}, offset={}, len={} bytes",
            id, offset, len
        ));

        // TRACE: Full SFTP request
        trace!(
            "SFTP SSH_FXP_READ request: id={}, handle='{}', offset={}, len={}",
            id,
            handle,
            offset,
            len
        );
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_READ request: id={}, handle='{}', offset={}, len={}",
            id, handle, offset, len
        ));

        let handles = self.handles.lock().await;
        if let Some(handle_info) = handles.get(&handle) {
            let path = handle_info.path.clone();
            drop(handles);

            let params = serde_json::json!({
                "path": path,
                "handle": handle,
                "offset": offset,
                "length": len,
            });
            match self.llm_sftp_operation("read", params).await {
                Ok(response) => {
                    if let Some(status) = sftp_error_status(&response) {
                        debug!(
                            "SFTP read for {}: decision=model_reject ({:?})",
                            path, status
                        );
                        return Err(status);
                    }

                    if sftp_no_answer(&response) {
                        // Without this the missing `content` defaults to "", `offset >= 0` is
                        // immediately past the end, and the client is told EOF — i.e. it
                        // downloads a successful zero-byte file and reports no error at all.
                        error!("SFTP read for {}: decision=fail_closed_no_answer", path);
                        let _ = self.status_tx.send(format!(
                            "[ERROR] SFTP read for {path}: decision=fail_closed_no_answer"
                        ));
                        return Err(BACKEND_FAILURE_STATUS);
                    }

                    // Get file content from LLM
                    let content = response
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // The handler returns the WHOLE file; apply the requested window here.
                    // Returning the full content for every request made a client that reads
                    // in chunks receive the file repeatedly and never see EOF.
                    let full = content.as_bytes();
                    let start = usize::try_from(offset).unwrap_or(usize::MAX);
                    if start >= full.len() {
                        debug!(
                            "SFTP response: SSH_FXP_STATUS id={}, status=EOF (offset {} >= size {})",
                            id,
                            offset,
                            full.len()
                        );
                        return Err(StatusCode::Eof);
                    }
                    let end = start.saturating_add(len as usize).min(full.len());
                    let data = full[start..end].to_vec();
                    let actual_len = data.len();

                    let _ = self
                        .status_tx
                        .send(format!("→ SFTP read {} bytes from {}", actual_len, path));

                    // DEBUG: SFTP response summary
                    debug!(
                        "SFTP response: SSH_FXP_DATA id={}, data_len={} bytes",
                        id, actual_len
                    );
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP response: SSH_FXP_DATA id={}, data_len={} bytes",
                        id, actual_len
                    ));

                    // TRACE: Full SFTP response (truncate if too long)
                    if actual_len <= 256 {
                        trace!(
                            "SFTP SSH_FXP_DATA response: id={}, data={:?}",
                            id,
                            String::from_utf8_lossy(&data)
                        );
                        let _ = self.status_tx.send(format!(
                            "[TRACE] SFTP SSH_FXP_DATA response: id={}, data={:?}",
                            id,
                            String::from_utf8_lossy(&data)
                        ));
                    } else {
                        trace!(
                            "SFTP SSH_FXP_DATA response: id={}, data_len={} bytes (truncated)",
                            id,
                            actual_len
                        );
                        let _ = self.status_tx.send(format!("[TRACE] SFTP SSH_FXP_DATA response: id={}, data_len={} bytes (truncated)", id, actual_len));
                    }

                    Ok(Data { id, data })
                }
                Err(_) => {
                    // FAILURE, not EOF. EOF is a *successful* end-of-file: a client that gets
                    // it at offset 0 writes out a complete zero-byte file and exits 0, so a
                    // backend outage silently truncated every download. Already logged with
                    // its category by `llm_sftp_operation`.
                    debug!("SFTP response: SSH_FXP_STATUS id={}, status=FAILURE", id);
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=FAILURE (read '{}')",
                        id, handle
                    ));

                    Err(BACKEND_FAILURE_STATUS)
                }
            }
        } else {
            error!("SFTP read: invalid handle {}", handle);
            let _ = self
                .status_tx
                .send(format!("[ERROR] SFTP read: invalid handle {}", handle));

            // DEBUG: SFTP error response
            debug!(
                "SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            );
            let _ = self.status_tx.send(format!(
                "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            ));

            Err(StatusCode::BadMessage)
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        // DEBUG: SFTP request summary
        debug!(
            "SFTP request: SSH_FXP_CLOSE id={}, handle_len={} bytes",
            id,
            handle.len()
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_CLOSE id={}, handle_len={} bytes",
            id,
            handle.len()
        ));

        // TRACE: Full SFTP request
        trace!("SFTP SSH_FXP_CLOSE request: id={}, handle='{}'", id, handle);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_CLOSE request: id={}, handle='{}'",
            id, handle
        ));

        // Remove handle from tracking
        if let Some(handle_info) = self.handles.lock().await.remove(&handle) {
            let _ = self
                .status_tx
                .send(format!("→ SFTP closed: {}", handle_info.path));

            // DEBUG: SFTP response summary
            debug!(
                "SFTP response: SSH_FXP_STATUS id={}, status=OK (closed '{}')",
                id, handle_info.path
            );
            let _ = self.status_tx.send(format!(
                "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=OK (closed '{}')",
                id, handle_info.path
            ));

            // TRACE: Full SFTP response
            trace!(
                "SFTP SSH_FXP_STATUS response: id={}, status=OK, path='{}'",
                id,
                handle_info.path
            );
            let _ = self.status_tx.send(format!(
                "[TRACE] SFTP SSH_FXP_STATUS response: id={}, status=OK, path='{}'",
                id, handle_info.path
            ));
        } else {
            // DEBUG: Unknown handle closed (still return OK per SFTP spec)
            debug!(
                "SFTP response: SSH_FXP_STATUS id={}, status=OK (unknown handle)",
                id
            );
            let _ = self.status_tx.send(format!(
                "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=OK (unknown handle)",
                id
            ));
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        // DEBUG: SFTP request summary
        debug!("SFTP request: SSH_FXP_LSTAT id={}, path={}", id, path);
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_LSTAT id={}, path={}",
            id, path
        ));

        // TRACE: Full SFTP request
        trace!("SFTP SSH_FXP_LSTAT request: id={}, path='{}'", id, path);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_LSTAT request: id={}, path='{}'",
            id, path
        ));

        let params = serde_json::json!({ "path": path });
        match self.llm_sftp_operation("lstat", params).await {
            Ok(response) => {
                if let Some(status) = sftp_error_status(&response) {
                    debug!("SFTP lstat refused by handler for {}: {:?}", path, status);
                    let _ = self.status_tx.send(format!(
                        "[DEBUG] SFTP lstat for {path}: decision=model_reject"
                    ));
                    return Err(status);
                }

                if sftp_no_answer(&response) {
                    // Otherwise every field below falls back to its default and the client is
                    // told the path exists as a 0-byte 0o100644 file — so a handler that said
                    // nothing stats *any* path successfully, including ones it would have
                    // refused. That is the fail-open shape CLAUDE.md calls the most dangerous
                    // pattern here.
                    error!("SFTP lstat for {}: decision=fail_closed_no_answer", path);
                    let _ = self.status_tx.send(format!(
                        "[ERROR] SFTP lstat for {path}: decision=fail_closed_no_answer"
                    ));
                    return Err(BACKEND_FAILURE_STATUS);
                }

                let mut attrs = FileAttributes::default();

                // Parse attributes from LLM response
                if let Some(size) = response.get("size").and_then(|v| v.as_u64()) {
                    attrs.size = Some(size);
                }

                // The mode's *type* bits are what a client reads to decide whether an entry is
                // a file or a directory, so they must always be set explicitly.
                //
                // This used to OR in `S_IFDIR` when `is_dir` was true and otherwise leave
                // `FileAttributes::default()` alone — and russh-sftp's default is `0o40777`,
                // a directory. So a handler answering `{"size": 23, "is_dir": false}` had its
                // file reported to the client as a **directory**: `ls -l` showed `d`, and
                // clients that check the type before downloading refused it. `is_dir: false`
                // was, in effect, ignored. The defaults below match what `readdir` already
                // uses for the same entries, so the two views agree.
                let is_dir = response
                    .get("is_dir")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let type_bit = if is_dir { 0o40000 } else { 0o100000 };
                attrs.permissions =
                    Some(match response.get("permissions").and_then(|v| v.as_u64()) {
                        // A handler that supplied the type bits itself is taken at its word.
                        Some(perms) if perms & 0o170000 != 0 => perms as u32,
                        Some(perms) => perms as u32 | type_bit,
                        None if is_dir => 0o40755,
                        None => 0o100644,
                    });

                // DEBUG: SFTP response summary
                debug!(
                    "SFTP response: SSH_FXP_ATTRS id={}, size={:?}, perms={:?}",
                    id, attrs.size, attrs.permissions
                );
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_ATTRS id={}, size={:?}, perms={:?}",
                    id, attrs.size, attrs.permissions
                ));

                // TRACE: Full SFTP response
                trace!(
                    "SFTP SSH_FXP_ATTRS response: id={}, path='{}', attrs={:?}",
                    id,
                    path,
                    attrs
                );
                let _ = self.status_tx.send(format!(
                    "[TRACE] SFTP SSH_FXP_ATTRS response: id={}, path='{}', attrs={:?}",
                    id, path, attrs
                ));

                Ok(Attrs { id, attrs })
            }
            Err(_) => {
                // Already logged with its category by `llm_sftp_operation`.
                debug!("SFTP response: SSH_FXP_STATUS id={}, status=FAILURE", id);
                let _ = self.status_tx.send(format!(
                    "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=FAILURE (lstat '{}')",
                    id, path
                ));

                Err(BACKEND_FAILURE_STATUS)
            }
        }
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        // DEBUG: SFTP request summary
        debug!(
            "SFTP request: SSH_FXP_FSTAT id={}, handle_len={} bytes",
            id,
            handle.len()
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_FSTAT id={}, handle_len={} bytes",
            id,
            handle.len()
        ));

        // TRACE: Full SFTP request
        trace!("SFTP SSH_FXP_FSTAT request: id={}, handle='{}'", id, handle);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_FSTAT request: id={}, handle='{}'",
            id, handle
        ));

        let handles = self.handles.lock().await;
        if let Some(handle_info) = handles.get(&handle) {
            let path = handle_info.path.clone();
            drop(handles);

            // Delegate to lstat (which will log the lstat request/response)
            trace!("SFTP fstat delegating to lstat for path: '{}'", path);
            let _ = self.status_tx.send(format!(
                "[TRACE] SFTP fstat delegating to lstat for path: '{}'",
                path
            ));
            self.lstat(id, path).await
        } else {
            error!("SFTP fstat: invalid handle {}", handle);
            let _ = self
                .status_tx
                .send(format!("[ERROR] SFTP fstat: invalid handle {}", handle));

            // DEBUG: SFTP error response
            debug!(
                "SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            );
            let _ = self.status_tx.send(format!(
                "[DEBUG] SFTP response: SSH_FXP_STATUS id={}, status=BAD_MESSAGE",
                id
            ));

            Err(StatusCode::BadMessage)
        }
    }

    /// `SSH_FXP_STAT` — the follow-symlinks form of `lstat`.
    ///
    /// This used to fall through to `unimplemented()` and answer `SSH_FX_OP_UNSUPPORTED`, so
    /// `sftp.stat(path)` — what every client calls to size a file before downloading it, and
    /// what `sftp -P … ls -l` uses — failed against a server whose `lstat` worked fine. There
    /// is no filesystem behind this handler and therefore no symlink for the two calls to
    /// disagree about, so `stat` is `lstat`, exactly as `fstat` already is once its handle is
    /// resolved. The handler still sees a single `lstat` operation and needs no new vocabulary.
    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        debug!("SFTP request: SSH_FXP_STAT id={}, path={}", id, path);
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_STAT id={}, path={}",
            id, path
        ));
        trace!("SFTP stat delegating to lstat for path: '{}'", path);
        self.lstat(id, path).await
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // DEBUG: SFTP request summary
        debug!("SFTP request: SSH_FXP_REALPATH id={}, path={}", id, path);
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP request: SSH_FXP_REALPATH id={}, path={}",
            id, path
        ));

        // TRACE: Full SFTP request
        trace!("SFTP SSH_FXP_REALPATH request: id={}, path='{}'", id, path);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_REALPATH request: id={}, path='{}'",
            id, path
        ));

        // Answered locally - the handler is not consulted. OpenSSH opens every session with
        // realpath("."), and echoing "." straight back leaves the client with a relative
        // working directory that every later path is resolved against; map it to "/".
        let path = if path.is_empty() || path == "." {
            "/".to_string()
        } else {
            path
        };

        let attrs = FileAttributes::default();
        let file = File::new(path.clone(), attrs);

        // DEBUG: SFTP response summary
        debug!(
            "SFTP response: SSH_FXP_NAME id={}, resolved_path={}",
            id, path
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] SFTP response: SSH_FXP_NAME id={}, resolved_path={}",
            id, path
        ));

        // TRACE: Full SFTP response
        trace!("SFTP SSH_FXP_NAME response: id={}, path='{}'", id, path);
        let _ = self.status_tx.send(format!(
            "[TRACE] SFTP SSH_FXP_NAME response: id={}, path='{}'",
            id, path
        ));

        Ok(Name {
            id,
            files: vec![file],
        })
    }

    fn unimplemented(&self) -> Self::Error {
        error!("SFTP unimplemented packet received");
        let _ = self
            .status_tx
            .send("[ERROR] SFTP unimplemented packet received".to_string());
        StatusCode::OpUnsupported
    }
}
