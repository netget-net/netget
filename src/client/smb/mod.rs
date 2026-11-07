//! SMB client implementation
pub mod actions;

pub use actions::SmbClientProtocol;

use crate::llm::actions::client_trait::Client;
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::smb::actions::{
    SMB_CLIENT_CONNECTED_EVENT, SMB_CLIENT_DIR_LISTED_EVENT, SMB_CLIENT_ERROR_EVENT,
    SMB_CLIENT_FILE_READ_EVENT, SMB_CLIENT_FILE_WRITTEN_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

use pavao::{
    SmbClient as PavaoSmbClient, SmbCredentials, SmbDirent, SmbDirentType, SmbOpenOptions,
    SmbOptions,
};
use std::io::{Read as IoRead, Write as IoWrite};
use tokio::sync::Mutex;

/// The live libsmbclient handle, shared by the LLM task and the command loop.
///
/// Every native call runs on a blocking worker; its file handles are created and
/// dropped on that worker. The async mutex serializes operations before spawning
/// work, and no native handle or guard survives into a model event dispatch.
type SharedSmb = Arc<Mutex<NativeSmb>>;
// pavao 0.2 owns one process-global native context; dropping any SmbClient frees it.
// Refuse a second live owner rather than letting it invalidate the first session.
static NATIVE_SESSION: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));
struct NativeSmb {
    client: Option<PavaoSmbClient>,
    lease: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for NativeSmb {
    fn drop(&mut self) {
        let client = self.client.take();
        let lease = self.lease.take();
        let cleanup = move || {
            drop(client);
            drop(lease);
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(cleanup);
        } else {
            std::thread::spawn(cleanup);
        }
    }
}

/// Buffered file contents forwarded into model events are capped independently of SMB packets.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// Read at most one byte beyond the cap, refusing partial data instead of claiming success.
pub fn read_file_bounded(reader: impl IoRead) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SMB file exceeds buffered byte cap",
        ));
    }
    Ok(data)
}

async fn blocking_smb<T: Send + 'static>(
    client: &SharedSmb,
    operation: impl FnOnce(&PavaoSmbClient) -> Result<T> + Send + 'static,
) -> Result<T> {
    let client = client.clone().lock_owned().await;
    tokio::task::spawn_blocking(move || {
        operation(client.client.as_ref().context("SMB client is closed")?)
    })
    .await
    .context("SMB worker panicked")?
}

/// What applying one action against the SMB share actually did.
///
/// SMB never yields [`crate::state::client_handles::ClientSendOutcome::Sent`]:
/// libsmbclient owns the transport and may sign or encrypt it, so NetGet never
/// sees a byte count on the wire. A write reports the number of payload bytes it
/// really put into the file, inside `Executed`.
pub enum SmbApplied {
    /// The action ran; the string describes what it did.
    Executed(String),
    /// The client was disconnected.
    Disconnected,
}

/// SMB client that connects to an SMB/CIFS server
pub struct SmbClient;

impl SmbClient {
    /// Connect to an SMB server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        info!(
            "SMB client {} initializing connection to {}",
            client_id, remote_addr
        );

        // Parse startup parameters for credentials
        let (username, password, domain, workgroup) = if let Some(params) = startup_params {
            let username = params
                .get_optional_string("username")?
                .unwrap_or_else(|| "guest".to_string());
            let password = params
                .get_optional_string("password")?
                .unwrap_or_else(|| "".to_string());
            let domain = params.get_optional_string("domain")?;
            let workgroup = params.get_optional_string("workgroup")?;

            (username, password, domain, workgroup)
        } else {
            ("guest".to_string(), "".to_string(), None, None)
        };

        info!(
            "SMB client {} using credentials - username: {}, domain: {:?}, workgroup: {:?}",
            client_id, username, domain, workgroup
        );

        // Create SMB credentials using builder pattern
        let mut creds = SmbCredentials::default()
            .server(&remote_addr)
            .username(&username)
            .password(&password);

        // Note: pavao API uses workgroup() for both domain and workgroup
        if let Some(w) = workgroup.or(domain) {
            creds = creds.workgroup(&w);
        }

        // Acquire ownership before native initialization: pavao's context is global.
        let lease = NATIVE_SESSION
            .clone()
            .try_acquire_owned()
            .context("the pavao SMB backend supports one active native session per process")?;
        // Create SMB client
        let smb_client: SharedSmb = Arc::new(Mutex::new(
            tokio::task::spawn_blocking(move || {
                let client = PavaoSmbClient::new(creds, SmbOptions::default())
                    .context("Failed to create SMB client")?;
                client.set_timeout(std::time::Duration::from_secs(30))?;
                Ok::<_, anyhow::Error>(NativeSmb {
                    client: Some(client),
                    lease: Some(lease),
                })
            })
            .await
            .context("SMB initialization worker panicked")??,
        ));

        // For SMB, we use a dummy local address since it's a library-based client
        // The actual connection happens per-operation
        let local_addr = "127.0.0.1:0".parse::<SocketAddr>()?;

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] SMB client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        info!("SMB client {} connected to {}", client_id, remote_addr);

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call below: a dashboard-created
        // client defaults to a `*` -> manual rule, so that call can park for minutes
        // waiting for a human, and the operator must be able to reach the share while
        // it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn({
            let smb_client = smb_client.clone();
            let llm_client = llm_client.clone();
            let app_state = app_state.clone();
            let status_tx = status_tx.clone();
            async move {
                Self::command_loop(
                    command_rx, smb_client, client_id, llm_client, app_state, status_tx,
                )
                .await;
            }
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn task to handle LLM interactions
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let remote_addr_clone = remote_addr.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            // Send initial connected event to LLM
            if let Some(instruction) = app_state_clone.get_instruction_for_client(client_id).await {
                let protocol = Arc::new(SmbClientProtocol::new());
                let event = Event::new(
                    &SMB_CLIENT_CONNECTED_EVENT,
                    serde_json::json!({
                        "share_url": format!("smb://{}", remote_addr_clone),
                    }),
                );

                let memory = app_state_clone
                    .get_memory_for_client(client_id)
                    .await
                    .unwrap_or_default();

                match call_llm_for_client(
                    &llm_client,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    protocol.as_ref(),
                    &status_tx_clone,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates,
                    }) => {
                        // Update memory
                        if let Some(mem) = memory_updates {
                            app_state_clone.set_memory_for_client(client_id, mem).await;
                        }

                        // Execute actions
                        for action in actions {
                            if let Err(e) = Self::execute_smb_action(
                                &smb_client,
                                action,
                                client_id,
                                &protocol,
                                &llm_client,
                                &app_state_clone,
                                &status_tx_clone,
                            )
                            .await
                            {
                                error!("SMB client {} action error: {}", client_id, e);

                                // Send error event to LLM
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "action_execution",
                                    }),
                                );

                                let _ = Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    &protocol,
                                    &llm_client,
                                    &app_state_clone,
                                    &status_tx_clone,
                                    &smb_client,
                                )
                                .await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for SMB client {}: {}", client_id, e);
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (the client was removed,
    /// which drops the handle) or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this
    /// client: it owns no socket, and every SMB verb yields a
    /// `ClientActionResult::Custom` that only libsmbclient can carry out. So the
    /// action goes through [`Self::execute_smb_action`] — the exact function the LLM
    /// path uses, including the follow-up events — and the outcome is recorded and
    /// replied the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        smb_client: SharedSmb,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = Arc::new(SmbClientProtocol::new());

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            // `execute_action` is the only step that can fail before the share is
            // touched, so its error is a rejection (unknown verb / bad params) rather
            // than an SMB failure.
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_smb_result(
                    result,
                    &smb_client,
                    client_id,
                    &protocol,
                    &llm_client,
                    &app_state,
                    &status_tx,
                )
                .await
                .map(|applied| match applied {
                    SmbApplied::Executed(detail) => ClientSendOutcome::Executed { detail },
                    SmbApplied::Disconnected => ClientSendOutcome::Disconnected,
                }),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "SMB client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a dead client and a late send fails fast.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute an SMB action and call LLM with result
    async fn execute_smb_action(
        smb_client: &SharedSmb,
        action: serde_json::Value,
        client_id: ClientId,
        protocol: &Arc<SmbClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<SmbApplied> {
        let result = protocol.execute_action(action)?;
        Self::apply_smb_result(
            result, smb_client, client_id, protocol, llm_client, app_state, status_tx,
        )
        .await
    }

    /// Carry one already-decoded action out against the share. Shared by the
    /// connected-event path, the follow-up event path and injected commands, so the
    /// libsmbclient calls exist exactly once.
    async fn apply_smb_result(
        action_result: crate::llm::actions::client_trait::ClientActionResult,
        smb_client: &SharedSmb,
        client_id: ClientId,
        protocol: &Arc<SmbClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<SmbApplied> {
        // Assigned exactly once on every path that does not return early.
        let detail: String;
        let mut failure = None;
        match action_result {
            crate::llm::actions::client_trait::ClientActionResult::Custom { name, data } => {
                match name.as_str() {
                    "smb_list_dir" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;

                        debug!("SMB client {} listing directory: {}", client_id, path);

                        // List directory using pavao. The guard is scoped to the
                        // synchronous call only — never held across the LLM await below.
                        let owned_path = path.to_string();
                        let list_result =
                            blocking_smb(smb_client, move |smb| Ok(smb.list_dir(&owned_path)?))
                                .await;
                        match list_result {
                            Ok(entries) => {
                                let entry_list: Vec<serde_json::Value> = entries
                                    .iter()
                                    .map(|entry| {
                                        let dirent: &SmbDirent = entry;
                                        serde_json::json!({
                                            "name": dirent.name(),
                                            "type": match dirent.get_type() {
                                                SmbDirentType::Workgroup => "workgroup",
                                                SmbDirentType::Server => "server",
                                                SmbDirentType::FileShare => "file_share",
                                                SmbDirentType::PrinterShare => "printer_share",
                                                SmbDirentType::CommsShare => "comms_share",
                                                SmbDirentType::IpcShare => "ipc_share",
                                                SmbDirentType::Dir => "dir",
                                                SmbDirentType::File => "file",
                                                SmbDirentType::Link => "link",
                                            },
                                            "comment": dirent.comment(),
                                        })
                                    })
                                    .collect();

                                info!(
                                    "SMB client {} listed {} entries in {}",
                                    client_id,
                                    entry_list.len(),
                                    path
                                );
                                detail = format!(
                                    "list_directory {:?}: {} entries",
                                    path,
                                    entry_list.len()
                                );

                                let event = Event::new(
                                    &SMB_CLIENT_DIR_LISTED_EVENT,
                                    serde_json::json!({
                                        "path": path,
                                        "entries": entry_list,
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &event, client_id, protocol, llm_client, app_state, status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                            Err(e) => {
                                error!("SMB client {} list_dir error: {}", client_id, e);
                                detail = format!("list_directory {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "list_directory",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    "smb_read_file" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;

                        debug!("SMB client {} reading file: {}", client_id, path);

                        // Open file for reading and immediately read contents
                        // We need to close the file before any await (SmbFile contains raw pointer, not Send)
                        let owned_path = path.to_string();
                        let read_result = blocking_smb(smb_client, move |smb| {
                            let file =
                                smb.open_with(&owned_path, SmbOpenOptions::default().read(true))?;
                            Ok(read_file_bounded(file)?)
                        })
                        .await;

                        match read_result {
                            Ok(content_bytes) => {
                                let size = content_bytes.len();

                                // Try to convert to UTF-8 string, fallback to base64 for binary
                                let content =
                                    if let Ok(text) = String::from_utf8(content_bytes.clone()) {
                                        text
                                    } else {
                                        use base64::{engine::general_purpose, Engine as _};
                                        format!(
                                            "base64:{}",
                                            general_purpose::STANDARD.encode(&content_bytes)
                                        )
                                    };

                                info!("SMB client {} read {} bytes from {}", client_id, size, path);
                                detail = format!("read_file {path:?}: {size} bytes read");

                                let event = Event::new(
                                    &SMB_CLIENT_FILE_READ_EVENT,
                                    serde_json::json!({
                                        "path": path,
                                        "content": content,
                                        "size": size,
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &event, client_id, protocol, llm_client, app_state, status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                            Err(e) => {
                                error!("SMB client {} read_file error: {}", client_id, e);
                                detail = format!("read_file {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "read_file",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    "smb_write_file" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;
                        let content = data
                            .get("content")
                            .and_then(|v| v.as_str())
                            .context("Missing content")?;

                        debug!("SMB client {} writing file: {}", client_id, path);

                        // `smb_file_read` emits binary as `base64:<encoded>`, so write must
                        // understand the same sentinel or the round trip is broken: reading a
                        // binary file and writing it back wrote the literal string
                        // "base64:iVBORw0KG..." to the share. The prefix is the marker the
                        // read side already chose; this is the other half of it.
                        let content_bytes = match content.strip_prefix("base64:") {
                            Some(encoded) => {
                                use base64::{engine::general_purpose, Engine as _};
                                general_purpose::STANDARD.decode(encoded.trim()).context(
                                    "content began with \"base64:\" but the rest is not valid \
                                     base64. Binary content must be base64 exactly as \
                                     smb_file_read reports it; text content must not start \
                                     with \"base64:\".",
                                )?
                            }
                            None => content.as_bytes().to_vec(),
                        };
                        if content_bytes.len() > MAX_FILE_BYTES {
                            anyhow::bail!("SMB write exceeds buffered byte cap");
                        }
                        let owned_path = path.to_string();
                        let write_result = blocking_smb(smb_client, move |smb| {
                            let mut file = smb.open_with(
                                &owned_path,
                                SmbOpenOptions::default()
                                    .write(true)
                                    .create(true)
                                    .truncate(true),
                            )?;
                            file.write_all(&content_bytes)?;
                            Ok(content_bytes.len())
                        })
                        .await;

                        match write_result {
                            Ok(bytes_written) => {
                                info!(
                                    "SMB client {} wrote {} bytes to {}",
                                    client_id, bytes_written, path
                                );
                                detail =
                                    format!("write_file {path:?}: {bytes_written} bytes written");

                                let event = Event::new(
                                    &SMB_CLIENT_FILE_WRITTEN_EVENT,
                                    serde_json::json!({
                                        "path": path,
                                        "bytes_written": bytes_written,
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &event, client_id, protocol, llm_client, app_state, status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                            Err(e) => {
                                error!("SMB client {} write_file error: {}", client_id, e);
                                detail = format!("write_file {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "write_file",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    "smb_create_dir" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;

                        debug!("SMB client {} creating directory: {}", client_id, path);

                        let owned_path = path.to_string();
                        let mkdir_result = blocking_smb(smb_client, move |smb| {
                            Ok(smb.mkdir(&owned_path, pavao::SmbMode::from(0o755))?)
                        })
                        .await;
                        match mkdir_result {
                            Ok(()) => {
                                info!("SMB client {} created directory {}", client_id, path);
                                detail = format!("create_directory {path:?}: created");
                                let _ = status_tx.send(format!(
                                    "[CLIENT] SMB client {} created directory: {}",
                                    client_id, path
                                ));
                            }
                            Err(e) => {
                                error!("SMB client {} mkdir error: {}", client_id, e);
                                detail = format!("create_directory {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "create_directory",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    "smb_delete_file" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;

                        debug!("SMB client {} deleting file: {}", client_id, path);

                        let owned_path = path.to_string();
                        let unlink_result =
                            blocking_smb(smb_client, move |smb| Ok(smb.unlink(&owned_path)?)).await;
                        match unlink_result {
                            Ok(()) => {
                                info!("SMB client {} deleted file {}", client_id, path);
                                detail = format!("delete_file {path:?}: deleted");
                                let _ = status_tx.send(format!(
                                    "[CLIENT] SMB client {} deleted file: {}",
                                    client_id, path
                                ));
                            }
                            Err(e) => {
                                error!("SMB client {} unlink error: {}", client_id, e);
                                detail = format!("delete_file {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "delete_file",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    "smb_delete_dir" => {
                        let path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .context("Missing path")?;

                        debug!("SMB client {} deleting directory: {}", client_id, path);

                        let owned_path = path.to_string();
                        let rmdir_result =
                            blocking_smb(smb_client, move |smb| Ok(smb.rmdir(&owned_path)?)).await;
                        match rmdir_result {
                            Ok(()) => {
                                info!("SMB client {} deleted directory {}", client_id, path);
                                detail = format!("delete_directory {path:?}: deleted");
                                let _ = status_tx.send(format!(
                                    "[CLIENT] SMB client {} deleted directory: {}",
                                    client_id, path
                                ));
                            }
                            Err(e) => {
                                error!("SMB client {} rmdir error: {}", client_id, e);
                                detail = format!("delete_directory {path:?} failed: {e}");
                                failure = Some(e.to_string());
                                let error_event = Event::new(
                                    &SMB_CLIENT_ERROR_EVENT,
                                    serde_json::json!({
                                        "error": e.to_string(),
                                        "operation": "delete_directory",
                                    }),
                                );

                                Self::call_llm_with_event(
                                    &error_event,
                                    client_id,
                                    protocol,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    smb_client,
                                )
                                .await?;
                            }
                        }
                    }
                    _ => {
                        error!("SMB client {} unknown action: {}", client_id, name);
                        detail = format!("custom result '{name}' has no SMB handler");
                    }
                }
            }
            crate::llm::actions::client_trait::ClientActionResult::Disconnect => {
                info!("SMB client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                // Drop the command handle here rather than only in the command loop:
                // the LLM can disconnect too, and a handle left behind would offer
                // [ send ] into a closed client.
                app_state.remove_client_handle(client_id).await;
                let _ = status_tx.send(format!("[CLIENT] SMB client {} disconnected", client_id));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return Ok(SmbApplied::Disconnected);
            }
            crate::llm::actions::client_trait::ClientActionResult::WaitForMore => {
                debug!("SMB client {} waiting for more", client_id);
                detail = "wait_for_more".to_string();
            }
            other => {
                debug!("SMB client {} unhandled action result", client_id);
                detail = format!("unhandled action result {other:?}");
            }
        }

        if let Some(error) = failure {
            anyhow::bail!("SMB operation failed: {error}");
        }
        Ok(SmbApplied::Executed(detail))
    }

    /// Call LLM with an event and execute resulting actions
    async fn call_llm_with_event(
        event: &Event,
        client_id: ClientId,
        protocol: &Arc<SmbClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        smb_client: &SharedSmb,
    ) -> Result<()> {
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                llm_client,
                app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(event),
                protocol.as_ref(),
                status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute actions
                    for action in actions {
                        Box::pin(Self::execute_smb_action(
                            smb_client, action, client_id, protocol, llm_client, app_state,
                            status_tx,
                        ))
                        .await?;
                    }
                }
                Err(e) => {
                    error!("LLM error for SMB client {}: {}", client_id, e);
                }
            }
        }

        Ok(())
    }
}
