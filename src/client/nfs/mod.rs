//! NFS client implementation
pub mod actions;

pub use actions::NfsClientProtocol;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client as ClientTrait, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use serde_json::json;

#[cfg(unix)]
use nfs3_client::{tokio::TokioConnector, Nfs3ConnectionBuilder};
#[cfg(unix)]
use nfs3_types::nfs3::*;

use crate::client::nfs::actions::{NFS_CLIENT_CONNECTED_EVENT, NFS_CLIENT_OPERATION_RESULT_EVENT};

/// The mounted NFS3 connection. Named because it appears in a dozen signatures.
#[cfg(unix)]
type NfsConn = nfs3_client::Nfs3Connection<nfs3_client::tokio::TokioIo<tokio::net::TcpStream>>;

/// NFS client that connects to a remote NFS server
pub struct NfsClient;

impl NfsClient {
    /// Connect to an NFS server with integrated LLM actions
    #[cfg(unix)]
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse remote_addr into server and export path
        // Format: server:port:/export/path or server:/export/path (default port 2049)
        let (server_addr, export_path) = Self::parse_nfs_address(&remote_addr)?;

        Log::new(Some(&status_tx)).info(format!(
            "NFS client {} attempting to connect to {} for export {}",
            client_id, server_addr, export_path
        ));

        // Extract just the server part (remove port if present)
        let server = server_addr.split(':').next().unwrap_or(&server_addr);

        // Where to find the three RPC programs. The defaults are the real-world ones —
        // portmapper on 111, MOUNT and NFS resolved through it, and a privileged local source
        // port, which many servers demand. They are overridable because a server that
        // multiplexes all three programs on one ephemeral port (NetGet's own does, through
        // `nfsserve`) is otherwise unreachable: without an override the client asks 111 for
        // ports no matter what address it was given.
        let params = startup_params.as_ref();
        let port_param = |key: &str| -> Result<Option<u16>> {
            let raw = params
                .map(|p| p.get_optional_u64(key))
                .transpose()?
                .flatten();
            match raw {
                None => Ok(None),
                Some(v) if (1..=65535).contains(&v) => Ok(Some(v as u16)),
                Some(v) => Err(anyhow::anyhow!(
                    "NFS client '{key}' must be between 1 and 65535, got {v}"
                )),
            }
        };
        let portmapper_port = port_param("portmapper_port")?;
        let mount_port = port_param("mount_port")?;
        let nfs_port = port_param("nfs_port")?;
        let privileged_source_port = params
            .map(|p| p.get_optional_bool("privileged_source_port"))
            .transpose()?
            .flatten()
            .unwrap_or(true);

        // Mount the NFS export
        let mut builder = Nfs3ConnectionBuilder::new(TokioConnector, server, &export_path)
            .connect_from_privileged_port(privileged_source_port);
        if let Some(port) = portmapper_port {
            builder = builder.portmapper_port(port);
        }
        if let Some(port) = mount_port {
            builder = builder.mount_port(port);
        }
        if let Some(port) = nfs_port {
            builder = builder.nfs3_port(port);
        }
        let connection = builder
            .mount()
            .await
            .context("Failed to mount NFS export")?;

        Log::new(Some(&status_tx)).info(format!(
            "NFS client {} successfully mounted export {}",
            client_id, export_path
        ));

        // Get root file handle
        let root_fh = connection.root_nfs_fh3();
        let root_fh_hex = hex::encode(&root_fh.data.0);

        // Update client status to connected
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Create file handle cache
        let fh_cache = Arc::new(Mutex::new(HashMap::new()));
        fh_cache
            .lock()
            .await
            .insert("/".to_string(), root_fh.clone());

        // Spawn NFS operation handler
        let connection_arc = Arc::new(Mutex::new(connection));

        // The dashboard's `[ send ]` channel, registered BEFORE the connected-event LLM call
        // that the handler task below makes. A dashboard-created client defaults to a
        // `*` -> manual rule, so that call can park for minutes waiting for a human;
        // registering after it would leave the rail reading "no command channel" for the
        // whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_task = tokio::spawn(Self::command_loop(
            connection_arc.clone(),
            fh_cache.clone(),
            command_rx,
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        let app_state_clone = app_state.clone();
        let llm_client_clone = llm_client.clone();
        let status_tx_clone = status_tx.clone();
        let fh_cache_clone = fh_cache.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            if let Err(e) = Self::handle_nfs_operations(
                connection_arc,
                fh_cache_clone,
                client_id,
                export_path,
                root_fh_hex,
                llm_client_clone,
                app_state_clone,
                status_tx_clone,
            )
            .await
            {
                error!("NFS client {} handler error: {}", client_id, e);
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // The address the dashboard shows for this client.
        //
        // This used to be `format!("{}:2049", server).parse()?`, which is wrong twice. The
        // `?` runs *after* the export is mounted and after both tasks are spawned and
        // registered, so for any non-literal-IP `server` — `fileserver.local:/home`, which
        // the docs give as an example — `connect()` returned `Err` on a connection that had
        // in fact succeeded and was still running: the client was reported as failed while
        // its mount and its two tasks stayed alive. And when it did parse, the port was
        // hardcoded 2049 regardless of `nfs_port`, so the rail named a port the client had
        // never spoken to.
        //
        // `nfs3_client` only dials a literal IP (`Nfs3ConnectionBuilder` parses `server` as
        // an `IpAddr`), so if the mount above succeeded then `server` parses here too. Fall
        // back to an unspecified address rather than failing a live connection.
        let shown_port = nfs_port.unwrap_or(2049);
        let shown_addr = server
            .parse::<std::net::IpAddr>()
            .map(|ip| SocketAddr::new(ip, shown_port))
            .unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            });
        Ok(shown_addr)
    }

    /// Handle NFS operations with LLM integration
    #[cfg(unix)]
    async fn handle_nfs_operations(
        connection: Arc<Mutex<NfsConn>>,
        fh_cache: Arc<Mutex<HashMap<String, nfs_fh3>>>,
        client_id: ClientId,
        export_path: String,
        root_fh_hex: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // Get instruction
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();

        let protocol = Arc::new(NfsClientProtocol::new());

        // Send connected event to LLM
        let connected_event = Event::new(
            &NFS_CLIENT_CONNECTED_EVENT,
            json!({
                "export_path": export_path,
                "root_fh": root_fh_hex
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        let result = call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&connected_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await?;

        // Update memory
        if let Some(new_memory) = result.memory_updates {
            app_state.set_memory_for_client(client_id, new_memory).await;
        }

        // Execute actions from LLM
        for action in result.actions {
            if let Err(e) = Self::execute_action(
                &connection,
                &fh_cache,
                action,
                client_id,
                &llm_client,
                &app_state,
                &status_tx,
                protocol.as_ref(),
            )
            .await
            {
                Log::new(Some(&status_tx)).error(format!("NFS operation failed: {}", e));
            }
        }

        // Keep client alive - monitor for disconnection
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            if app_state.get_client(client_id).await.is_none() {
                info!("NFS client {} stopped", client_id);
                break;
            }
        }

        Ok(())
    }

    /// Execute a single NFS action
    #[cfg(unix)]
    async fn execute_action(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        action: serde_json::Value,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &dyn ClientTrait,
    ) -> Result<()> {
        let action_result = protocol.execute_action(action.clone())?;

        match action_result {
            ClientActionResult::Disconnect => {
                info!("NFS client {} disconnecting", client_id);
                // Stop offering [ send ] on a session that is going away.
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                return Ok(());
            }
            ClientActionResult::WaitForMore => {
                trace!("NFS client {} waiting", client_id);
                return Ok(());
            }
            ClientActionResult::Custom { name, data } => {
                // A `?` here used to short-circuit past `report_operation`, so every NFS
                // error status — `Read failed: NFS3ERR_ACCES`, a lookup on a path that does
                // not exist — died as a log line and raised no event. The model that asked
                // for the operation got silence and could neither retry nor adapt: the
                // action chain simply stopped. That is the "asks the model what to do and
                // throws the answer away" shape from the root CLAUDE.md, one step further
                // along. The failure is now an event like any other result.
                let result_data = match Self::perform_op(connection, fh_cache, &name, data).await {
                    Ok(result_data) => {
                        info!("NFS client {} completed operation: {}", client_id, name);
                        result_data
                    }
                    Err(e) => {
                        warn!("NFS client {} operation {} failed: {}", client_id, name, e);
                        serde_json::json!({
                            "success": false,
                            "error": e.to_string(),
                        })
                    }
                };

                Box::pin(Self::report_operation(
                    connection,
                    fh_cache,
                    &name,
                    result_data,
                    client_id,
                    llm_client,
                    app_state,
                    status_tx,
                ))
                .await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Raise `nfs_operation_result` for a completed operation and execute whatever the
    /// handler answers.
    ///
    /// Split out of [`Self::execute_action`] so the command loop can run an injected
    /// operation, reply with its outcome immediately, and only then let the model react - a
    /// handler parked for a human must not hold up the next injected command.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn report_operation(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        name: &str,
        result_data: serde_json::Value,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let protocol = NfsClientProtocol::new();

        let result_event = Event::new(
            &NFS_CLIENT_OPERATION_RESULT_EVENT,
            json!({
                "operation": name,
                "result": result_data
            }),
        );

        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        let llm_result = call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&result_event),
            &protocol,
            status_tx,
        )
        .await?;

        if let Some(new_memory) = llm_result.memory_updates {
            app_state.set_memory_for_client(client_id, new_memory).await;
        }

        for next_action in llm_result.actions {
            Box::pin(Self::execute_action(
                connection,
                fh_cache,
                next_action,
                client_id,
                llm_client,
                app_state,
                status_tx,
                &protocol,
            ))
            .await?;
        }
        Ok(())
    }

    /// Run one NFS operation against the mounted export.
    ///
    /// The single place the operation table lives, so an injected dashboard command and an
    /// LLM-produced action reach exactly the same code.
    #[cfg(unix)]
    async fn perform_op(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        name: &str,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        match name {
            "nfs_lookup" => Self::op_lookup(connection, fh_cache, data).await,
            "nfs_read_file" => Self::op_read_file(connection, fh_cache, data).await,
            "nfs_write_file" => Self::op_write_file(connection, fh_cache, data).await,
            "nfs_list_dir" => Self::op_list_dir(connection, fh_cache, data).await,
            "nfs_get_attr" => Self::op_get_attr(connection, fh_cache, data).await,
            "nfs_create_file" => Self::op_create_file(connection, fh_cache, data).await,
            "nfs_mkdir" => Self::op_mkdir(connection, fh_cache, data).await,
            "nfs_remove" => Self::op_remove(connection, fh_cache, data).await,
            "nfs_rmdir" => Self::op_rmdir(connection, fh_cache, data).await,
            other => Err(anyhow::anyhow!("Unknown NFS operation: {}", other)),
        }
    }

    /// Drain injected commands (the dashboard's `[ send ]`) until the channel closes - which
    /// happens when the client is removed - or an injected `disconnect` ends the session.
    ///
    /// A task of its own rather than a `select!` arm: the ONC-RPC exchanges inside
    /// `nfs3_client` read with `read_exact`, which is not cancellation-safe, and the
    /// connection mutex is what serialises this loop against the handler task.
    ///
    /// Outcome semantics: `nfs3_client` frames every RPC, so this loop can honestly claim no
    /// byte count. An operation that ran reports `Executed` naming it and summarising the
    /// reply; one the server refused is an `Err`, never a quieter `Sent`.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        connection: Arc<Mutex<NfsConn>>,
        fh_cache: Arc<Mutex<HashMap<String, nfs_fh3>>>,
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = Arc::new(NfsClientProtocol::new());

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let mut follow_up: Option<(String, serde_json::Value)> = None;
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Disconnect) => {
                    disconnect = true;
                    Ok(ClientSendOutcome::Disconnected)
                }
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more: nothing was asked of the export".to_string(),
                }),
                Ok(ClientActionResult::NoAction) => Ok(ClientSendOutcome::Executed {
                    detail: "no_action".to_string(),
                }),
                Ok(ClientActionResult::Custom { name, data }) => {
                    match Self::perform_op(&connection, &fh_cache, &name, data).await {
                        Ok(result) => {
                            let detail = format!("{name} completed: {result}");
                            follow_up = Some((name, result));
                            Ok(ClientSendOutcome::Executed { detail })
                        }
                        Err(e) => Err(e.context(format!("injected NFS action '{name}'"))),
                    }
                }
                Ok(other) => Ok(ClientSendOutcome::Executed {
                    detail: format!("unsupported action result {other:?}"),
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

            if let Err(e) = &outcome {
                error!("NFS client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }

            // The operation-result event goes to the model in its own task: a handler parked
            // for a human must not block the next injected command.
            if let Some((name, result)) = follow_up {
                let connection = connection.clone();
                let fh_cache = fh_cache.clone();
                let llm_client = llm_client.clone();
                let state = app_state.clone();
                let tx = status_tx.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = Self::report_operation(
                        &connection,
                        &fh_cache,
                        &name,
                        result,
                        client_id,
                        &llm_client,
                        &state,
                        &tx,
                    )
                    .await
                    {
                        error!("NFS client {} follow-up failed: {}", client_id, e);
                    }
                });
                app_state.register_client_task(client_id, handle).await;
            }
        }

        // Every exit lands here: drop the handle so the rail stops offering [ send ] on a
        // session nothing is draining any more.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Resolve path to file handle
    #[cfg(unix)]
    async fn resolve_path(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        path: &str,
    ) -> Result<nfs_fh3> {
        // Check cache
        {
            let cache = fh_cache.lock().await;
            if let Some(fh) = cache.get(path) {
                return Ok(fh.clone());
            }
        }

        // Root directory
        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if components.is_empty() {
            let conn = connection.lock().await;
            return Ok(conn.root_nfs_fh3());
        }

        // Walk path
        let mut current_fh = {
            let conn = connection.lock().await;
            conn.root_nfs_fh3()
        };
        let mut current_path = String::from("/");

        for component in components {
            let lookup_args = LOOKUP3args {
                what: diropargs3 {
                    dir: current_fh.clone(),
                    name: component.as_bytes().into(),
                },
            };

            let lookup_res = connection.lock().await.lookup(&lookup_args).await?;

            match lookup_res {
                LOOKUP3res::Ok(ok_res) => {
                    current_fh = ok_res.object;
                    current_path = if current_path == "/" {
                        format!("/{}", component)
                    } else {
                        format!("{}/{}", current_path, component)
                    };
                    fh_cache
                        .lock()
                        .await
                        .insert(current_path.clone(), current_fh.clone());
                }
                LOOKUP3res::Err((stat, _)) => {
                    return Err(anyhow::anyhow!(
                        "Lookup failed for {}: {:?}",
                        component,
                        stat
                    ));
                }
            }
        }

        Ok(current_fh)
    }

    /// NFS lookup operation
    #[cfg(unix)]
    async fn op_lookup(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let fh = Self::resolve_path(connection, fh_cache, path).await?;

        Ok(json!({
            "path": path,
            "file_handle": hex::encode(&fh.data.0),
            "success": true
        }))
    }

    /// NFS read file operation
    #[cfg(unix)]
    async fn op_read_file(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let offset = data["offset"].as_u64().unwrap_or(0);
        let count = crate::client::wire_values::number::<u32>(&data, "count", 4096)?;

        let fh = Self::resolve_path(connection, fh_cache, path).await?;

        let read_args = READ3args {
            file: fh,
            offset,
            count,
        };

        let read_res = connection.lock().await.read(&read_args).await?;

        match read_res {
            READ3res::Ok(ok_res) => {
                let data_str = String::from_utf8_lossy(&ok_res.data.0).to_string();
                Ok(json!({
                    "path": path,
                    "data": data_str,
                    "bytes_read": ok_res.count,
                    "eof": ok_res.eof,
                    "success": true
                }))
            }
            READ3res::Err((stat, _)) => Err(anyhow::anyhow!("Read failed: {:?}", stat)),
        }
    }

    /// NFS write file operation
    #[cfg(unix)]
    async fn op_write_file(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let write_data = data["data"].as_str().context("Missing 'data' parameter")?;
        let offset = data["offset"].as_u64().unwrap_or(0);

        let fh = Self::resolve_path(connection, fh_cache, path).await?;

        let write_args = WRITE3args {
            file: fh,
            offset,
            count: u32::try_from(write_data.len()).context("NFS write exceeds u32 length")?,
            stable: stable_how::FILE_SYNC,
            data: write_data.as_bytes().into(),
        };

        let write_res = connection.lock().await.write(&write_args).await?;

        match write_res {
            WRITE3res::Ok(ok_res) => Ok(json!({
                "path": path,
                "bytes_written": ok_res.count,
                "success": true
            })),
            WRITE3res::Err((stat, _)) => Err(anyhow::anyhow!("Write failed: {:?}", stat)),
        }
    }

    /// NFS list directory operation
    #[cfg(unix)]
    async fn op_list_dir(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().unwrap_or("/");
        let fh = Self::resolve_path(connection, fh_cache, path).await?;

        let readdir_args = READDIR3args {
            dir: fh,
            cookie: 0,
            cookieverf: cookieverf3([0; 8]),
            count: 4096,
        };

        let readdir_res = connection.lock().await.readdir(&readdir_args).await?;

        match readdir_res {
            READDIR3res::Ok(ok_res) => {
                let mut entries = Vec::new();

                // List<T> is a wrapper around Vec<T>, access via .0
                for entry in &ok_res.reply.entries.0 {
                    entries.push(json!({
                        "name": String::from_utf8_lossy(entry.name.as_ref()),
                        "fileid": entry.fileid
                    }));
                }

                Ok(json!({
                    "path": path,
                    "entries": entries,
                    "success": true
                }))
            }
            READDIR3res::Err((stat, _)) => Err(anyhow::anyhow!("Readdir failed: {:?}", stat)),
        }
    }

    /// NFS get attributes operation
    #[cfg(unix)]
    async fn op_get_attr(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let fh = Self::resolve_path(connection, fh_cache, path).await?;

        let getattr_args = GETATTR3args { object: fh };

        let getattr_res = connection.lock().await.getattr(&getattr_args).await?;

        match getattr_res {
            GETATTR3res::Ok(ok_res) => Ok(json!({
                "path": path,
                "type": format!("{:?}", ok_res.obj_attributes.type_),
                "size": ok_res.obj_attributes.size,
                "mode": ok_res.obj_attributes.mode,
                "success": true
            })),
            GETATTR3res::Err(stat) => Err(anyhow::anyhow!("Getattr failed: {:?}", stat)),
        }
    }

    /// NFS create file operation
    #[cfg(unix)]
    async fn op_create_file(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let mode = crate::client::wire_values::number::<u32>(&data, "mode", 0o644)?;

        let (dir_path, filename) = path.rsplit_once('/').unwrap_or(("/", path));
        let dir_fh = Self::resolve_path(connection, fh_cache, dir_path).await?;

        let create_args = CREATE3args {
            where_: diropargs3 {
                dir: dir_fh,
                name: filename.as_bytes().into(),
            },
            how: createhow3::UNCHECKED(sattr3 {
                mode: Nfs3Option::Some(mode),
                uid: Nfs3Option::None,
                gid: Nfs3Option::None,
                size: Nfs3Option::None,
                atime: set_atime::DONT_CHANGE,
                mtime: set_mtime::DONT_CHANGE,
            }),
        };

        let create_res = connection.lock().await.create(&create_args).await?;

        match create_res {
            CREATE3res::Ok(ok_res) => {
                if let Nfs3Option::Some(obj) = ok_res.obj {
                    fh_cache.lock().await.insert(path.to_string(), obj);
                }
                Ok(json!({
                    "path": path,
                    "created": true,
                    "success": true
                }))
            }
            CREATE3res::Err((stat, _)) => Err(anyhow::anyhow!("Create failed: {:?}", stat)),
        }
    }

    /// NFS mkdir operation
    #[cfg(unix)]
    async fn op_mkdir(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;
        let mode = crate::client::wire_values::number::<u32>(&data, "mode", 0o755)?;

        let (dir_path, dirname) = path.rsplit_once('/').unwrap_or(("/", path));
        let dir_fh = Self::resolve_path(connection, fh_cache, dir_path).await?;

        let mkdir_args = MKDIR3args {
            where_: diropargs3 {
                dir: dir_fh,
                name: dirname.as_bytes().into(),
            },
            attributes: sattr3 {
                mode: Nfs3Option::Some(mode),
                uid: Nfs3Option::None,
                gid: Nfs3Option::None,
                size: Nfs3Option::None,
                atime: set_atime::DONT_CHANGE,
                mtime: set_mtime::DONT_CHANGE,
            },
        };

        let mkdir_res = connection.lock().await.mkdir(&mkdir_args).await?;

        match mkdir_res {
            MKDIR3res::Ok(ok_res) => {
                if let Nfs3Option::Some(obj) = ok_res.obj {
                    fh_cache.lock().await.insert(path.to_string(), obj);
                }
                Ok(json!({
                    "path": path,
                    "created": true,
                    "success": true
                }))
            }
            MKDIR3res::Err((stat, _)) => Err(anyhow::anyhow!("Mkdir failed: {:?}", stat)),
        }
    }

    /// NFS remove file operation
    #[cfg(unix)]
    async fn op_remove(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;

        let (dir_path, filename) = path.rsplit_once('/').unwrap_or(("/", path));
        let dir_fh = Self::resolve_path(connection, fh_cache, dir_path).await?;

        let remove_args = REMOVE3args {
            object: diropargs3 {
                dir: dir_fh,
                name: filename.as_bytes().into(),
            },
        };

        let remove_res = connection.lock().await.remove(&remove_args).await?;

        match remove_res {
            REMOVE3res::Ok(_) => {
                fh_cache.lock().await.remove(path);
                Ok(json!({
                    "path": path,
                    "removed": true,
                    "success": true
                }))
            }
            REMOVE3res::Err((stat, _)) => Err(anyhow::anyhow!("Remove failed: {:?}", stat)),
        }
    }

    /// NFS rmdir operation
    #[cfg(unix)]
    async fn op_rmdir(
        connection: &Arc<Mutex<NfsConn>>,
        fh_cache: &Arc<Mutex<HashMap<String, nfs_fh3>>>,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = data["path"].as_str().context("Missing 'path' parameter")?;

        let (dir_path, dirname) = path.rsplit_once('/').unwrap_or(("/", path));
        let dir_fh = Self::resolve_path(connection, fh_cache, dir_path).await?;

        let rmdir_args = RMDIR3args {
            object: diropargs3 {
                dir: dir_fh,
                name: dirname.as_bytes().into(),
            },
        };

        let rmdir_res = connection.lock().await.rmdir(&rmdir_args).await?;

        match rmdir_res {
            RMDIR3res::Ok(_) => {
                fh_cache.lock().await.remove(path);
                Ok(json!({
                    "path": path,
                    "removed": true,
                    "success": true
                }))
            }
            RMDIR3res::Err((stat, _)) => Err(anyhow::anyhow!("Rmdir failed: {:?}", stat)),
        }
    }

    /// Parse NFS address into server address and export path
    /// Format: server:port:/export/path or server:/export/path (default port 2049)
    fn parse_nfs_address(addr: &str) -> Result<(String, String)> {
        // Split by last ':' to separate path from server:port
        if let Some(pos) = addr.rfind(':') {
            let (server_part, path_part) = addr.split_at(pos);
            let path = path_part.trim_start_matches(':');

            // Check if path starts with '/' - if so, it's the export path
            if path.starts_with('/') {
                let server = if !server_part.contains(':') {
                    format!("{}:2049", server_part)
                } else {
                    server_part.to_string()
                };
                return Ok((server, path.to_string()));
            }
        }

        // Default format: assume everything before last ':' is server, rest is path
        Err(anyhow::anyhow!(
            "Invalid NFS address format. Expected: server:port:/export/path or server:/export/path"
        ))
    }

    /// Connect to NFS server without the nfs feature (fallback)
    #[cfg(not(unix))]
    pub async fn connect_with_llm_actions(
        _remote_addr: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _client_id: ClientId,
        _startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        Log::new(Some(&status_tx)).error("NFS feature not enabled at compile time".to_string());
        Err(anyhow::anyhow!("NFS feature not enabled"))
    }
}
