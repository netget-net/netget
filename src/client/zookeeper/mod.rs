//! ZooKeeper client implementation
pub mod actions;

pub use actions::ZookeeperClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use zookeeper_async::{Acl, CreateMode, WatchedEvent, ZooKeeper};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::zookeeper::actions::{
    ZOOKEEPER_CLIENT_CHILDREN_RECEIVED_EVENT, ZOOKEEPER_CLIENT_CONNECTED_EVENT,
    ZOOKEEPER_CLIENT_DATA_RECEIVED_EVENT, ZOOKEEPER_CLIENT_OPERATION_COMPLETE_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// How long to wait for the initial session before refusing to start.
///
/// Distinct from [`SESSION_TIMEOUT`], which governs an *established* session. See the note at
/// the call site for why an explicit bound is required here.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Session timeout requested at handshake. ZooKeeper clamps it into `2 * tickTime ..=
/// 20 * tickTime` and tells us what it settled on; NetGet's own server clamps to
/// `4000..=40000` ms, so 10s is inside the negotiable range of both.
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The live ZooKeeper session, shared between the connected-event handler and the
/// injected-command loop.
///
/// `ZooKeeper`'s operations all take `&self` and it is `Send + Sync`, so this needs no
/// `Mutex` - unlike the etcd client, whose `etcd_client::Client` wants `&mut self`.
type SharedZk = Arc<ZooKeeper>;

/// One completed ZooKeeper operation: what to tell the operator, and the event to raise.
struct ZkOutcome {
    detail: String,
    event_type: &'static EventType,
    event_data: serde_json::Value,
}

/// What one executed action did. Shared vocabulary between the connected-event handler
/// and the injected-command loop.
enum Applied {
    /// The action ran; `detail` says what it did.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// ZooKeeper client that connects to a ZooKeeper server
pub struct ZookeeperClient;

impl ZookeeperClient {
    /// Connect to a ZooKeeper server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!(
            "ZooKeeper client {} connecting to {}",
            client_id, remote_addr
        );

        // `remote_addr` is a ZooKeeper *connect string*, not a single address: comma-separated
        // `host:port` pairs with an optional `/chroot` suffix. It is handed to the library
        // as-is rather than parsed as one `SocketAddr` - the old code did that and rejected
        // every legitimate ensemble or chrooted address before even trying to connect.
        // Bounded, because `ZooKeeper::connect` is not.
        //
        // A ZooKeeper client is *designed* to retry its connect string forever — that is
        // correct for a long-lived session against a real ensemble, and wrong for the one call
        // that decides whether this client starts at all. Against a closed port it never
        // returns, so `connect_with_llm_actions` never returns, and whatever asked for the
        // client (the dashboard's create form, `open_client`, an MCP caller) waits with it.
        // `SESSION_TIMEOUT` does not help: that is the *session* timeout negotiated after a
        // connection exists.
        //
        // Caught by `every_registered_client_protocol_refuses_a_closed_port_promptly`, where
        // ZooKeeper was the only protocol of 91 to hang rather than refuse.
        let zk: SharedZk = Arc::new(
            tokio::time::timeout(
                CONNECT_TIMEOUT,
                ZooKeeper::connect(&remote_addr, SESSION_TIMEOUT, |_ev: WatchedEvent| {}),
            )
            .await
            .with_context(|| {
                format!(
                    "Timed out after {CONNECT_TIMEOUT:?} connecting to ZooKeeper at \
                     {remote_addr}. The client library retries a connect string indefinitely, \
                     so this bound is what turns an unreachable ensemble into a refusal."
                )
            })?
            .with_context(|| format!("Failed to connect to ZooKeeper at {remote_addr}"))?,
        );

        info!(
            "ZooKeeper client {} established a session with {}",
            client_id, remote_addr
        );

        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("zookeeper_connected".to_string(), serde_json::json!(true));
                client.set_protocol_field(
                    "connect_string".to_string(),
                    serde_json::json!(remote_addr),
                );
            })
            .await;

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] ZooKeeper client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] / composer).
        // Registered BEFORE the connected-event LLM call below, which a manual `*` routing
        // rule can park for minutes - the operator must be able to reach ZooKeeper while it
        // waits.
        //
        // This task is also what keeps the session alive: `remove_client` drops the command
        // sender, so `recv()` returns `None` the moment the client goes away and the loop
        // closes the session on its way out.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            zk.clone(),
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Raise the connected event. Nothing did this before: the client marked itself
        // Connected and returned, so `zookeeper_connected` was declared and never emitted and
        // the LLM was never consulted at all.
        let protocol = Arc::new(ZookeeperClientProtocol::new());
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &ZOOKEEPER_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                }),
            );
            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(mem) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute them through the same path injected commands use, so the
                    // ZooKeeper call for each verb exists exactly once.
                    for action in result.actions {
                        let executed = match protocol.execute_action(action) {
                            Ok(executed) => executed,
                            Err(e) => {
                                error!("ZooKeeper client {} rejected action: {}", client_id, e);
                                continue;
                            }
                        };
                        match Self::apply_action(
                            executed,
                            client_id,
                            &zk,
                            &app_state,
                            &llm_client,
                            &status_tx,
                        )
                        .await
                        {
                            Ok(Applied::Ran(detail)) => {
                                info!("ZooKeeper client {}: {}", client_id, detail)
                            }
                            Ok(Applied::Disconnect) => {
                                info!("ZooKeeper client {} disconnecting after connect", client_id);
                                let _ = zk.close().await;
                                app_state.remove_client_handle(client_id).await;
                                app_state
                                    .update_client_status(client_id, ClientStatus::Disconnected)
                                    .await;
                                let _ = status_tx.send("__UPDATE_UI__".to_string());
                                break;
                            }
                            Err(e) => {
                                error!("ZooKeeper client {} action failed: {}", client_id, e)
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "ZooKeeper client {} LLM call failed on connect: {}",
                        client_id, e
                    );
                }
            }
        }

        // ZooKeeper does not expose the session's local socket, so report the conventional
        // placeholder the rest of the client layer uses for connectionless/library clients.
        Ok("127.0.0.1:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: there is no
    /// write half NetGet owns - `zookeeper-async` holds the socket and its own I/O task - and
    /// every ZooKeeper verb yields `ClientActionResult::Custom`. So the action goes through
    /// [`Self::apply_action`], the same function the connected-event path uses.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        zk: SharedZk,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = ZookeeperClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(executed) => match Self::apply_action(
                    executed,
                    client_id,
                    &zk,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                {
                    // Never `Sent`: `zookeeper-async` owns the socket and never reports how
                    // many bytes a request serialised to, so a byte count here would be
                    // invented. `Executed` carries what ZooKeeper actually answered instead.
                    Ok(Applied::Ran(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Err(e) => Err(e),
                },
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
                    "ZooKeeper client {} injected action failed: {}",
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
        }

        // Every exit path lands here: end the ZooKeeper session (otherwise the server holds
        // it until the negotiated timeout expires) and stop the dashboard offering [ send ].
        if let Err(e) = zk.close().await {
            debug!(
                "ZooKeeper client {} session close returned: {}",
                client_id, e
            );
        }
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("ZooKeeper client {} command loop ended", client_id);
    }

    /// Run one executed action against the live ZooKeeper session.
    ///
    /// The ZooKeeper round-trip is awaited - so the reported detail describes an operation
    /// that really happened - while the event it raises goes to the LLM from its own
    /// registered task. That split matters: a client whose events are routed to a manual
    /// handler would otherwise park the command loop for the length of a human's think time,
    /// and `[ send ]` would report a timeout for an operation that in fact succeeded.
    async fn apply_action(
        executed: ClientActionResult,
        client_id: ClientId,
        zk: &SharedZk,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        let outcome = match executed {
            ClientActionResult::Custom { name, data } if name == "create_znode" => {
                let path = required_str(&data, "path", "create_znode")?;
                let value = required_str(&data, "data", "create_znode")?;
                Self::perform_create(client_id, zk, path, value).await?
            }
            ClientActionResult::Custom { name, data } if name == "get_data" => {
                let path = required_str(&data, "path", "get_data")?;
                Self::perform_get_data(client_id, zk, path).await?
            }
            ClientActionResult::Custom { name, data } if name == "set_data" => {
                let path = required_str(&data, "path", "set_data")?;
                let value = required_str(&data, "data", "set_data")?;
                Self::perform_set_data(client_id, zk, path, value).await?
            }
            ClientActionResult::Custom { name, data } if name == "delete_znode" => {
                let path = required_str(&data, "path", "delete_znode")?;
                Self::perform_delete(client_id, zk, path).await?
            }
            ClientActionResult::Custom { name, data } if name == "get_children" => {
                let path = required_str(&data, "path", "get_children")?;
                Self::perform_get_children(client_id, zk, path).await?
            }
            ClientActionResult::Disconnect => {
                info!("ZooKeeper client {} disconnecting", client_id);
                return Ok(Applied::Disconnect);
            }
            ClientActionResult::WaitForMore => {
                return Ok(Applied::Ran("wait_for_more".to_string()))
            }
            ClientActionResult::NoAction => return Ok(Applied::Ran("no_action".to_string())),
            // Not swallowed: an action this client cannot carry out says so, rather than
            // looking identical to success.
            ClientActionResult::Custom { name, .. } => {
                return Ok(Applied::Ran(format!(
                    "custom result '{name}' is not handled by the ZooKeeper client"
                )))
            }
            ClientActionResult::SendData(_) => {
                return Ok(Applied::Ran(
                    "send_data has no meaning for a ZooKeeper client (zookeeper-async owns \
                     the socket)"
                        .to_string(),
                ))
            }
            ClientActionResult::Multiple(_) => {
                return Ok(Applied::Ran(
                    "multiple results are not produced by the ZooKeeper client".to_string(),
                ))
            }
        };

        let detail = outcome.detail.clone();
        let state_clone = app_state.clone();
        let llm_clone = llm_client.clone();
        let status_clone = status_tx.clone();
        let notify_handle = tokio::spawn(async move {
            Self::notify_event(
                client_id,
                outcome.event_type,
                outcome.event_data,
                state_clone,
                llm_clone,
                status_clone,
            )
            .await;
        });
        app_state
            .register_client_task(client_id, notify_handle)
            .await;

        Ok(Applied::Ran(detail))
    }

    async fn perform_create(
        client_id: ClientId,
        zk: &SharedZk,
        path: String,
        data: String,
    ) -> Result<ZkOutcome> {
        info!("ZooKeeper client {} creating znode {}", client_id, path);
        let created = zk
            .create(
                &path,
                data.clone().into_bytes(),
                Acl::open_unsafe().clone(),
                CreateMode::Persistent,
            )
            .await
            .with_context(|| format!("create of {path} failed"))?;

        Ok(ZkOutcome {
            detail: format!("create_znode '{path}' -> created '{created}'"),
            event_type: &ZOOKEEPER_CLIENT_OPERATION_COMPLETE_EVENT,
            event_data: serde_json::json!({
                "operation": "create",
                "path": path,
                "created_path": created,
            }),
        })
    }

    async fn perform_get_data(
        client_id: ClientId,
        zk: &SharedZk,
        path: String,
    ) -> Result<ZkOutcome> {
        info!("ZooKeeper client {} reading znode {}", client_id, path);
        // `watch: false` throughout: this client has no watch mechanism, and asking the
        // server to set one it will never read would leak a watch per call.
        let (bytes, stat) = zk
            .get_data(&path, false)
            .await
            .with_context(|| format!("get_data of {path} failed"))?;
        let text = String::from_utf8_lossy(&bytes).to_string();

        Ok(ZkOutcome {
            detail: format!(
                "get_data '{}' -> {} byte(s), version {}",
                path,
                bytes.len(),
                stat.version
            ),
            event_type: &ZOOKEEPER_CLIENT_DATA_RECEIVED_EVENT,
            event_data: serde_json::json!({
                "path": path,
                "data": text,
                "version": stat.version,
            }),
        })
    }

    async fn perform_set_data(
        client_id: ClientId,
        zk: &SharedZk,
        path: String,
        data: String,
    ) -> Result<ZkOutcome> {
        info!("ZooKeeper client {} writing znode {}", client_id, path);
        // `version: None` means -1, "any version" - this client keeps no version state to
        // do a compare-and-swap with, and inventing one would fail every write.
        let stat = zk
            .set_data(&path, data.clone().into_bytes(), None)
            .await
            .with_context(|| format!("set_data of {path} failed"))?;

        Ok(ZkOutcome {
            detail: format!("set_data '{}' -> version {}", path, stat.version),
            event_type: &ZOOKEEPER_CLIENT_OPERATION_COMPLETE_EVENT,
            event_data: serde_json::json!({
                "operation": "set_data",
                "path": path,
                "version": stat.version,
            }),
        })
    }

    async fn perform_delete(client_id: ClientId, zk: &SharedZk, path: String) -> Result<ZkOutcome> {
        info!("ZooKeeper client {} deleting znode {}", client_id, path);
        zk.delete(&path, None)
            .await
            .with_context(|| format!("delete of {path} failed"))?;

        Ok(ZkOutcome {
            detail: format!("delete_znode '{path}' -> deleted"),
            event_type: &ZOOKEEPER_CLIENT_OPERATION_COMPLETE_EVENT,
            event_data: serde_json::json!({
                "operation": "delete",
                "path": path,
            }),
        })
    }

    async fn perform_get_children(
        client_id: ClientId,
        zk: &SharedZk,
        path: String,
    ) -> Result<ZkOutcome> {
        info!(
            "ZooKeeper client {} listing children of {}",
            client_id, path
        );
        let children = zk
            .get_children(&path, false)
            .await
            .with_context(|| format!("get_children of {path} failed"))?;

        Ok(ZkOutcome {
            detail: format!("get_children '{}' -> {}", path, children.join(", ")),
            event_type: &ZOOKEEPER_CLIENT_CHILDREN_RECEIVED_EVENT,
            event_data: serde_json::json!({
                "path": path,
                "children": children,
            }),
        })
    }

    /// Hand one completed operation to the LLM as its protocol event.
    async fn notify_event(
        client_id: ClientId,
        event_type: &'static EventType,
        event_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let event = Event::new(event_type, event_data);
        let protocol = Arc::new(ZookeeperClientProtocol::new());
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                // Follow-up actions are routed back through the client's own command
                // channel rather than executed here, so every action - LLM-produced or
                // injected - is applied by the one loop that owns the session, and this
                // task stays a leaf.
                for action in result.actions {
                    if let Err(e) = app_state
                        .send_to_client(client_id, action, Duration::from_secs(60))
                        .await
                    {
                        debug!(
                            "ZooKeeper client {} could not apply a follow-up action: {}",
                            client_id, e
                        );
                    }
                }
            }
            Err(e) => {
                error!("LLM error for ZooKeeper client {}: {}", client_id, e);
            }
        }
    }
}

/// Pull a required string out of an executed action's data, naming the verb when it is
/// missing. `execute_action` already validates these, so a failure here means the protocol
/// and this module disagree - which is worth an explicit error rather than a silent default.
fn required_str(data: &serde_json::Value, field: &str, verb: &str) -> Result<String> {
    data.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("Missing '{field}' in {verb}"))
}
