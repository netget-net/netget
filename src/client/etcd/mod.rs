//! etcd client implementation
pub mod actions;

pub use actions::EtcdClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::client::etcd::actions::{
    ETCD_CLIENT_CONNECTED_EVENT, ETCD_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// The live etcd session, shared between the connected-event handler and the
/// injected-command loop.
///
/// Holding the connected `etcd_client::Client` rather than dropping it is what makes
/// injected actions possible at all: the alternative would be a command loop that
/// re-dials etcd for every action, which is a second connection path with its own
/// failure modes and no relationship to the session the dashboard says is "connected".
type SharedEtcd = Arc<Mutex<etcd_client::Client>>;

/// One completed etcd operation. `event_data` is the `etcd_response_received` payload;
/// `detail` is the human-readable line the dashboard shows for an injected action.
struct EtcdOutcome {
    event_data: serde_json::Value,
    detail: String,
}

/// What one executed action did. Shared vocabulary between the connected-event handler
/// and the injected-command loop.
enum Applied {
    /// The action ran; `detail` says what it did.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// etcd client that connects to remote etcd servers
pub struct EtcdClient;

impl EtcdClient {
    /// Connect to an etcd server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("etcd client {} connecting to {}", client_id, remote_addr);

        // Parse endpoint (etcd-client expects a Vec of endpoints)
        let endpoints = vec![remote_addr.clone()];

        // Connect to etcd using etcd-client. The handle is kept for the life of the
        // client so every later operation runs on this session.
        let etcd: SharedEtcd = Arc::new(Mutex::new(
            etcd_client::Client::connect(&endpoints, None)
                .await
                .context("Failed to connect to etcd server")?,
        ));

        info!(
            "etcd client {} connected successfully to {}",
            client_id, remote_addr
        );

        // Store client state
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("etcd_connected".to_string(), serde_json::json!(true));
                client.set_protocol_field("endpoints".to_string(), serde_json::json!(endpoints));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] etcd client {} connected to {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] / composer).
        // Registered BEFORE the connected-event LLM call below, which a manual `*` routing
        // rule can park for minutes - the operator must be able to reach etcd while it
        // waits.
        //
        // This task also replaces the old "poll get_client() every 5s" idle task:
        // `remove_client` drops the command sender, so `recv()` returns `None` the moment
        // the client goes away.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            etcd.clone(),
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Send connected event to LLM
        let connected_event = Event::new(
            &ETCD_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_addr,
            }),
        );

        // Call LLM with connected event
        let protocol = Arc::new(EtcdClientProtocol::new());
        let instruction = app_state
            .with_client_mut(client_id, |client| client.instruction.clone())
            .await
            .unwrap_or_default();
        let memory = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("memory")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .unwrap_or_default();

        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&connected_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state
                        .with_client_mut(client_id, |client| {
                            client.set_protocol_field("memory".to_string(), serde_json::json!(mem));
                        })
                        .await;
                }
                debug!(
                    "etcd client {} LLM generated {} actions on connect",
                    client_id,
                    result.actions.len()
                );

                // Execute them. Until this existed the connect handler counted the
                // actions and threw them away, so an instruction like "PUT /a = b on
                // connect" silently did nothing.
                for action in result.actions {
                    let executed = match protocol.execute_action(action) {
                        Ok(executed) => executed,
                        Err(e) => {
                            error!("etcd client {} rejected action: {}", client_id, e);
                            continue;
                        }
                    };
                    match Self::apply_action(
                        executed,
                        client_id,
                        &etcd,
                        &app_state,
                        &llm_client,
                        &status_tx,
                        0,
                    )
                    .await
                    {
                        Ok(Applied::Ran(detail)) => info!("etcd client {}: {}", client_id, detail),
                        Ok(Applied::Disconnect) => break,
                        Err(e) => error!("etcd client {} action failed: {}", client_id, e),
                    }
                }
            }
            Err(e) => {
                error!(
                    "etcd client {} LLM call failed on connect: {}",
                    client_id, e
                );
            }
        }

        // Return a dummy local address (etcd client is connection-based but doesn't expose local addr)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: there is
    /// no write half NetGet owns - `etcd-client` holds the HTTP/2 connection - and every
    /// etcd verb yields `ClientActionResult::Custom`. So the action goes through
    /// [`Self::apply_action`], the same function the connected-event path uses.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        etcd: SharedEtcd,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = EtcdClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(executed) => match Self::apply_action(
                    executed,
                    client_id,
                    &etcd,
                    &app_state,
                    &llm_client,
                    &status_tx,
                    0,
                )
                .await
                {
                    // Never `Sent`: `etcd-client` owns the gRPC connection and never
                    // reports how many bytes a request serialised to, so a byte count
                    // here would be invented. `Executed` carries what etcd actually
                    // did instead - revision, key count, keys deleted.
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
                    "etcd client {} injected action failed: {}",
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

        // Nothing can be injected any more: stop the dashboard offering [ send ].
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("etcd client {} command loop ended", client_id);
    }

    /// Run one executed action against the live etcd session.
    ///
    /// The etcd round-trip is awaited - so the reported detail describes an operation
    /// that really happened - while the `etcd_response_received` LLM call it triggers
    /// runs in its own registered task. That split matters: a client whose events are
    /// routed to a manual handler would otherwise park the command loop for the length
    /// of a human's think time.
    /// How many operations deep this client keeps following the model's answers. Each
    /// operation reports its result, and that report can ask for another operation;
    /// without a bound, a model that answers `etcd_get` with `etcd_get` never stops.
    const MAX_FOLLOWUP_DEPTH: u8 = 4;

    /// Boxed rather than a plain `async fn` because the recursion is real: an operation
    /// reports its result, the model answers with another operation, and that comes back
    /// here. A self-awaiting `async fn` has an infinitely-sized future, and the boxed type
    /// has to name `+ Send` explicitly or `tokio::spawn` cannot take it.
    #[allow(clippy::too_many_arguments)]
    fn apply_action<'a>(
        executed: ClientActionResult,
        client_id: ClientId,
        etcd: &'a SharedEtcd,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Applied>> + Send + 'a>> {
        Box::pin(async move {
            let outcome = match executed {
            ClientActionResult::Custom { name, data } if name == "etcd_get" => {
                let key = data
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' in etcd_get")?
                    .to_string();
                Self::perform_get(client_id, etcd, key).await?
            }
            ClientActionResult::Custom { name, data } if name == "etcd_put" => {
                let key = data
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' in etcd_put")?
                    .to_string();
                let value = data
                    .get("value")
                    .and_then(|v| v.as_str())
                    .context("Missing 'value' in etcd_put")?
                    .to_string();
                Self::perform_put(client_id, etcd, key, value).await?
            }
            ClientActionResult::Custom { name, data } if name == "etcd_delete" => {
                let key = data
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' in etcd_delete")?
                    .to_string();
                Self::perform_delete(client_id, etcd, key).await?
            }
            ClientActionResult::Disconnect => {
                info!("etcd client {} disconnecting", client_id);
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
                    "custom result '{name}' is not handled by the etcd client"
                )))
            }
            ClientActionResult::SendData(_) => {
                return Ok(Applied::Ran(
                    "send_data has no meaning for an etcd client (etcd-client owns the gRPC connection)"
                        .to_string(),
                ))
            }
            ClientActionResult::Multiple(_) => {
                return Ok(Applied::Ran(
                    "multiple results are not produced by the etcd client".to_string(),
                ))
            }
        };

            let detail = outcome.detail.clone();
            let state_clone = app_state.clone();
            let llm_clone = llm_client.clone();
            let status_clone = status_tx.clone();
            let etcd_clone = etcd.clone();
            let notify_handle = tokio::spawn(async move {
                Self::notify_response(
                    client_id,
                    outcome.event_data,
                    etcd_clone,
                    state_clone,
                    llm_clone,
                    status_clone,
                    depth,
                )
                .await;
            });
            app_state
                .register_client_task(client_id, notify_handle)
                .await;

            Ok(Applied::Ran(detail))
        })
    }

    /// Execute a get operation on the live session.
    async fn perform_get(
        client_id: ClientId,
        etcd: &SharedEtcd,
        key: String,
    ) -> Result<EtcdOutcome> {
        info!("etcd client {} getting key: {}", client_id, key);

        let resp = {
            // A clone of the client, not the guard: `etcd_client::Client` is a cheap handle
            // over one tonic channel, and holding the lock across the RPC would serialise every
            // operation behind the slowest one.
            let mut client = etcd.lock().await.clone();
            client
                .get(key.clone(), None)
                .await
                .context("Failed to get key from etcd")?
        };

        // Build response data
        let kvs: Vec<serde_json::Value> = resp
            .kvs()
            .iter()
            .map(|kv| {
                serde_json::json!({
                    "key": String::from_utf8_lossy(kv.key()).to_string(),
                    "value": String::from_utf8_lossy(kv.value()).to_string(),
                    "create_revision": kv.create_revision(),
                    "mod_revision": kv.mod_revision(),
                    "version": kv.version(),
                    "lease": kv.lease(),
                })
            })
            .collect();

        debug!(
            "etcd client {} received {} key-value pairs",
            client_id,
            kvs.len()
        );

        Ok(EtcdOutcome {
            detail: format!("etcd_get '{}' -> {} key-value pair(s)", key, kvs.len()),
            event_data: serde_json::json!({
                "operation": "get",
                "key": key,
                "kvs": kvs,
                "count": resp.count(),
                "more": resp.more(),
            }),
        })
    }

    /// Execute a put operation on the live session.
    async fn perform_put(
        client_id: ClientId,
        etcd: &SharedEtcd,
        key: String,
        value: String,
    ) -> Result<EtcdOutcome> {
        info!("etcd client {} putting key: {} = {}", client_id, key, value);

        let resp = {
            // A clone of the client, not the guard: `etcd_client::Client` is a cheap handle
            // over one tonic channel, and holding the lock across the RPC would serialise every
            // operation behind the slowest one.
            let mut client = etcd.lock().await.clone();
            client
                .put(key.clone(), value.clone(), None)
                .await
                .context("Failed to put key to etcd")?
        };

        let revision = resp.header().map(|h| h.revision()).unwrap_or(0);
        debug!(
            "etcd client {} put completed, header revision: {}",
            client_id, revision
        );

        Ok(EtcdOutcome {
            detail: format!("etcd_put '{}' -> revision {}", key, revision),
            event_data: serde_json::json!({
                "operation": "put",
                "key": key,
                "value": value,
                "revision": revision,
            }),
        })
    }

    /// Execute a delete operation on the live session.
    async fn perform_delete(
        client_id: ClientId,
        etcd: &SharedEtcd,
        key: String,
    ) -> Result<EtcdOutcome> {
        info!("etcd client {} deleting key: {}", client_id, key);

        let resp = {
            // A clone of the client, not the guard: `etcd_client::Client` is a cheap handle
            // over one tonic channel, and holding the lock across the RPC would serialise every
            // operation behind the slowest one.
            let mut client = etcd.lock().await.clone();
            client
                .delete(key.clone(), None)
                .await
                .context("Failed to delete key from etcd")?
        };

        debug!(
            "etcd client {} delete completed, deleted {} keys",
            client_id,
            resp.deleted()
        );

        Ok(EtcdOutcome {
            detail: format!("etcd_delete '{}' -> {} key(s) deleted", key, resp.deleted()),
            event_data: serde_json::json!({
                "operation": "delete",
                "key": key,
                "deleted": resp.deleted(),
            }),
        })
    }

    /// Raise `etcd_response_received` for a completed operation.
    #[allow(clippy::too_many_arguments)]
    async fn notify_response(
        client_id: ClientId,
        event_data: serde_json::Value,
        etcd: SharedEtcd,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        depth: u8,
    ) {
        let response_event = Event::new(&ETCD_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

        let protocol = Arc::new(EtcdClientProtocol::new());
        let instruction = app_state
            .with_client_mut(client_id, |client| client.instruction.clone())
            .await
            .unwrap_or_default();
        let memory = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("memory")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .unwrap_or_default();

        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&response_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state
                        .with_client_mut(client_id, |client| {
                            client.set_protocol_field("memory".to_string(), serde_json::json!(mem));
                        })
                        .await;
                }
                debug!(
                    "etcd client {} LLM generated {} actions after operation",
                    client_id,
                    result.actions.len()
                );

                // Run them. They used to be counted and thrown away, so the chain was
                // exactly one operation deep: the model was asked what to do after a put,
                // answered "now get it", and nothing happened. Boxed because the cycle is
                // real (operation -> report -> operation) and bounded so it terminates.
                if depth + 1 >= Self::MAX_FOLLOWUP_DEPTH {
                    if !result.actions.is_empty() {
                        warn!(
                            "etcd client {} reached the follow-up depth limit ({}); \
                             dropping {} action(s)",
                            client_id,
                            Self::MAX_FOLLOWUP_DEPTH,
                            result.actions.len()
                        );
                    }
                    return;
                }
                for action in result.actions {
                    let executed = match protocol.execute_action(action) {
                        Ok(executed) => executed,
                        Err(e) => {
                            error!("etcd client {} rejected follow-up action: {}", client_id, e);
                            continue;
                        }
                    };
                    match Self::apply_action(
                        executed,
                        client_id,
                        &etcd,
                        &app_state,
                        &llm_client,
                        &status_tx,
                        depth + 1,
                    )
                    .await
                    {
                        Ok(Applied::Ran(detail)) => {
                            info!("etcd client {} follow-up: {}", client_id, detail)
                        }
                        Ok(Applied::Disconnect) => break,
                        Err(e) => {
                            error!("etcd client {} follow-up action failed: {}", client_id, e)
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    "etcd client {} LLM call failed after operation: {}",
                    client_id, e
                );
            }
        }
    }
}
