//! CouchDB client implementation
pub mod actions;

pub use actions::CouchDbClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::client::couchdb::actions::{
    COUCHDB_CLIENT_CONNECTED_EVENT, COUCHDB_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::{console_error, console_info};

/// CouchDB client that connects to a CouchDB server
pub struct CouchDbClient;

impl CouchDbClient {
    /// Connect to a CouchDB server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<SocketAddr> {
        // Build CouchDB URL (add http:// if not present)
        let url = if remote_addr.starts_with("http://") || remote_addr.starts_with("https://") {
            remote_addr.clone()
        } else {
            format!("http://{}", remote_addr)
        };

        console_info!(status_tx, "Connecting to CouchDB at {}", url);

        // Create CouchDB client using couch_rs
        let client = if let (Some(user), Some(pass)) = (username.clone(), password.clone()) {
            console_info!(status_tx, "Using basic auth (username: {})", user);
            couch_rs::Client::new(&url, &user, &pass)
                .context(format!("Failed to create CouchDB client for {}", url))?
        } else {
            couch_rs::Client::new_no_auth(&url)
                .context(format!("Failed to create CouchDB client for {}", url))?
        };

        // Try to connect and get server info
        let server_info = match client.check_status().await {
            Ok(status) => {
                console_info!(
                    status_tx,
                    "Connected to CouchDB (version: {})",
                    &status.version
                );
                Some(serde_json::json!({
                    "couchdb": "Welcome",
                    "version": status.version,
                    "vendor": status.vendor
                }))
            }
            Err(e) => {
                console_error!(status_tx, "Failed to get CouchDB server info: {}", e);
                None
            }
        };

        // Parse local address from URL
        // For HTTP clients, we don't have a real local socket address
        // Use a dummy address
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        info!(
            "CouchDB client {} connected to {} (local: {})",
            client_id, url, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] CouchDB client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Clone for async task
        let client_arc = Arc::new(tokio::sync::Mutex::new(client));
        let client_for_connected = client_arc.clone();

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered - and already being drained by its own task - BEFORE the
        // connected-event LLM call, which a manual `*` rule can park for minutes: the
        // operator must be able to reach the client while it waits. The couch_rs handle
        // is already behind an Arc<Mutex<_>>, so the command task shares the very same
        // connection the LLM path uses.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(command_loop(
            command_rx,
            client_id,
            client_arc.clone(),
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with couchdb_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &COUCHDB_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": url,
                    "server_info": server_info,
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(), // No memory yet for initial connection
                Some(&event),
                &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Execute actions from LLM response
                    // Use a queue to handle follow-up actions
                    let mut action_queue: Vec<serde_json::Value> = result.actions;

                    while let Some(action) = action_queue.pop() {
                        match execute_couchdb_action(
                            &action,
                            client_id,
                            &client_for_connected,
                            0,
                            &app_state,
                            &llm_client,
                            &status_tx,
                            Dispatch::Inline,
                        )
                        .await
                        {
                            Ok(follow_up_actions) => {
                                // Add follow-up actions to the front of the queue
                                action_queue.extend(follow_up_actions.into_iter().rev());
                            }
                            Err(e) => {
                                console_error!(
                                    status_tx,
                                    "Error executing action after connect: {}",
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    console_error!(status_tx, "LLM error on couchdb_connected event: {}", e);
                }
            }
        }

        // A connect-event action may have disconnected the client; the handle must not
        // outlive it or the dashboard offers [ send ] into a dead connection.
        if matches!(
            app_state.get_client(client_id).await.map(|c| c.status),
            None | Some(ClientStatus::Disconnected)
        ) {
            app_state.remove_client_handle(client_id).await;
        }

        // CouchDB has no persistent read loop: operations are driven by actions. The
        // command task spawned above is what keeps the client alive - it replaces the old
        // 5s "is the client gone yet" poll, because the command channel closes the moment
        // the client is removed.
        Ok(local_addr)
    }
}

/// Drain injected commands until the channel closes (client removed) or an injected
/// `disconnect` ends the session.
///
/// `command_support::handle_stream_client_command` cannot serve this client: it writes
/// `SendData` to a socket, and every CouchDB verb yields `ClientActionResult::Custom`
/// that has to go through `couch_rs`. So the action goes through
/// [`execute_couchdb_action`] - the same function the connected-event path uses - and the
/// outcome is recorded and replied exactly the way the generic arm does it.
async fn command_loop(
    mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
    client_id: ClientId,
    client: Arc<tokio::sync::Mutex<couch_rs::Client>>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
) {
    let protocol = crate::client::couchdb::actions::CouchDbClientProtocol::new();

    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();

        // Validate through the protocol's own vocabulary first, so an unknown or
        // misspelled action is reported as Rejected rather than silently ignored.
        let outcome = match protocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(ClientActionResult::Custom { name, .. }) if name == "disconnect" => {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                Ok(ClientSendOutcome::Disconnected)
            }
            Ok(_) => {
                // Awaited, not dispatched: the reported outcome describes an operation
                // that has actually completed, and the couchdb_response_received event
                // has already fired (and its follow-up actions run) by then.
                let mut queue = vec![action.clone()];
                let mut executed = 0usize;
                let mut failure: Option<anyhow::Error> = None;
                while let Some(next) = queue.pop() {
                    match execute_couchdb_action(
                        &next,
                        client_id,
                        &client,
                        0,
                        &app_state,
                        &llm_client,
                        &status_tx,
                        Dispatch::Deferred,
                    )
                    .await
                    {
                        Ok(follow_ups) => {
                            executed += 1;
                            queue.extend(follow_ups.into_iter().rev());
                        }
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                }
                match failure {
                    Some(e) => Err(e),
                    None => {
                        let action_type = action
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("action");
                        Ok(ClientSendOutcome::Executed {
                            detail: if executed > 1 {
                                format!(
                                    "{action_type} executed ({} follow-up action(s) from the \
                                     response event)",
                                    executed - 1
                                )
                            } else {
                                format!("{action_type} executed")
                            },
                        })
                    }
                }
            }
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
                "CouchDB client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);

        if disconnect {
            break;
        }
    }

    info!("CouchDB client {} command loop stopped", client_id);
    app_state.remove_client_handle(client_id).await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Execute a CouchDB action from the LLM
/// Whether the `couchdb_response_received` event's LLM call runs on the caller's
/// task or on its own.
/// How many LLM turns one action -> response-event -> action chain may take.
///
/// The cycle is real: `create_database` raises `couchdb_response_received`, whose answer may be
/// another `create_database`. Executing that answer -- which this client did not used to do on
/// the deferred path -- is what makes the recursion possible, so it is bounded rather than cut.
const MAX_FOLLOWUP_DEPTH: u8 = 6;

#[derive(Clone, Copy)]
enum Dispatch {
    /// Await the LLM call and hand its actions back, so the connected-event path
    /// keeps draining follow-ups exactly as it always has.
    Inline,
    /// Raise the event from its own registered task and return no actions.
    ///
    /// Used by the injected-command loop. A dashboard-created client defaults to a
    /// `*` -> manual rule, so that LLM call can park for up to 300s waiting for a
    /// human, while the composer's SEND_TIMEOUT is 30s. Awaiting it would report a
    /// command that in fact succeeded as a timeout, and head-of-line-block every
    /// later command on the channel.
    Deferred,
}

/// Run the actions a deferred event's answer produced, bounded by [`MAX_FOLLOWUP_DEPTH`].
///
/// Shared by the two deferred paths (`couchdb_response_received` and
/// `couchdb_client_conflict`). Each action can itself raise a response event, so this is the
/// recursive edge; hitting the bound reports on the status stream rather than stopping quietly.
#[allow(clippy::too_many_arguments)]
async fn run_followups(
    actions: Vec<serde_json::Value>,
    client_id: ClientId,
    client: &Arc<tokio::sync::Mutex<couch_rs::Client>>,
    depth: u8,
    app_state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    if actions.is_empty() {
        return;
    }
    if depth >= MAX_FOLLOWUP_DEPTH {
        warn!(
            "CouchDB client {} stopped a follow-up chain at depth {}: {} action(s) not executed",
            client_id,
            depth,
            actions.len()
        );
        let _ = status_tx.send(format!(
            "[CLIENT] ⚠ couchdb client {} hit the follow-up depth limit ({}); {} action(s) were \
             not executed",
            client_id,
            MAX_FOLLOWUP_DEPTH,
            actions.len()
        ));
        return;
    }

    let mut queue = actions;
    while let Some(action) = queue.pop() {
        match execute_couchdb_action(
            &action,
            client_id,
            client,
            depth + 1,
            app_state,
            llm_client,
            status_tx,
            Dispatch::Deferred,
        )
        .await
        {
            Ok(more) => queue.extend(more.into_iter().rev()),
            Err(e) => {
                error!(
                    "CouchDB client {} follow-up action failed: {}",
                    client_id, e
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] couchdb client {client_id} follow-up action failed: {e}"
                ));
            }
        }
    }
}

/// Returns an explicitly boxed future rather than being an `async fn`.
///
/// Load-bearing: the chain is `execute_couchdb_action` -> `send_response_event` ->
/// `run_followups` -> `execute_couchdb_action`, and async fns in a cycle cannot have their
/// opaque return types inferred (E0391). Naming the type here breaks it at the definition;
/// boxing at a call site does not, because the coercion still needs the callee's opaque type.
///
/// **Every arm copies the handle out of the mutex and releases it immediately**
/// (`client.lock().await.clone()`), rather than holding the guard for the arm's body.
/// `couch_rs::Client` is a cheap `Clone` over a reqwest client — `Database::new` clones one
/// internally — so the copy costs nothing, and the guard was previously held across
/// `send_response_event`, which on the `Dispatch::Inline` path **makes an LLM call**. A
/// dashboard-created client defaults to a `*` -> manual routing rule, so that call can park
/// for the full 300s intercept timeout with the CouchDB handle locked, and every injected
/// `[ send ]` command blocks on `client.lock()` for the whole park — defeating the one thing
/// the command channel exists to guarantee. It also serialised operations that reqwest is
/// perfectly happy to run concurrently.
#[allow(clippy::too_many_arguments)]
fn execute_couchdb_action<'a>(
    action: &'a serde_json::Value,
    client_id: ClientId,
    client: &'a Arc<tokio::sync::Mutex<couch_rs::Client>>,
    depth: u8,
    app_state: &'a Arc<AppState>,
    llm_client: &'a OllamaClient,
    status_tx: &'a mpsc::UnboundedSender<String>,
    notify: Dispatch,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<serde_json::Value>>> + Send + 'a>>
{
    Box::pin(async move {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        match action_type {
            "create_database" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                console_info!(status_tx, "Creating database: {}", db_name);

                let couch = client.lock().await.clone();
                let actions = match couch.make_db(db_name).await {
                    Ok(_) => {
                        console_info!(status_tx, "Database {} created successfully", db_name);
                        send_response_event(
                            client_id,
                            "create_database",
                            true,
                            serde_json::json!({"database": db_name}),
                            None,
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to create database {}: {}", db_name, e);
                        send_response_event(
                            client_id,
                            "create_database",
                            false,
                            serde_json::json!({}),
                            Some(format!("{}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await
                    }
                };
                return Ok(actions);
            }
            "delete_database" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                console_info!(status_tx, "Deleting database: {}", db_name);

                let couch = client.lock().await.clone();
                match couch.destroy_db(db_name).await {
                    Ok(_) => {
                        console_info!(status_tx, "Database {} deleted successfully", db_name);
                        return Ok(send_response_event(
                            client_id,
                            "delete_database",
                            true,
                            serde_json::json!({"database": db_name}),
                            None,
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to delete database {}: {}", db_name, e);
                        return Ok(send_response_event(
                            client_id,
                            "delete_database",
                            false,
                            serde_json::json!({}),
                            Some(format!("{}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "list_databases" => {
                console_info!(status_tx, "Listing all databases");

                let couch = client.lock().await.clone();
                match couch.list_dbs().await {
                    Ok(dbs) => {
                        console_info!(status_tx, "Found {} databases", dbs.len());
                        return Ok(send_response_event(
                            client_id,
                            "list_databases",
                            true,
                            serde_json::json!({"databases": dbs}),
                            None,
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to list databases: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "list_databases",
                            false,
                            serde_json::json!({}),
                            Some(format!("{}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "create_document" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let doc_id = action.get("doc_id").and_then(|v| v.as_str());

                let document = action
                    .get("document")
                    .ok_or_else(|| anyhow::anyhow!("Missing document"))?;

                console_info!(status_tx, "Creating document in {}: {:?}", db_name, doc_id);

                let couch = client.lock().await.clone();

                // Use raw HTTP API via req()
                let (path, method) = if let Some(id) = doc_id {
                    // PUT /{db}/{docid} - create with specific ID
                    (format!("/{}/{}", db_name, id), reqwest::Method::PUT)
                } else {
                    // POST /{db} - auto-generate ID
                    (format!("/{}", db_name), reqwest::Method::POST)
                };

                let response = match couch
                    .req(method.clone(), &path, None)
                    .json(document)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        console_error!(status_tx, "Failed to create document: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "create_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Request failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                let status = response.status();
                match response.json::<serde_json::Value>().await {
                    Ok(result) => {
                        if status.is_success() {
                            console_info!(
                                status_tx,
                                "Document created: {} (rev: {})",
                                result
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown"),
                                result
                                    .get("rev")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "create_document",
                                true,
                                result,
                                None,
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        } else {
                            console_error!(
                                status_tx,
                                "Failed to create document: {} - {}",
                                status,
                                result
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown error")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "create_document",
                                false,
                                serde_json::json!({}),
                                Some(format!(
                                    "{}: {}",
                                    result
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error"),
                                    result
                                        .get("reason")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                )),
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        }
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to parse response: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "create_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Response parsing failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "get_document" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let doc_id = action
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing doc_id"))?;

                console_info!(status_tx, "Getting document {}/{}", db_name, doc_id);

                let couch = client.lock().await.clone();
                let db = match couch.db(db_name).await {
                    Ok(db) => db,
                    Err(e) => {
                        console_error!(status_tx, "Failed to get database {}: {}", db_name, e);
                        return Ok(send_response_event(
                            client_id,
                            "get_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Database not found: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                match db.get_raw(doc_id).await {
                    Ok(doc) => {
                        console_info!(status_tx, "Document retrieved: {}", doc_id);
                        return Ok(send_response_event(
                            client_id,
                            "get_document",
                            true,
                            doc,
                            None,
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to get document {}: {}", doc_id, e);
                        return Ok(send_response_event(
                            client_id,
                            "get_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("{}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "update_document" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let doc_id = action
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing doc_id"))?;

                let document = action
                    .get("document")
                    .ok_or_else(|| anyhow::anyhow!("Missing document"))?;

                // Ensure document has _id
                let mut doc = document.clone();
                if let Some(obj) = doc.as_object_mut() {
                    obj.insert("_id".to_string(), serde_json::json!(doc_id));
                }

                // Verify _rev is present (required for updates)
                let rev = doc.get("_rev").and_then(|v| v.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("Missing _rev field in document (required for updates)")
                })?;

                console_info!(
                    status_tx,
                    "Updating document {}/{} (rev: {})",
                    db_name,
                    doc_id,
                    rev
                );

                let couch = client.lock().await.clone();

                // Use raw HTTP API via req()
                // PUT /{db}/{docid} with document including _rev
                let path = format!("/{}/{}", db_name, doc_id);

                let response = match couch
                    .req(reqwest::Method::PUT, &path, None)
                    .json(&doc)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        console_error!(status_tx, "Failed to update document: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "update_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Request failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                let status = response.status();
                match response.json::<serde_json::Value>().await {
                    Ok(result) => {
                        if status.is_success() {
                            console_info!(
                                status_tx,
                                "Document updated: {} (new rev: {})",
                                result
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown"),
                                result
                                    .get("rev")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "update_document",
                                true,
                                result,
                                None,
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        } else {
                            // Check for conflict (409)
                            if status.as_u16() == 409 {
                                console_error!(
                                    status_tx,
                                    "Conflict updating document {}: revision mismatch",
                                    doc_id
                                );
                                let conflict_actions = send_conflict_event(
                                    client_id,
                                    db_name,
                                    doc_id,
                                    Some(rev),
                                    client,
                                    depth,
                                    app_state,
                                    llm_client,
                                    status_tx,
                                    notify,
                                )
                                .await;
                                if !conflict_actions.is_empty() {
                                    return Ok(conflict_actions);
                                }
                            }

                            console_error!(
                                status_tx,
                                "Failed to update document: {} - {}",
                                status,
                                result
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown error")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "update_document",
                                false,
                                serde_json::json!({}),
                                Some(format!(
                                    "{}: {}",
                                    result
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error"),
                                    result
                                        .get("reason")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                )),
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        }
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to parse response: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "update_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Response parsing failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "delete_document" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let doc_id = action
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing doc_id"))?;

                let rev = action
                    .get("rev")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing rev"))?;

                console_info!(
                    status_tx,
                    "Deleting document {}/{} (rev: {})",
                    db_name,
                    doc_id,
                    rev
                );

                let couch = client.lock().await.clone();

                // Use raw HTTP API via req()
                // DELETE /{db}/{docid}?rev={rev}
                let path = format!("/{}/{}", db_name, doc_id);
                let mut params = std::collections::HashMap::new();
                params.insert("rev".to_string(), rev.to_string());

                let response = match couch
                    .req(reqwest::Method::DELETE, &path, Some(&params))
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        console_error!(status_tx, "Failed to delete document: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "delete_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Request failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                let status = response.status();
                match response.json::<serde_json::Value>().await {
                    Ok(result) => {
                        if status.is_success() {
                            console_info!(
                                status_tx,
                                "Document deleted: {} (rev: {})",
                                result
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown"),
                                result
                                    .get("rev")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "delete_document",
                                true,
                                result,
                                None,
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        } else {
                            // Check for conflict (409)
                            if status.as_u16() == 409 {
                                console_error!(
                                    status_tx,
                                    "Conflict deleting document {}: revision mismatch",
                                    doc_id
                                );
                                let conflict_actions = send_conflict_event(
                                    client_id,
                                    db_name,
                                    doc_id,
                                    Some(rev),
                                    client,
                                    depth,
                                    app_state,
                                    llm_client,
                                    status_tx,
                                    notify,
                                )
                                .await;
                                if !conflict_actions.is_empty() {
                                    return Ok(conflict_actions);
                                }
                            }

                            console_error!(
                                status_tx,
                                "Failed to delete document: {} - {}",
                                status,
                                result
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown error")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "delete_document",
                                false,
                                serde_json::json!({}),
                                Some(format!(
                                    "{}: {}",
                                    result
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error"),
                                    result
                                        .get("reason")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                )),
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        }
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to parse response: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "delete_document",
                            false,
                            serde_json::json!({}),
                            Some(format!("Response parsing failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "bulk_docs" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let docs = action
                    .get("docs")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("Missing or invalid docs array"))?;

                console_info!(
                    status_tx,
                    "Bulk docs: {} documents in {}",
                    docs.len(),
                    db_name
                );

                let couch = client.lock().await.clone();

                // Use raw HTTP API via req()
                // POST /{db}/_bulk_docs with {"docs": [...]}
                let path = format!("/{}/_bulk_docs", db_name);
                let body = serde_json::json!({
                    "docs": docs
                });

                let response = match couch
                    .req(reqwest::Method::POST, &path, None)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        console_error!(status_tx, "Failed to perform bulk docs: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "bulk_docs",
                            false,
                            serde_json::json!({}),
                            Some(format!("Request failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                let status = response.status();
                match response.json::<serde_json::Value>().await {
                    Ok(results) => {
                        if status.is_success() {
                            // Results is an array of {ok, id, rev} or {error, reason}
                            let count = if let Some(arr) = results.as_array() {
                                arr.len()
                            } else {
                                0
                            };
                            console_info!(status_tx, "Bulk docs completed: {} results", count);
                            return Ok(send_response_event(
                                client_id,
                                "bulk_docs",
                                true,
                                results,
                                None,
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        } else {
                            console_error!(
                                status_tx,
                                "Failed to perform bulk docs: {} - {}",
                                status,
                                results
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown error")
                            );
                            return Ok(send_response_event(
                                client_id,
                                "bulk_docs",
                                false,
                                serde_json::json!({}),
                                Some(format!(
                                    "{}: {}",
                                    results
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error"),
                                    results
                                        .get("reason")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                )),
                                client,
                                depth,
                                app_state,
                                llm_client,
                                status_tx,
                                notify,
                            )
                            .await);
                        }
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to parse response: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "bulk_docs",
                            false,
                            serde_json::json!({}),
                            Some(format!("Response parsing failed: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "list_documents" => {
                let db_name = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing database name"))?;

                let _include_docs = action
                    .get("include_docs")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                console_info!(status_tx, "Listing documents in {}", db_name);

                let couch = client.lock().await.clone();
                let db = match couch.db(db_name).await {
                    Ok(db) => db,
                    Err(e) => {
                        console_error!(status_tx, "Failed to get database {}: {}", db_name, e);
                        return Ok(send_response_event(
                            client_id,
                            "list_documents",
                            false,
                            serde_json::json!({}),
                            Some(format!("Database not found: {}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                };

                match db.get_all_raw().await {
                    Ok(all_docs) => {
                        console_info!(status_tx, "Found {} documents", all_docs.total_rows);
                        // Convert DocumentCollection to JSON manually
                        let docs_json = serde_json::json!({
                            "total_rows": all_docs.total_rows,
                            "offset": all_docs.offset,
                            "rows": all_docs.rows
                        });
                        return Ok(send_response_event(
                            client_id,
                            "list_documents",
                            true,
                            docs_json,
                            None,
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to list documents: {}", e);
                        return Ok(send_response_event(
                            client_id,
                            "list_documents",
                            false,
                            serde_json::json!({}),
                            Some(format!("{}", e)),
                            client,
                            depth,
                            app_state,
                            llm_client,
                            status_tx,
                            notify,
                        )
                        .await);
                    }
                }
            }
            "query_view" => {
                console_info!(
                    status_tx,
                    "View queries not yet fully implemented in couch_rs"
                );
                return Ok(send_response_event(
                    client_id,
                    "query_view",
                    false,
                    serde_json::json!({}),
                    Some("View queries not yet implemented".to_string()),
                    client,
                    depth,
                    app_state,
                    llm_client,
                    status_tx,
                    notify,
                )
                .await);
            }
            "watch_changes" => {
                // Long-poll `/{db}/_changes` in its own registered task and raise
                // `couchdb_change_detected` per change.
                //
                // This verb used to answer "Changes feed not yet implemented", which meant
                // COUCHDB_CLIENT_CHANGE_DETECTED_EVENT -- advertised in get_event_types(), so
                // the model could be told it exists and write a handler for it -- could never
                // fire. Watching a database for changes is the one thing CouchDB is chosen
                // for over a plain document store.
                let database = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if database.is_empty() {
                    return Ok(send_response_event(
                        client_id,
                        "watch_changes",
                        false,
                        serde_json::json!({}),
                        Some("watch_changes needs a database".to_string()),
                        client,
                        depth,
                        app_state,
                        llm_client,
                        status_tx,
                        notify,
                    )
                    .await);
                }

                let base_url = app_state
                    .with_client_mut(client_id, |c| {
                        c.get_protocol_field("remote_addr")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .await
                    .flatten()
                    .unwrap_or_default();

                let watch_client = client.clone();
                let watch_state = app_state.clone();
                let watch_llm = llm_client.clone();
                let watch_tx = status_tx.clone();
                let db = database.clone();
                let handle = tokio::spawn(async move {
                    watch_changes_feed(
                        client_id,
                        base_url,
                        db,
                        watch_client,
                        watch_state,
                        watch_llm,
                        watch_tx,
                    )
                    .await;
                });
                app_state.register_client_task(client_id, handle).await;

                return Ok(send_response_event(
                    client_id,
                    "watch_changes",
                    true,
                    serde_json::json!({ "database": database, "watching": true }),
                    None,
                    client,
                    depth,
                    app_state,
                    llm_client,
                    status_tx,
                    notify,
                )
                .await);
            }
            "disconnect" => {
                console_info!(status_tx, "Disconnecting CouchDB client {}", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                return Ok(Vec::new());
            }
            "wait_for_more" => {
                // No action needed - just acknowledge
                return Ok(Vec::new());
            }
            _ => {
                console_error!(status_tx, "Unknown action type: {}", action_type);
                return Ok(Vec::new());
            }
        }
    })
}

/// Send response event to LLM
#[allow(clippy::too_many_arguments)]
async fn send_response_event(
    client_id: ClientId,
    operation: &str,
    success: bool,
    data: serde_json::Value,
    error: Option<String>,
    client: &Arc<tokio::sync::Mutex<couch_rs::Client>>,
    depth: u8,
    app_state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    notify: Dispatch,
) -> Vec<serde_json::Value> {
    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        let mut event_data = serde_json::json!({
            "operation": operation,
            "success": success,
            "data": data,
        });

        if let Some(err) = error {
            event_data["error"] = serde_json::json!(err);
        }

        let event = Event::new(&COUCHDB_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

        // Deferred: hand the event to its own registered task and answer the caller
        // now. The command loop owes the dashboard a reply, and this LLM call may be
        // parked for a human; see `Dispatch::Deferred`.
        if let Dispatch::Deferred = notify {
            let llm_client = llm_client.clone();
            let app_state_task = app_state.clone();
            let status_tx = status_tx.clone();
            let client_task = client.clone();
            let handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
                    &app_state_task,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
                    &status_tx,
                )
                .await
                {
                    Ok(result) => {
                        if let Some(new_memory) = result.memory_updates {
                            app_state_task
                                .set_memory_for_client(client_id, new_memory)
                                .await;
                        }
                        // These used to be counted into a log line and dropped, on the
                        // stated grounds that "only the client's own loop owns the CouchDB
                        // handle". That was not true: the handle is an
                        // `Arc<tokio::sync::Mutex<couch_rs::Client>>`, shared by
                        // construction, and `execute_couchdb_action` already takes it by
                        // reference. The inline sibling of this branch returns its actions
                        // and they run, so the deferred path was the odd one out -- and it
                        // is the path every dashboard-injected command takes.
                        run_followups(
                            result.actions,
                            client_id,
                            &client_task,
                            depth,
                            &app_state_task,
                            &llm_client,
                            &status_tx,
                        )
                        .await;
                    }
                    Err(e) => error!("LLM error on deferred response event: {}", e),
                }
            });
            app_state.register_client_task(client_id, handle).await;
            return Vec::new();
        }

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
            status_tx,
        )
        .await
        {
            Ok(result) => {
                // Update memory if provided
                if let Some(new_memory) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, new_memory).await;
                }

                // Return actions to be executed by caller
                return result.actions;
            }
            Err(e) => {
                error!("LLM error on response event: {}", e);
            }
        }
    }
    Vec::new()
}

/// Send conflict event to LLM when document revision mismatch occurs
#[allow(clippy::too_many_arguments)]
async fn send_conflict_event(
    client_id: ClientId,
    database: &str,
    doc_id: &str,
    expected_rev: Option<&str>,
    client: &Arc<tokio::sync::Mutex<couch_rs::Client>>,
    depth: u8,
    app_state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    notify: Dispatch,
) -> Vec<serde_json::Value> {
    use crate::client::couchdb::actions::COUCHDB_CLIENT_CONFLICT_EVENT;

    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        let event = Event::new(
            &COUCHDB_CLIENT_CONFLICT_EVENT,
            serde_json::json!({
                "database": database,
                "doc_id": doc_id,
                "expected_rev": expected_rev,
            }),
        );

        // Deferred: same reasoning as in `send_response_event` -- the command loop
        // owes the dashboard a reply and must not wait on a parked LLM call.
        if let Dispatch::Deferred = notify {
            let llm_client = llm_client.clone();
            let app_state_task = app_state.clone();
            let status_tx = status_tx.clone();
            let client_task = client.clone();
            let handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
                    &app_state_task,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
                    &status_tx,
                )
                .await
                {
                    Ok(result) => {
                        if let Some(new_memory) = result.memory_updates {
                            app_state_task
                                .set_memory_for_client(client_id, new_memory)
                                .await;
                        }
                        // A 409 is precisely the event whose answer must run: the model has
                        // just been told a write lost a revision race and asked what to do
                        // about it. This arm did not exist.
                        run_followups(
                            result.actions,
                            client_id,
                            &client_task,
                            depth,
                            &app_state_task,
                            &llm_client,
                            &status_tx,
                        )
                        .await;
                    }
                    Err(e) => error!("LLM error on deferred conflict event: {}", e),
                }
            });
            app_state.register_client_task(client_id, handle).await;
            return Vec::new();
        }

        // The model's answer to a conflict is returned to the caller and queued like
        // any other follow-up. It used to be discarded with `let _ =`, so a model
        // resolving a 409 was silently ignored.
        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
            status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(new_memory) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, new_memory).await;
                }
                return result.actions;
            }
            Err(e) => error!("LLM error on conflict event: {}", e),
        }
    }
    Vec::new()
}

/// Long-poll a database's `_changes` feed, raising `couchdb_change_detected` per change.
///
/// Long-poll rather than `feed=continuous`: each request returns a complete JSON body, so
/// there is no partial-line framing to get wrong, and the loop stops cleanly when the
/// client goes away. `since` advances to the sequence the server reports, so a change is
/// reported once.
///
/// The answer to each `couchdb_change_detected` **is** executed, bounded by
/// [`MAX_FOLLOWUP_DEPTH`].
///
/// This used to say it raised no actions of its own because "the event's answer is handled by
/// the normal event path". Nothing handled it: the call was an `if let Err(..)` with no success
/// arm, so a client told to watch a database and react to changes watched them and did nothing.
/// Each change starts its own bounded chain, which is the same contract every other event on
/// this client has.
#[allow(clippy::too_many_arguments)]
async fn watch_changes_feed(
    client_id: ClientId,
    base_url: String,
    database: String,
    client: Arc<tokio::sync::Mutex<couch_rs::Client>>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
) {
    // Built through the shared constructor so a literal-IP CouchDB host skips the system
    // resolver; see `crate::llm::ollama_client::client_for_endpoint`.
    let http = crate::llm::ollama_client::client_for_endpoint(&base_url);
    let mut since = "now".to_string();
    loop {
        if app_state.get_client(client_id).await.is_none() {
            return;
        }
        let url = format!(
            "{}/{}/_changes?feed=longpoll&since={}&timeout=30000",
            base_url.trim_end_matches('/'),
            database,
            since
        );
        let body: serde_json::Value = match http.get(&url).send().await {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        "CouchDB client {} changes feed decode failed: {}",
                        client_id,
                        e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            },
            Err(e) => {
                tracing::warn!(
                    "CouchDB client {} changes feed request failed: {}",
                    client_id,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        if let Some(seq) = body.get("last_seq") {
            since = seq
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| seq.to_string());
        }
        let Some(results) = body.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for change in results {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                continue;
            };
            let event = Event::new(
                &crate::client::couchdb::actions::COUCHDB_CLIENT_CHANGE_DETECTED_EVENT,
                serde_json::json!({
                    "database": database,
                    "doc_id": change.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
                    "seq": change.get("seq"),
                    "deleted": change.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false),
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
                &crate::client::couchdb::actions::CouchDbClientProtocol::new(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(new_memory) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, new_memory).await;
                    }
                    run_followups(
                        result.actions,
                        client_id,
                        &client,
                        0,
                        &app_state,
                        &llm_client,
                        &status_tx,
                    )
                    .await;
                }
                Err(e) => error!(
                    "CouchDB client {} LLM error on couchdb_change_detected: {}",
                    client_id, e
                ),
            }
        }
    }
}
