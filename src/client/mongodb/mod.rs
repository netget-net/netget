//! MongoDB client implementation
pub mod actions;

pub use actions::MongodbClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

#[cfg(not(target_arch = "wasm32"))]
use mongodb::{
    bson::Document,
    options::{ClientOptions, FindOptions},
    Client as MongoClient, Database,
};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::mongodb::actions::{
    MONGODB_CLIENT_CONNECTED_EVENT, MONGODB_CLIENT_RESULT_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{ClientId, ClientStatus};

/// What one executed action did to the MongoDB database handle.
///
/// Returned by [`MongodbClient::apply_action`], the single place an action reaches the
/// server — the connected-event LLM path and injected dashboard commands both go through it.
#[cfg(not(target_arch = "wasm32"))]
enum Applied {
    /// An operation ran. `detail` is the injected-action outcome text; `event` is the
    /// `mongodb_result_received` the client raises next, exactly as the LLM path does.
    Ran { detail: String, event: Event },
    /// The session should end.
    Disconnect,
    /// The action executed but touched the database in no way.
    Nothing(&'static str),
}

/// How many action → result → action hops one operation may set off.
///
/// The chain is genuinely self-referential: an action produces a result, the result is an
/// event, and the model's answer to that event is more actions. The previous code cut it by
/// running follow-ups through `apply_action` directly, so a follow-up raised no event at all
/// — the chain was exactly one step deep and a `find` the model issued in reply to an insert
/// confirmation ran with its documents going nowhere. That is the recorded elasticsearch
/// defect, in a MongoDB shirt, with a comment explaining why it was fine.
///
/// A depth bound is the honest version of the same protection: every operation reports, and
/// the chain still terminates. Past the bound an action is still executed — refusing it would
/// discard work the model asked for — but its result is not reported, so nothing recurses.
const MAX_FOLLOWUP_DEPTH: u8 = 4;

/// MongoDB client that connects to a MongoDB server
pub struct MongodbClient;

impl MongodbClient {
    /// Connect to a MongoDB server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        Self::connect_impl(
            remote_addr,
            llm_client,
            app_state,
            status_tx,
            client_id,
            startup_params,
        )
        .await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn connect_impl(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse startup parameters
        let database_name = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("database"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "admin".to_string());

        let username = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("username"))
            .transpose()?
            .flatten();

        let password = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("password"))
            .transpose()?
            .flatten();

        // Build MongoDB connection string
        let connection_string = if let (Some(user), Some(pass)) = (username, password) {
            format!("mongodb://{}:{}@{}", user, pass, remote_addr)
        } else {
            format!("mongodb://{}", remote_addr)
        };

        // Parse connection options
        let client_options = ClientOptions::parse(&connection_string)
            .await
            .context(format!(
                "Failed to parse MongoDB connection string for {}",
                remote_addr
            ))?;

        // Connect to MongoDB server
        let mongo_client = MongoClient::with_options(client_options)
            .context(format!("Failed to connect to MongoDB at {}", remote_addr))?;

        info!("MongoDB client {} connected to {}", client_id, remote_addr);

        // Get database
        let db = mongo_client.database(&database_name);

        // Parse socket address (MongoDB connection string to SocketAddr)
        let socket_addr: SocketAddr = if remote_addr.contains(':') {
            remote_addr
                .parse()
                .context("Failed to parse socket address")?
        } else {
            format!("{}:27017", remote_addr)
                .parse()
                .context("Failed to parse socket address")?
        };

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] MongoDB client {} connected to {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap database in Arc for shared access. `Database` is a cheap handle onto the
        // driver's connection pool and is `Send + Sync`, so the LLM path and the injected
        // command loop can hold it at once with no mutex.
        let db_arc = Arc::new(db);
        let protocol = Arc::new(MongodbClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes — the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            db_arc.clone(),
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &MONGODB_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                    "database": database_name,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            let protocol_clone = protocol.clone();
            let db_clone = db_arc.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    protocol_clone.as_ref(),
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
                            match Self::execute_llm_action(
                                client_id,
                                action,
                                &protocol_clone,
                                &db_clone,
                                &app_state_clone,
                                &llm_client,
                                &status_tx_clone,
                                0,
                            )
                            .await
                            {
                                Ok(true) => {}
                                Ok(false) => break,
                                Err(e) => error!("Error executing MongoDB action: {}", e),
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for MongoDB client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        Ok(socket_addr)
    }

    #[cfg(target_arch = "wasm32")]
    async fn connect_impl(
        _remote_addr: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _client_id: ClientId,
        _startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        Err(anyhow::anyhow!("MongoDB client feature not enabled"))
    }

    /// Drain injected commands until the channel closes (the client was removed or stopped)
    /// or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// the driver owns the socket, so every verb yields `ClientActionResult::Custom` and the
    /// effect goes through the shared [`Self::apply_action`].
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<MongodbClientProtocol>,
        db: Arc<Database>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let mut follow_up: Option<Event> = None;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => match Self::apply_action(client_id, result, &db, &status_tx).await {
                    Err(e) => Err(e),
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Ok(Applied::Nothing(what)) => Ok(ClientSendOutcome::Executed {
                        detail: what.to_string(),
                    }),
                    Ok(Applied::Ran { detail, event }) => {
                        follow_up = Some(event);
                        Ok(ClientSendOutcome::Executed { detail })
                    }
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
                error!("MongoDB client {} injected action failed: {}", client_id, e);
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
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }

            // The model sees an injected operation's result exactly as it sees one it asked
            // for — after the reply, so the dashboard is not held for an LLM round-trip.
            if let Some(event) = follow_up {
                if let Err(e) = Self::raise_result_event(
                    client_id,
                    event,
                    &protocol,
                    &db,
                    &app_state,
                    &llm_client,
                    &status_tx,
                    0,
                )
                .await
                {
                    error!("MongoDB client {} result event failed: {}", client_id, e);
                }
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a client whose loop is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one action from the LLM and report what it did.
    ///
    /// Returns `false` once the session has ended, so a caller iterating a batch stops rather
    /// than running the rest against a disconnected client.
    ///
    /// `depth` is how many follow-up hops led here; 0 for the connected event and for an
    /// injected command. See [`MAX_FOLLOWUP_DEPTH`].
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    async fn execute_llm_action(
        client_id: ClientId,
        action: serde_json::Value,
        protocol: &Arc<MongodbClientProtocol>,
        db: &Arc<Database>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> Result<bool> {
        match Self::apply_action(client_id, protocol.execute_action(action)?, db, status_tx).await?
        {
            Applied::Ran { event, detail } => {
                if depth >= MAX_FOLLOWUP_DEPTH {
                    warn!(
                        "MongoDB client {} stopped a follow-up chain at depth {}: '{}' ran but \
                         its result is not being reported, so the model will not answer it",
                        client_id, depth, detail
                    );
                    let _ = status_tx.send(format!(
                        "[WARN] MongoDB client {} hit the follow-up depth limit ({}); the last \
                         operation ran but its result was not reported",
                        client_id, MAX_FOLLOWUP_DEPTH
                    ));
                } else {
                    Self::raise_result_event(
                        client_id, event, protocol, db, app_state, llm_client, status_tx, depth,
                    )
                    .await?;
                }
            }
            Applied::Disconnect => {
                info!("MongoDB client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                return Ok(false);
            }
            Applied::Nothing(what) => {
                trace!(
                    "MongoDB client {} action had no effect: {}",
                    client_id,
                    what
                );
            }
        }

        Ok(true)
    }

    /// Run one executed action against the database. Shared by the LLM path and injected
    /// commands so the BSON conversion and driver calls exist exactly once.
    #[cfg(not(target_arch = "wasm32"))]
    async fn apply_action(
        client_id: ClientId,
        result: crate::llm::actions::client_trait::ClientActionResult,
        db: &Arc<Database>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        use crate::llm::actions::client_trait::ClientActionResult;

        match result {
            ClientActionResult::Custom { name, data } if name == "mongodb_find" => {
                let collection_name = data
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing collection")?;
                let filter_json = data.get("filter").cloned().unwrap_or(serde_json::json!({}));
                let projection_json = data.get("projection").cloned();
                let limit = data.get("limit").and_then(|v| v.as_i64());

                trace!(
                    "MongoDB client {} finding in collection: {}",
                    client_id,
                    collection_name
                );

                let collection = db.collection::<Document>(collection_name);

                // Convert JSON filter to BSON document
                let filter = serde_json::from_value::<Document>(filter_json.clone())
                    .context("Failed to convert filter to BSON")?;

                // Build find options
                let mut find_options = FindOptions::default();
                if let Some(proj_json) = projection_json {
                    let projection = serde_json::from_value::<Document>(proj_json).ok();
                    find_options.projection = projection;
                }
                if let Some(lim) = limit {
                    find_options.limit = Some(lim);
                }

                // Execute find
                let cursor = collection
                    .find(filter)
                    .with_options(find_options)
                    .await
                    .context("Failed to execute find")?;

                // Collect results
                use futures::stream::StreamExt;
                let documents: Vec<Document> = cursor
                    .collect::<Vec<Result<Document, mongodb::error::Error>>>()
                    .await
                    .into_iter()
                    .filter_map(|r| r.ok())
                    .collect();

                let _ = status_tx.send(format!(
                    "[MongoDB] Found {} documents in {}",
                    documents.len(),
                    collection_name
                ));

                let detail = format!(
                    "find on '{}' returned {} documents; no byte count — the driver owns the socket",
                    collection_name,
                    documents.len()
                );
                let event = result_event("find", Some(documents), None);
                Ok(Applied::Ran { detail, event })
            }
            ClientActionResult::Custom { name, data } if name == "mongodb_insert" => {
                let collection_name = data
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing collection")?;
                let doc_json = data.get("document").context("Missing document")?;

                trace!(
                    "MongoDB client {} inserting into collection: {}",
                    client_id,
                    collection_name
                );

                let collection = db.collection::<Document>(collection_name);

                // Convert JSON to BSON document
                let document = serde_json::from_value::<Document>(doc_json.clone())
                    .context("Failed to convert document to BSON")?;

                // Execute insert
                let result = collection
                    .insert_one(document)
                    .await
                    .context("Failed to insert document")?;

                let _ = status_tx.send(format!(
                    "[MongoDB] Inserted document into {} (id: {:?})",
                    collection_name, result.inserted_id
                ));

                let detail = format!(
                    "insert into '{}' acknowledged (id {:?}); no byte count — the driver owns the socket",
                    collection_name, result.inserted_id
                );
                let event = result_event("insert", None, Some(1));
                Ok(Applied::Ran { detail, event })
            }
            ClientActionResult::Custom { name, data } if name == "mongodb_update" => {
                let collection_name = data
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing collection")?;
                let filter_json = data.get("filter").context("Missing filter")?;
                let update_json = data.get("update").context("Missing update")?;

                trace!(
                    "MongoDB client {} updating collection: {}",
                    client_id,
                    collection_name
                );

                let collection = db.collection::<Document>(collection_name);

                // Convert JSON to BSON documents
                let filter = serde_json::from_value::<Document>(filter_json.clone())
                    .context("Failed to convert filter to BSON")?;
                let update = serde_json::from_value::<Document>(update_json.clone())
                    .context("Failed to convert update to BSON")?;

                // Execute update
                let result = collection
                    .update_many(filter, update)
                    .await
                    .context("Failed to update documents")?;

                let _ = status_tx.send(format!(
                    "[MongoDB] Updated {} documents in {}",
                    result.modified_count, collection_name
                ));

                let detail = format!(
                    "update on '{}' modified {} documents; no byte count — the driver owns the socket",
                    collection_name, result.modified_count
                );
                let event = result_event("update", None, Some(result.modified_count));
                Ok(Applied::Ran { detail, event })
            }
            ClientActionResult::Custom { name, data } if name == "mongodb_delete" => {
                let collection_name = data
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing collection")?;
                let filter_json = data.get("filter").context("Missing filter")?;

                trace!(
                    "MongoDB client {} deleting from collection: {}",
                    client_id,
                    collection_name
                );

                let collection = db.collection::<Document>(collection_name);

                // Convert JSON filter to BSON document
                let filter = serde_json::from_value::<Document>(filter_json.clone())
                    .context("Failed to convert filter to BSON")?;

                // Execute delete
                let result = collection
                    .delete_many(filter)
                    .await
                    .context("Failed to delete documents")?;

                let _ = status_tx.send(format!(
                    "[MongoDB] Deleted {} documents from {}",
                    result.deleted_count, collection_name
                ));

                let detail = format!(
                    "delete on '{}' removed {} documents; no byte count — the driver owns the socket",
                    collection_name, result.deleted_count
                );
                let event = result_event("delete", None, Some(result.deleted_count));
                Ok(Applied::Ran { detail, event })
            }
            ClientActionResult::Custom { name, .. } => {
                trace!(
                    "MongoDB client {} ignoring custom result '{}'",
                    client_id,
                    name
                );
                Ok(Applied::Nothing("custom result not handled by this client"))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more")),
            ClientActionResult::NoAction => Ok(Applied::Nothing("no_action")),
            ClientActionResult::SendData(_) => Ok(Applied::Nothing(
                "send_data is not meaningful for a mongodb driver handle",
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Nothing(
                "multiple results not handled by this client",
            )),
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn execute_llm_action(
        _client_id: ClientId,
        _action: serde_json::Value,
        _protocol: &Arc<MongodbClientProtocol>,
        _db: &Arc<()>,
        _app_state: &Arc<AppState>,
        _llm_client: &OllamaClient,
        _status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        Err(anyhow::anyhow!("MongoDB client feature not enabled"))
    }

    /// Send a prepared result event to the LLM and run whatever it answers with.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    async fn raise_result_event(
        client_id: ClientId,
        event: Event,
        protocol: &Arc<MongodbClientProtocol>,
        db: &Arc<Database>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> Result<()> {
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
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

                // Execute the follow-up actions, and report their results too.
                //
                // These were once logged and dropped outright ("we'd need to pass db_arc
                // here"), then run through `apply_action` — which executes but raises no
                // event, so the chain stopped dead after one hop and a query the model
                // issued in reply to a write confirmation returned its documents to nobody.
                // They now go back through `execute_llm_action`, which reports, bounded by
                // `MAX_FOLLOWUP_DEPTH`. The recursion is boxed because an `async fn` that
                // awaits itself has an infinitely-sized future.
                for action in actions {
                    match Box::pin(Self::execute_llm_action(
                        client_id,
                        action.clone(),
                        protocol,
                        db,
                        app_state,
                        llm_client,
                        status_tx,
                        depth + 1,
                    ))
                    .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            info!("MongoDB client {} follow-up ended the session", client_id);
                            break;
                        }
                        Err(e) => {
                            error!(
                                "MongoDB client {} follow-up action failed: {}",
                                client_id, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("LLM error for MongoDB result: {}", e);
            }
        }

        Ok(())
    }
}

/// Build the `mongodb_result_received` event for one completed operation.
#[cfg(not(target_arch = "wasm32"))]
fn result_event(result_type: &str, documents: Option<Vec<Document>>, count: Option<u64>) -> Event {
    let mut event_data = serde_json::json!({
        "result_type": result_type,
    });

    if let Some(docs) = documents {
        // Convert BSON documents to JSON
        let json_docs: Vec<serde_json::Value> = docs
            .iter()
            .filter_map(|doc| serde_json::to_value(doc).ok())
            .collect();
        event_data["documents"] = serde_json::json!(json_docs);
    }

    if let Some(c) = count {
        event_data["count"] = serde_json::json!(c);
    }

    Event::new(&MONGODB_CLIENT_RESULT_RECEIVED_EVENT, event_data)
}
