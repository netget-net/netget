//! Elasticsearch client implementation
pub mod actions;

pub use actions::ElasticsearchClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::client::elasticsearch::actions::{
    ELASTICSEARCH_CLIENT_CONNECTED_EVENT, ELASTICSEARCH_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::client::http_fetch::{FetchClient, FetchRequest};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::utils::truncate::truncate_for_log;

/// The body of a one-shot follow-up request.
///
/// Two encodings, because `_bulk` is NDJSON and every other endpoint is JSON, and
/// Elasticsearch refuses a bulk request whose content type says `application/json`.
enum RequestBody {
    Json(serde_json::Value),
    Ndjson(String),
}

/// Elasticsearch client that interacts with Elasticsearch clusters
pub struct ElasticsearchClient;

impl ElasticsearchClient {
    /// Connect to an Elasticsearch cluster with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // For Elasticsearch, "connection" is logical (HTTP-based)
        // We'll create a reqwest client configured for Elasticsearch

        info!(
            "Elasticsearch client {} initialized for {}",
            client_id, remote_addr
        );

        // Ensure URL has scheme
        let cluster_url =
            if remote_addr.starts_with("http://") || remote_addr.starts_with("https://") {
                remote_addr.clone()
            } else {
                format!("http://{}", remote_addr)
            };

        // Build HTTP client for Elasticsearch
        #[cfg(not(target_arch = "wasm32"))]
        let _http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client for Elasticsearch")?;
        // The browser transport has no TLS: an `https://` cluster is refused here, with the
        // reason, rather than on the first request.
        crate::client::http_fetch::check_url(&cluster_url)?;

        // `username` / `password` / `default_index` were all declared and none was read:
        // a secured cluster answered 401 with nothing in the parameter list to explain it,
        // and an operation that omitted `index` built the URL `{cluster}//_search`.
        //
        // The credentials are resolved once here into the `Authorization: Basic ...` value
        // every request now carries, rather than re-encoded per call. A username with no
        // password is a valid Basic credential (`user:`), so only the username is required
        // to switch authentication on.
        let (username, password, default_index) = match &startup_params {
            Some(params) => (
                params.get_optional_string("username")?,
                params.get_optional_string("password")?,
                params.get_optional_string("default_index")?,
            ),
            None => (None, None, None),
        };
        let authorization = username.map(|user| {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user, password.unwrap_or_default()).as_bytes());
            format!("Basic {encoded}")
        });

        // Store client configuration in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("es_client".to_string(), serde_json::json!("initialized"));
                client.set_protocol_field(
                    "cluster_url".to_string(),
                    serde_json::json!(cluster_url.clone()),
                );
                if let Some(value) = &authorization {
                    client
                        .set_protocol_field("authorization".to_string(), serde_json::json!(value));
                }
                if let Some(index) = &default_index {
                    client
                        .set_protocol_field("default_index".to_string(), serde_json::json!(index));
                }
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Elasticsearch client {} ready for {}",
            client_id, cluster_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered BEFORE the connected-event LLM call below: a dashboard-created
        // client defaults to a `*` -> manual routing rule, which parks that call until
        // a human answers, and [ send ] has to work for the whole park.
        //
        // The command loop also replaces the 5s "has the client been removed yet"
        // poll this client used to run: `remove_client` drops the handle, the sender
        // goes with it, and `recv()` returns None - promptly, and without a timer.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event to get initial instructions
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(ElasticsearchClientProtocol::new());
            let event = Event::new(
                &ELASTICSEARCH_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "cluster_url": cluster_url.clone(),
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
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute initial actions through the same path injected
                    // commands use, so the two cannot diverge. Spawned (and
                    // registered) rather than awaited: `connect` must return
                    // promptly, and an in-flight request has to die with the client.
                    for action in actions {
                        let result = match protocol.execute_action(action) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("Failed to execute initial action: {}", e);
                                continue;
                            }
                        };
                        let state_clone = app_state.clone();
                        let llm_clone = llm_client.clone();
                        let status_clone = status_tx.clone();
                        let handle = tokio::spawn(async move {
                            let outcome = Self::apply_action(
                                result,
                                client_id,
                                &state_clone,
                                &llm_clone,
                                &status_clone,
                            )
                            .await;
                            debug!(
                                "Elasticsearch client {} connect action: {:?}",
                                client_id, outcome
                            );
                        });
                        app_state.register_client_task(client_id, handle).await;
                    }
                }
                Err(e) => {
                    error!(
                        "Initial LLM call failed for Elasticsearch client {}: {}",
                        client_id, e
                    );
                }
            }
        }

        // Return dummy address (Elasticsearch is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Index a document into Elasticsearch
    pub async fn index_document(
        client_id: ClientId,
        index: String,
        id: Option<String>,
        document: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<u16> {
        let (cluster_url, authorization) = Self::cluster_endpoint(&app_state, client_id).await?;

        let url = if let Some(doc_id) = &id {
            format!("{}/{}/_doc/{}", cluster_url, index, doc_id)
        } else {
            format!("{}/{}/_doc", cluster_url, index)
        };

        info!(
            "Elasticsearch client {} indexing document into {}",
            client_id, index
        );

        let http_client = Self::http_client();
        let response = Self::authorize(http_client.post(&url), &authorization)
            .json(&document)
            .send()
            .await
            .context("Failed to send index request")?;

        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));

        info!(
            "Elasticsearch client {} index response: {}",
            client_id, status_code
        );

        // Raise the response event from its own registered task rather than inline.
        // A dashboard-created client defaults to a `*` -> manual routing rule, so this
        // LLM call can park for minutes waiting for a human; awaiting it here would
        // wedge the command loop and make an injected action that in fact succeeded
        // look to the dashboard like a timeout.
        let notify = Self::spawn_response_notification(
            client_id,
            "index_document".to_string(),
            status_code,
            response_body,
            app_state.clone(),
            llm_client,
            status_tx,
        );
        app_state.register_client_task(client_id, notify).await;

        Ok(status_code)
    }

    /// Search documents in Elasticsearch
    pub async fn search(
        client_id: ClientId,
        index: String,
        query: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<u16> {
        let (cluster_url, authorization) = Self::cluster_endpoint(&app_state, client_id).await?;
        let url = format!("{}/{}/_search", cluster_url, index);

        info!(
            "Elasticsearch client {} searching index {}",
            client_id, index
        );

        let search_body = serde_json::json!({
            "query": query
        });

        let http_client = Self::http_client();
        let response = Self::authorize(http_client.post(&url), &authorization)
            .json(&search_body)
            .send()
            .await
            .context("Failed to send search request")?;

        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));

        info!(
            "Elasticsearch client {} search response: {} hits",
            client_id,
            response_body
                .get("hits")
                .and_then(|h| h.get("total"))
                .and_then(|t| t.get("value"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );

        // Raise the response event from its own registered task rather than inline.
        // A dashboard-created client defaults to a `*` -> manual routing rule, so this
        // LLM call can park for minutes waiting for a human; awaiting it here would
        // wedge the command loop and make an injected action that in fact succeeded
        // look to the dashboard like a timeout.
        let notify = Self::spawn_response_notification(
            client_id,
            "search".to_string(),
            status_code,
            response_body,
            app_state.clone(),
            llm_client,
            status_tx,
        );
        app_state.register_client_task(client_id, notify).await;

        Ok(status_code)
    }

    /// Get a document by ID
    pub async fn get_document(
        client_id: ClientId,
        index: String,
        id: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<u16> {
        let (cluster_url, authorization) = Self::cluster_endpoint(&app_state, client_id).await?;
        let url = format!("{}/{}/_doc/{}", cluster_url, index, id);

        info!(
            "Elasticsearch client {} getting document {} from {}",
            client_id, id, index
        );

        let http_client = Self::http_client();
        let response = Self::authorize(http_client.get(&url), &authorization)
            .send()
            .await
            .context("Failed to send get request")?;

        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));

        // Raise the response event from its own registered task rather than inline.
        // A dashboard-created client defaults to a `*` -> manual routing rule, so this
        // LLM call can park for minutes waiting for a human; awaiting it here would
        // wedge the command loop and make an injected action that in fact succeeded
        // look to the dashboard like a timeout.
        let notify = Self::spawn_response_notification(
            client_id,
            "get_document".to_string(),
            status_code,
            response_body,
            app_state.clone(),
            llm_client,
            status_tx,
        );
        app_state.register_client_task(client_id, notify).await;

        Ok(status_code)
    }

    /// Delete a document by ID
    pub async fn delete_document(
        client_id: ClientId,
        index: String,
        id: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<u16> {
        let (cluster_url, authorization) = Self::cluster_endpoint(&app_state, client_id).await?;
        let url = format!("{}/{}/_doc/{}", cluster_url, index, id);

        info!(
            "Elasticsearch client {} deleting document {} from {}",
            client_id, id, index
        );

        let http_client = Self::http_client();
        let response = Self::authorize(http_client.delete(&url), &authorization)
            .send()
            .await
            .context("Failed to send delete request")?;

        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));

        // Raise the response event from its own registered task rather than inline.
        // A dashboard-created client defaults to a `*` -> manual routing rule, so this
        // LLM call can park for minutes waiting for a human; awaiting it here would
        // wedge the command loop and make an injected action that in fact succeeded
        // look to the dashboard like a timeout.
        let notify = Self::spawn_response_notification(
            client_id,
            "delete_document".to_string(),
            status_code,
            response_body,
            app_state.clone(),
            llm_client,
            status_tx,
        );
        app_state.register_client_task(client_id, notify).await;

        Ok(status_code)
    }

    /// Execute bulk operations
    /// Build the NDJSON body for a `_bulk` request.
    ///
    /// Extracted so the follow-up path can reach it too: `bulk_operation` is advertised to
    /// the model on `elasticsearch_response_received` like every other verb, but the
    /// follow-up dispatch had no arm for it and logged "skipped", so the one verb that
    /// batches work was the one the model could not use in reply to a result.
    fn build_bulk_ndjson(operations: Vec<serde_json::Value>) -> Result<String> {
        let mut bulk_body = String::new();
        for op in operations {
            let action = op
                .get("action")
                .and_then(|a| a.as_str())
                .context("Missing 'action' field in bulk operation")?;
            let index = op
                .get("index")
                .and_then(|i| i.as_str())
                .context("Missing 'index' field in bulk operation")?;
            let id = op.get("id").and_then(|i| i.as_str());

            match action {
                "index" => {
                    let mut meta = serde_json::json!({
                        "index": { "_index": index }
                    });
                    if let Some(doc_id) = id {
                        meta["index"]["_id"] = serde_json::json!(doc_id);
                    }
                    bulk_body.push_str(&serde_json::to_string(&meta)?);
                    bulk_body.push('\n');

                    let document = op
                        .get("document")
                        .context("Missing 'document' field for index action")?;
                    bulk_body.push_str(&serde_json::to_string(&document)?);
                    bulk_body.push('\n');
                }
                "delete" => {
                    let doc_id = id.context("Missing 'id' field for delete action")?;
                    let meta = serde_json::json!({
                        "delete": {
                            "_index": index,
                            "_id": doc_id
                        }
                    });
                    bulk_body.push_str(&serde_json::to_string(&meta)?);
                    bulk_body.push('\n');
                }
                "update" => {
                    let doc_id = id.context("Missing 'id' field for update action")?;
                    let meta = serde_json::json!({
                        "update": {
                            "_index": index,
                            "_id": doc_id
                        }
                    });
                    bulk_body.push_str(&serde_json::to_string(&meta)?);
                    bulk_body.push('\n');

                    let document = op
                        .get("document")
                        .context("Missing 'document' field for update action")?;
                    let update_doc = serde_json::json!({ "doc": document });
                    bulk_body.push_str(&serde_json::to_string(&update_doc)?);
                    bulk_body.push('\n');
                }
                _ => return Err(anyhow::anyhow!("Unknown bulk action: {}", action)),
            }
        }

        Ok(bulk_body)
    }

    pub async fn bulk_operation(
        client_id: ClientId,
        operations: Vec<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<u16> {
        let (cluster_url, authorization) = Self::cluster_endpoint(&app_state, client_id).await?;
        let url = format!("{}/_bulk", cluster_url);

        info!(
            "Elasticsearch client {} executing {} bulk operations",
            client_id,
            operations.len()
        );

        let bulk_body = Self::build_bulk_ndjson(operations)?;

        let http_client = Self::http_client();
        let response = Self::authorize(http_client.post(&url), &authorization)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send()
            .await
            .context("Failed to send bulk request")?;

        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));

        // Raise the response event from its own registered task rather than inline.
        // A dashboard-created client defaults to a `*` -> manual routing rule, so this
        // LLM call can park for minutes waiting for a human; awaiting it here would
        // wedge the command loop and make an injected action that in fact succeeded
        // look to the dashboard like a timeout.
        let notify = Self::spawn_response_notification(
            client_id,
            "bulk_operation".to_string(),
            status_code,
            response_body,
            app_state.clone(),
            llm_client,
            status_tx,
        );
        app_state.register_client_task(client_id, notify).await;

        Ok(status_code)
    }

    /// Apply one executed action against the cluster. Shared by the
    /// connected-event LLM path and by injected commands, so the two cannot
    /// diverge - and so every advertised verb is reachable from both. (The
    /// connect path used to dispatch only `index_document` and `search`, silently
    /// dropping `get_document`, `delete_document` and `bulk_operation`.)
    ///
    /// `reqwest` reports no wire byte count for a request it framed itself, so a
    /// completed operation is `Executed { detail }` naming the operation and the
    /// HTTP status it got back - never `Sent`, which would be a fabricated count.
    async fn apply_action(
        result: ClientActionResult,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> ClientSendOutcome {
        let (name, data) = match result {
            ClientActionResult::Custom { name, data } => (name, data),
            ClientActionResult::Disconnect => return ClientSendOutcome::Disconnected,
            ClientActionResult::WaitForMore => {
                return ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                }
            }
            ClientActionResult::NoAction => {
                return ClientSendOutcome::Executed {
                    detail: "no_action".to_string(),
                }
            }
            ClientActionResult::SendData(_) => {
                return ClientSendOutcome::Executed {
                    detail: "send_data has no meaning for the Elasticsearch client: it speaks \
                             the Elasticsearch REST API over reqwest, not a socket this client \
                             owns"
                        .to_string(),
                }
            }
            ClientActionResult::Multiple(_) => {
                return ClientSendOutcome::Executed {
                    detail: "the Elasticsearch client's own verbs never produce Multiple; \
                             nothing was applied"
                        .to_string(),
                }
            }
        };

        // An omitted `index` falls back to the `default_index` startup parameter. It used
        // to become the empty string, which built `{cluster}//_search` and was refused by
        // the cluster with nothing pointing at the cause.
        //
        // `bulk_operation` is exempt: it POSTs to the cluster-wide `/_bulk` and every
        // operation in its array names its own index, so it never reads this value.
        let index = if name == "bulk_operation" {
            String::new()
        } else {
            match Self::resolve_index(
                app_state,
                client_id,
                data.get("index").and_then(|v| v.as_str()).unwrap_or(""),
            )
            .await
            {
                Ok(index) => index,
                Err(e) => {
                    return ClientSendOutcome::Executed {
                        detail: format!("{name} failed: {e}"),
                    }
                }
            }
        };
        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let outcome = match name.as_str() {
            "index_document" => {
                let document = data
                    .get("document")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                Self::index_document(
                    client_id,
                    index.clone(),
                    id,
                    document,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
            }
            "search" => {
                let query = data.get("query").cloned().unwrap_or(serde_json::json!({}));
                Self::search(
                    client_id,
                    index.clone(),
                    query,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
            }
            "get_document" => match id {
                Some(id) => {
                    Self::get_document(
                        client_id,
                        index.clone(),
                        id,
                        app_state.clone(),
                        llm_client.clone(),
                        status_tx.clone(),
                    )
                    .await
                }
                None => Err(anyhow::anyhow!("get_document requires an 'id'")),
            },
            "delete_document" => match id {
                Some(id) => {
                    Self::delete_document(
                        client_id,
                        index.clone(),
                        id,
                        app_state.clone(),
                        llm_client.clone(),
                        status_tx.clone(),
                    )
                    .await
                }
                None => Err(anyhow::anyhow!("delete_document requires an 'id'")),
            },
            "bulk_operation" => {
                let operations = data
                    .get("operations")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                Self::bulk_operation(
                    client_id,
                    operations,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
            }
            other => Err(anyhow::anyhow!(
                "Unknown Elasticsearch operation: {}",
                other
            )),
        };

        match outcome {
            Ok(status_code) => ClientSendOutcome::Executed {
                detail: format!("{} completed: HTTP {}", name, status_code),
            },
            Err(e) => {
                Log::to(&status_tx).error(format!(
                    "Elasticsearch client {} operation {} failed: {}",
                    client_id, name, e
                ));
                ClientSendOutcome::Executed {
                    detail: format!("{} failed: {}", name, truncate_for_log(&e.to_string(), 200)),
                }
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed)
    /// or an injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// every Elasticsearch verb yields `ClientActionResult::Custom` and there is no
    /// write half to put bytes on. Actions therefore go through
    /// [`Self::apply_action`] - the same function the LLM path uses - and the
    /// outcome is logged and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = ElasticsearchClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => ClientSendOutcome::Rejected {
                    error: e.to_string(),
                },
                Ok(result) => {
                    Self::apply_action(result, client_id, &app_state, &llm_client, &status_tx).await
                }
            };
            let disconnected = matches!(outcome, ClientSendOutcome::Disconnected);

            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![serde_json::to_value(&outcome).unwrap_or(serde_json::Value::Null)],
                )
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, Ok(outcome));

            if disconnected {
                info!(
                    "Elasticsearch client {} disconnecting on injected action",
                    client_id
                );
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }
        }

        info!("Elasticsearch client {} command loop stopped", client_id);
        // Never leave the dashboard offering [ send ] into a client that is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Cluster URL plus the `Authorization` value resolved from the `username` / `password`
    /// startup parameters, if any. Every request goes through here so authentication cannot
    /// be applied to some operations and forgotten on others.
    async fn cluster_endpoint(
        app_state: &Arc<AppState>,
        client_id: ClientId,
    ) -> Result<(String, Option<String>)> {
        let (url, authorization) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("cluster_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("authorization")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                )
            })
            .await
            .unwrap_or((None, None));
        Ok((url.context("No cluster URL found")?, authorization))
    }

    /// The index an operation should act on: the one it named, or the `default_index`
    /// startup parameter when it named none. Fails rather than building `{cluster}//_search`
    /// out of an empty string, which is what an omitted index used to produce.
    async fn resolve_index(
        app_state: &Arc<AppState>,
        client_id: ClientId,
        requested: &str,
    ) -> Result<String> {
        if !requested.is_empty() {
            return Ok(requested.to_string());
        }
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("default_index")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context(
                "no index was given and no `default_index` startup parameter is set for this \
                 client",
            )
    }

    /// The HTTP client for one request: a fresh `reqwest::Client` natively, the shared hyper
    /// transport over the virtual loopback in the browser build
    /// ([`crate::client::http_fetch`]), there bounded at 30 seconds an exchange.
    fn http_client() -> FetchClient {
        #[cfg(not(target_arch = "wasm32"))]
        let client = FetchClient::from_reqwest(reqwest::Client::new());
        #[cfg(target_arch = "wasm32")]
        let client = FetchClient::transport(std::time::Duration::from_secs(30));
        client
    }

    /// Apply the cluster's `Authorization` header, when one was configured.
    fn authorize(request: FetchRequest, authorization: &Option<String>) -> FetchRequest {
        match authorization {
            Some(value) => request.header("Authorization", value),
            None => request,
        }
    }

    /// Raise `elasticsearch_response_received` off the caller's task. Never awaited by a
    /// caller that holds the command loop: an event handler may park this call for a human
    /// answer.
    /// Issue one Elasticsearch request and return `(status, body)`. Raises no event and
    /// calls no LLM **itself**.
    ///
    /// Follow-up actions the model returns for `elasticsearch_response_received` run through
    /// here rather than through `search`/`index_document`/..., because each of those ends in
    /// `spawn_response_notification`, which calls `call_llm_with_response`, which is where
    /// the follow-ups are executed — and rustc rejects the resulting async type.
    ///
    /// The caller reports the result itself, bounded by [`Self::MAX_FOLLOWUP_DEPTH`]. It used
    /// not to, and the comment here claimed that raising nothing "bounds the chain": it did,
    /// at one step, which meant a search issued in reply to an index confirmation returned
    /// its hits to nobody. The bound is the depth counter, not the silence.
    async fn run_request_once(
        client_id: ClientId,
        method: hyper::Method,
        path: &str,
        body: Option<RequestBody>,
        app_state: &Arc<AppState>,
    ) -> Result<(u16, serde_json::Value)> {
        let (cluster_url, authorization) = Self::cluster_endpoint(app_state, client_id).await?;
        let url = format!(
            "{}/{}",
            cluster_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let http_client = Self::http_client();
        let mut req = Self::authorize(http_client.request(method, &url), &authorization);
        match body {
            Some(RequestBody::Json(b)) => req = req.json(&b),
            // `_bulk` is NDJSON and Elasticsearch rejects it outright when it arrives as
            // `application/json`, so the content type has to travel with the body.
            Some(RequestBody::Ndjson(b)) => {
                req = req.header("Content-Type", "application/x-ndjson").body(b)
            }
            None => {}
        }
        let response = req.send().await.context("Elasticsearch request failed")?;
        let status_code = response.status().as_u16();
        let response_body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "Failed to parse response"}));
        Ok((status_code, response_body))
    }

    fn spawn_response_notification(
        client_id: ClientId,
        operation: String,
        status_code: u16,
        response: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = Self::call_llm_with_response(
                client_id,
                operation,
                status_code,
                response,
                app_state,
                llm_client,
                status_tx,
                0,
            )
            .await
            {
                error!(
                    "Elasticsearch client {} response notification failed: {}",
                    client_id, e
                );
            }
        })
    }

    /// How many follow-ups deep this client will keep reporting results to the model.
    /// Each report can produce another request, which produces another report; without a
    /// bound a model that answers `search` with `search` would loop on the LLM forever.
    const MAX_FOLLOWUP_DEPTH: u8 = 4;

    /// Helper: Call LLM with response
    #[allow(clippy::too_many_arguments)]
    async fn call_llm_with_response(
        client_id: ClientId,
        operation: String,
        status_code: u16,
        response: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> Result<()> {
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(ElasticsearchClientProtocol::new());
            let event = Event::new(
                &ELASTICSEARCH_CLIENT_RESPONSE_RECEIVED_EVENT,
                serde_json::json!({
                    "operation": operation,
                    "status_code": status_code,
                    "response": response,
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
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute what the model asked for. These were discarded behind a note
                    // saying it was "to avoid recursion" and that "responses don't trigger
                    // new operations" -- the recursion was real, the claim was not. Reading
                    // search hits and then fetching one of the documents, or refining the
                    // query, is exactly what a search client is for, and none of it worked.
                    //
                    // `run_request_once` issues the request without raising an event itself;
                    // this loop reports the outcome, bounded by MAX_FOLLOWUP_DEPTH. Every
                    // verb the model is offered on this event has an arm here — an advertised
                    // verb with no arm is the same defect one level down.
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in actions {
                        let Ok(ClientActionResult::Custom { name, data }) =
                            protocol.execute_action(action.clone())
                        else {
                            continue;
                        };
                        // `default_index` before `_all`: an operator who named a default
                        // index meant that one, and `_all` is a much wider blast radius
                        // than either the model or the operator asked for.
                        let index = match data.get("index").and_then(|v| v.as_str()) {
                            Some(named) if !named.is_empty() => named.to_string(),
                            _ => Self::resolve_index(&app_state, client_id, "")
                                .await
                                .unwrap_or_else(|_| "_all".to_string()),
                        };
                        let index = index.as_str();
                        let plan = match name.as_str() {
                            "search" => Some((
                                hyper::Method::POST,
                                format!("{index}/_search"),
                                Some(RequestBody::Json(serde_json::json!({
                                    "query": data.get("query").cloned()
                                        .unwrap_or(serde_json::json!({"match_all": {}}))
                                }))),
                            )),
                            "get_document" => data
                                .get("id")
                                .and_then(|v| v.as_str())
                                .map(|id| (hyper::Method::GET, format!("{index}/_doc/{id}"), None)),
                            "delete_document" => {
                                data.get("id").and_then(|v| v.as_str()).map(|id| {
                                    (hyper::Method::DELETE, format!("{index}/_doc/{id}"), None)
                                })
                            }
                            "index_document" => Some((
                                hyper::Method::POST,
                                format!("{index}/_doc"),
                                data.get("document").cloned().map(RequestBody::Json),
                            )),
                            // `_bulk` is cluster-wide and every entry names its own index,
                            // so it deliberately ignores `index` — the same exemption
                            // `apply_action` makes. It used to fall through to the arm below
                            // and be logged as skipped, which left the one verb that batches
                            // work unusable in reply to a result.
                            "bulk_operation" => {
                                let ops = data
                                    .get("operations")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default();
                                match Self::build_bulk_ndjson(ops) {
                                    Ok(ndjson) => Some((
                                        hyper::Method::POST,
                                        "_bulk".to_string(),
                                        Some(RequestBody::Ndjson(ndjson)),
                                    )),
                                    Err(e) => {
                                        error!(
                                            "Elasticsearch client {} follow-up bulk_operation \
                                             is malformed: {}",
                                            client_id, e
                                        );
                                        None
                                    }
                                }
                            }
                            other => {
                                info!(
                                    "Elasticsearch client {} follow-up '{}' has no wire \
                                     effect; skipped",
                                    client_id, other
                                );
                                None
                            }
                        };
                        let Some((method, path, body)) = plan else {
                            continue;
                        };
                        match Self::run_request_once(client_id, method, &path, body, &app_state)
                            .await
                        {
                            Ok((code, body)) => {
                                info!(
                                    "Elasticsearch client {} follow-up {} -> HTTP {}",
                                    client_id, name, code
                                );
                                // Tell the model what the follow-up returned. Without this
                                // the chain was exactly one step deep: a `search` issued in
                                // response to an index confirmation ran, and its hits went
                                // nowhere -- so the model could never read the results of a
                                // search it had asked for, which is what a search client is
                                // for. Boxed because the cycle is real, bounded because it
                                // would otherwise be endless.
                                if depth + 1 < Self::MAX_FOLLOWUP_DEPTH {
                                    if let Err(e) = Box::pin(Self::call_llm_with_response(
                                        client_id,
                                        name.clone(),
                                        code,
                                        body,
                                        app_state.clone(),
                                        llm_client.clone(),
                                        status_tx.clone(),
                                        depth + 1,
                                    ))
                                    .await
                                    {
                                        error!(
                                            "Elasticsearch client {} follow-up notification \
                                             failed: {}",
                                            client_id, e
                                        );
                                    }
                                } else {
                                    warn!(
                                        "Elasticsearch client {} reached the follow-up depth \
                                         limit ({}); not reporting {} to the model",
                                        client_id,
                                        Self::MAX_FOLLOWUP_DEPTH,
                                        name
                                    );
                                }
                            }
                            Err(e) => error!(
                                "Elasticsearch client {} follow-up {} failed: {}",
                                client_id, name, e
                            ),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for Elasticsearch client {}: {}", client_id, e);
                }
            }
        }

        Ok(())
    }
}
