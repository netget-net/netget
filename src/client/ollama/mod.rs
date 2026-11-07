//! Ollama client implementation
pub mod actions;

pub use actions::OllamaClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::http_fetch::{FetchClient, FetchResponse};
use crate::client::llm_budget::call_llm_for_client;
use crate::client::ollama::actions::{
    OLLAMA_CLIENT_CONNECTED_EVENT, OLLAMA_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Ollama client that connects to the Ollama API
pub struct OllamaClientImpl;

impl OllamaClientImpl {
    /// Connect to Ollama API with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        _startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // The endpoint is later interpolated into `{endpoint}/api/generate` and handed to
        // reqwest, which requires an absolute URL. A bare `127.0.0.1:11434` -- the form
        // every other client protocol accepts -- failed every request with "builder error"
        // (relative URL without a base). An explicit scheme is left as given.
        let remote_addr = if remote_addr.contains("://") {
            remote_addr
        } else {
            format!("http://{remote_addr}")
        };
        // In the browser build the transport has no TLS: an `https://` endpoint is refused here,
        // with the reason, rather than on the first call.
        crate::client::http_fetch::check_url(&remote_addr)?;

        info!(
            "Ollama client {} initializing with API endpoint: {}",
            client_id, remote_addr
        );

        // Store only endpoint in protocol_data (no model storage - LLM must provide model on every call)
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("api_endpoint".to_string(), serde_json::json!(remote_addr));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "Ollama client {} ready (endpoint: {})",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered - and already being drained by its own task - BEFORE the
        // connected-event LLM call, which a manual `*` rule can park for minutes: the
        // operator must be able to reach the client while it waits. This task also
        // replaces the old 5s "is the client gone yet" poll: the channel closes when the
        // client is removed, which ends the loop immediately.
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

        // Call LLM with ollama_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &OLLAMA_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "api_endpoint": remote_addr.clone(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(),
                Some(&event),
                &crate::client::ollama::actions::OllamaClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    info!("Ollama client ready after connect event");
                    let protocol = crate::client::ollama::actions::OllamaClientProtocol::new();
                    for action in result.actions {
                        match protocol.execute_action(action.clone()) {
                            Ok(ClientActionResult::Disconnect) => {
                                info!(
                                    "Ollama client {} disconnecting on connect-event action",
                                    client_id
                                );
                                app_state
                                    .update_client_status(client_id, ClientStatus::Disconnected)
                                    .await;
                                // Every exit path drops the handle so the dashboard stops
                                // offering [ send ] into a dead client.
                                app_state.remove_client_handle(client_id).await;
                                let _ = status_tx.send("__UPDATE_UI__".to_string());
                                return Ok("0.0.0.0:0".parse().unwrap());
                            }
                            Ok(result) => {
                                // Dispatch::Spawn: a 30s API call must not hold up
                                // `connect()`. The injected path awaits the same
                                // `apply_action` so its ClientSendOutcome is truthful.
                                if let Err(e) = Self::apply_action(
                                    result,
                                    Dispatch::Spawn,
                                    client_id,
                                    &app_state,
                                    &llm_client,
                                    &status_tx,
                                )
                                .await
                                {
                                    error!("Ollama request failed: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Ollama action execution error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on ollama_connected event: {}", e);
                }
            }
        }

        // Return a dummy local address (Ollama is a remote API, not a local connection)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: it writes
    /// `SendData` to a socket, and every Ollama verb yields `ClientActionResult::Custom`
    /// that has to go out over the HTTP API. So the action is executed through the
    /// protocol's own `execute_action` and applied by [`Self::apply_action`] - the same
    /// function the connected-event path uses - and the outcome is recorded and replied
    /// exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::ollama::actions::OllamaClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Dispatch::Await: the network exchange is awaited, so the reported
                // outcome describes a request that has actually completed. The
                // ollama_response_received event is delivered from its own registered
                // task, so a manual handler parked for a human's think time cannot wedge
                // this loop or time out the dashboard's [ send ].
                Ok(result) => Self::apply_action(
                    result,
                    Dispatch::Await,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
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
                    "Ollama client {} injected action failed: {}",
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

        info!("Ollama client {} command loop stopped", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Apply one already-executed action result. The single place an Ollama API call is
    /// dispatched from, so an injected action behaves exactly like an LLM-produced one.
    async fn apply_action(
        result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "send_generate_request" => {
                    let prompt = data
                        .get("prompt")
                        .and_then(|v| v.as_str())
                        .context("Missing 'prompt' in send_generate_request")?
                        .to_string();
                    let model = data
                        .get("model")
                        .and_then(|v| v.as_str())
                        .context("Missing 'model' in send_generate_request")?
                        .to_string();
                    match dispatch {
                        Dispatch::Spawn => {
                            Self::spawn_request(
                                client_id,
                                app_state,
                                Self::make_generate_request(
                                    client_id,
                                    prompt,
                                    model.clone(),
                                    app_state.clone(),
                                    llm_client.clone(),
                                    status_tx.clone(),
                                ),
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "send_generate_request dispatched (model={model})"
                            )))
                        }
                        Dispatch::Await => {
                            let exchange = Self::perform_generate_request(
                                client_id,
                                prompt,
                                model.clone(),
                                app_state,
                                status_tx,
                            )
                            .await?;
                            Self::spawn_notify(
                                client_id,
                                exchange.event_data,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "send_generate_request completed (model={model}, {})",
                                exchange.summary
                            )))
                        }
                    }
                }
                "send_chat_request" => {
                    let messages = data
                        .get("messages")
                        .cloned()
                        .context("Missing 'messages' in send_chat_request")?;
                    let model = data
                        .get("model")
                        .and_then(|v| v.as_str())
                        .context("Missing 'model' in send_chat_request")?
                        .to_string();
                    match dispatch {
                        Dispatch::Spawn => {
                            Self::spawn_request(
                                client_id,
                                app_state,
                                Self::make_chat_request(
                                    client_id,
                                    messages,
                                    model.clone(),
                                    app_state.clone(),
                                    llm_client.clone(),
                                    status_tx.clone(),
                                ),
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "send_chat_request dispatched (model={model})"
                            )))
                        }
                        Dispatch::Await => {
                            let exchange = Self::perform_chat_request(
                                client_id,
                                messages,
                                model.clone(),
                                app_state,
                                status_tx,
                            )
                            .await?;
                            Self::spawn_notify(
                                client_id,
                                exchange.event_data,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "send_chat_request completed (model={model}, {})",
                                exchange.summary
                            )))
                        }
                    }
                }
                "generate_embeddings" => {
                    let prompt = data
                        .get("prompt")
                        .and_then(|v| v.as_str())
                        .context("Missing 'prompt' in generate_embeddings")?
                        .to_string();
                    let model = data
                        .get("model")
                        .and_then(|v| v.as_str())
                        .context("Missing 'model' in generate_embeddings")?
                        .to_string();
                    match dispatch {
                        Dispatch::Spawn => {
                            Self::spawn_request(
                                client_id,
                                app_state,
                                Self::make_embeddings_request(
                                    client_id,
                                    prompt,
                                    model.clone(),
                                    app_state.clone(),
                                    llm_client.clone(),
                                    status_tx.clone(),
                                ),
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "generate_embeddings dispatched (model={model})"
                            )))
                        }
                        Dispatch::Await => {
                            let exchange = Self::perform_embeddings_request(
                                client_id,
                                prompt,
                                model.clone(),
                                app_state,
                                status_tx,
                            )
                            .await?;
                            Self::spawn_notify(
                                client_id,
                                exchange.event_data,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await;
                            Ok(Applied::Executed(format!(
                                "generate_embeddings completed (model={model}, {})",
                                exchange.summary
                            )))
                        }
                    }
                }
                "list_models" => match dispatch {
                    Dispatch::Spawn => {
                        Self::spawn_request(
                            client_id,
                            app_state,
                            Self::list_models(
                                client_id,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed("list_models dispatched".to_string()))
                    }
                    Dispatch::Await => {
                        let exchange =
                            Self::perform_list_models(client_id, app_state, status_tx).await?;
                        Self::spawn_notify(
                            client_id,
                            exchange.event_data,
                            app_state,
                            llm_client,
                            status_tx,
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "list_models completed ({})",
                            exchange.summary
                        )))
                    }
                },
                other => Ok(Applied::Executed(format!(
                    "custom result '{other}' has no Ollama executor"
                ))),
            },
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            ClientActionResult::SendData(_) => Ok(Applied::Executed(
                "raw send_data has no meaning for the Ollama HTTP client".to_string(),
            )),
            // OllamaClientProtocol::execute_action never produces Multiple.
            ClientActionResult::Multiple(_) => Ok(Applied::Executed(
                "multiple results are not produced by the Ollama client".to_string(),
            )),
        }
    }

    /// Make a generate request and hand the result to the LLM.
    pub async fn make_generate_request(
        client_id: ClientId,
        prompt: String,
        model: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange =
            Self::perform_generate_request(client_id, prompt, model, &app_state, &status_tx)
                .await?;
        Self::notify_response(
            client_id,
            exchange.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Make a chat request and hand the result to the LLM.
    pub async fn make_chat_request(
        client_id: ClientId,
        messages: serde_json::Value,
        model: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange =
            Self::perform_chat_request(client_id, messages, model, &app_state, &status_tx).await?;
        Self::notify_response(
            client_id,
            exchange.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// List available models and hand the result to the LLM.
    pub async fn list_models(
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_list_models(client_id, &app_state, &status_tx).await?;
        Self::notify_response(
            client_id,
            exchange.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Generate embeddings and hand the result to the LLM.
    pub async fn make_embeddings_request(
        client_id: ClientId,
        prompt: String,
        model: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange =
            Self::perform_embeddings_request(client_id, prompt, model, &app_state, &status_tx)
                .await?;
        Self::notify_response(
            client_id,
            exchange.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Deliver one exchange's `ollama_response_received` event from **its own registered
    /// task** and return immediately.
    ///
    /// This is the point of the perform/notify split. The injected-command loop already
    /// holds the truthful network result and must reply to the operator before that
    /// event's handler runs: a dashboard-created client defaults to a `*` -> manual rule,
    /// so the handler can park for a human's think time (300s by default), far longer
    /// than the composer's 30s send timeout.
    async fn spawn_notify(
        client_id: ClientId,
        event_data: serde_json::Value,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let state_clone = app_state.clone();
        let llm_clone = llm_client.clone();
        let status_clone = status_tx.clone();
        let notify_handle = tokio::spawn(async move {
            OllamaClientImpl::notify_response(
                client_id,
                event_data,
                state_clone,
                llm_clone,
                status_clone,
            )
            .await;
        });
        // Registered so the notification - and the LLM call it makes - is aborted when
        // the client is stopped.
        app_state
            .register_client_task(client_id, notify_handle)
            .await;
    }

    /// Spawn a whole request+notify future as a registered client task. Used by the
    /// connected-event path, which runs inline in `connect()`.
    async fn spawn_request<F>(client_id: ClientId, app_state: &Arc<AppState>, future: F)
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handle = tokio::spawn(async move {
            if let Err(e) = future.await {
                error!("Ollama request failed: {}", e);
            }
        });
        app_state.register_client_task(client_id, handle).await;
    }

    /// Fire one `ollama_response_received` event at the LLM and apply any memory update.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded (`actions: _`), so answering ollama_response_received did nothing at all --
    /// the whole point of raising the event.
    ///
    /// Everything goes through the `perform_*` round-trips, which raise no event. That
    /// bounds the loop -- a follow-up cannot trigger another response event and drive the
    /// model in circles -- and is the only shape that compiles, since routing back through
    /// the notifying entry points makes notify -> perform -> notify a self-referential
    /// async chain rustc cannot prove `Send`.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::ollama::actions::OllamaClientProtocol::new();
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            let outcome: Result<()> = match name.as_str() {
                "send_generate_request" => Self::perform_generate_request(
                    client_id,
                    data["prompt"].as_str().unwrap_or_default().to_string(),
                    data["model"].as_str().unwrap_or_default().to_string(),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                "send_chat_request" => Self::perform_chat_request(
                    client_id,
                    data["messages"].clone(),
                    data["model"].as_str().unwrap_or_default().to_string(),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                "list_models" => Self::perform_list_models(client_id, app_state, status_tx)
                    .await
                    .map(|_| ()),
                // `generate_embeddings` was missing from this list while being advertised,
                // executable and wired into `apply_action` — so the model could ask for an
                // embedding on connect but never in reply to a response, where it fell into
                // the `other` arm below and was logged away. `perform_embeddings_request`
                // raises no event, so it respects the same bound as its three neighbours.
                "generate_embeddings" => Self::perform_embeddings_request(
                    client_id,
                    data["prompt"].as_str().unwrap_or_default().to_string(),
                    data["model"].as_str().unwrap_or_default().to_string(),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                other => {
                    info!(
                        "Ollama client {} follow-up '{}' has no non-notifying path; skipped",
                        client_id, other
                    );
                    Ok(())
                }
            };
            if let Err(e) = outcome {
                error!("Ollama client {} follow-up action failed: {}", client_id, e);
            }
        }
    }

    async fn notify_response(
        client_id: ClientId,
        event_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let protocol = Arc::new(crate::client::ollama::actions::OllamaClientProtocol::new());
        let event = Event::new(&OLLAMA_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);
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
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                Self::run_follow_ups(client_id, actions, &app_state, &status_tx).await;
            }
            Err(e) => {
                error!("LLM error for Ollama client {}: {}", client_id, e);
            }
        }
    }

    /// Perform the generate round-trip only. No LLM involvement, so a caller can await
    /// this and know exactly what Ollama answered.
    pub async fn perform_generate_request(
        client_id: ClientId,
        prompt: String,
        model: String,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<OllamaExchange> {
        // Get API endpoint from client (model must be provided by LLM on every call)
        let api_endpoint = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("api_endpoint")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No API endpoint found")?;

        info!(
            "Ollama client {} making generate request with model: {}",
            client_id, model
        );

        let client = Self::http_client(&api_endpoint).await?;
        let url = format!("{}/api/generate", api_endpoint);

        let request_body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "stream": false
        });

        // Make request
        match client.post(&url).json(&request_body).send().await {
            Ok(response) => {
                let status_code = response.status();
                let response_json = Self::json_bounded(response).await?;

                if status_code.is_success() {
                    let response_text = response_json
                        .get("response")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    info!("Ollama client {} received generate response", client_id);

                    // Built here, delivered by `notify_response` - inline for the
                    // LLM path, from its own task for the injected-command path.
                    Ok(OllamaExchange {
                        summary: format!(
                            "{} chars of generated text",
                            response_text.chars().count()
                        ),
                        event_data: serde_json::json!({
                            "response_type": "generate",
                            "content": response_text,
                            "model": model,
                        }),
                    })
                } else {
                    let error_msg = response_json
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();

                    Err(anyhow::anyhow!("Ollama API error: {}", error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("Ollama client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Perform the chat round-trip only. No LLM involvement.
    pub async fn perform_chat_request(
        client_id: ClientId,
        messages: serde_json::Value,
        model: String,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<OllamaExchange> {
        // Get API endpoint from client (model must be provided by LLM on every call)
        let api_endpoint = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("api_endpoint")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No API endpoint found")?;

        info!(
            "Ollama client {} making chat request with model: {}",
            client_id, model
        );

        let client = Self::http_client(&api_endpoint).await?;
        let url = format!("{}/api/chat", api_endpoint);

        let request_body = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": false
        });

        // Make request
        match client.post(&url).json(&request_body).send().await {
            Ok(response) => {
                let status_code = response.status();
                let response_json = Self::json_bounded(response).await?;

                if status_code.is_success() {
                    let message_content = response_json
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    info!("Ollama client {} received chat response", client_id);

                    // Built here, delivered by `notify_response` - inline for the
                    // LLM path, from its own task for the injected-command path.
                    Ok(OllamaExchange {
                        summary: format!(
                            "{} chars of message content",
                            message_content.chars().count()
                        ),
                        event_data: serde_json::json!({
                            "response_type": "chat",
                            "content": message_content,
                            "model": model,
                        }),
                    })
                } else {
                    let error_msg = response_json
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();

                    Err(anyhow::anyhow!("Ollama API error: {}", error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("Ollama client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Perform the model listing only. No LLM involvement.
    pub async fn perform_list_models(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<OllamaExchange> {
        // Get API configuration from client
        let api_endpoint = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("api_endpoint")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No API endpoint found")?;

        info!("Ollama client {} listing models", client_id);

        let client = Self::http_client(&api_endpoint).await?;
        let url = format!("{}/api/tags", api_endpoint);

        // Make request
        match client.get(&url).send().await {
            Ok(response) => {
                let status_code = response.status();
                let response_json = Self::json_bounded(response).await?;

                if status_code.is_success() {
                    let models = response_json
                        .get("models")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    info!("Ollama client {} found {} models", client_id, models.len());

                    // Built here, delivered by `notify_response` - inline for the
                    // LLM path, from its own task for the injected-command path.
                    Ok(OllamaExchange {
                        summary: format!("{} models", models.len()),
                        event_data: serde_json::json!({
                            "response_type": "models",
                            "content": format!("Found {} models", models.len()),
                            "models": models,
                        }),
                    })
                } else {
                    let error_msg = response_json
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();

                    Err(anyhow::anyhow!("Ollama API error: {}", error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("Ollama client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Perform the embeddings round-trip only. No LLM involvement.
    pub async fn perform_embeddings_request(
        client_id: ClientId,
        prompt: String,
        model: String,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<OllamaExchange> {
        // Get API endpoint from client (model must be provided by LLM on every call)
        let api_endpoint = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("api_endpoint")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No API endpoint found")?;

        info!(
            "Ollama client {} making embeddings request with model: {}",
            client_id, model
        );

        let client = Self::http_client(&api_endpoint).await?;
        let url = format!("{}/api/embeddings", api_endpoint);

        let request_body = serde_json::json!({
            "model": model,
            "prompt": prompt
        });

        // Make request
        match client.post(&url).json(&request_body).send().await {
            Ok(response) => {
                let status_code = response.status();
                let response_json = Self::json_bounded(response).await?;

                if status_code.is_success() {
                    let embedding = response_json
                        .get("embedding")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.len())
                        .unwrap_or(0);

                    info!(
                        "Ollama client {} received embeddings ({} dimensions)",
                        client_id, embedding
                    );

                    // Built here, delivered by `notify_response` - inline for the
                    // LLM path, from its own task for the injected-command path.
                    Ok(OllamaExchange {
                        summary: format!("{} dimensions", embedding),
                        event_data: serde_json::json!({
                            "response_type": "embeddings",
                            "content": format!("Generated embeddings with {} dimensions", embedding),
                            "model": model,
                            "dimensions": embedding,
                        }),
                    })
                } else {
                    let error_msg = response_json
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();

                    Err(anyhow::anyhow!("Ollama API error: {}", error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "Ollama client {} embeddings request failed: {}",
                    client_id, e
                ));
                Err(e)
            }
        }
    }
}

/// How long one Ollama API call may take, end to end.
///
/// Generous, because generation legitimately takes minutes on a large model — but finite,
/// because `reqwest::Client::new()` has no timeout at all and the injected-command loop
/// awaits each request in turn. One endpoint that accepts the connection and never answers
/// used to wedge that loop for the life of the process, so the dashboard's `[ send ]` for
/// this client never worked again.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How much of a response body is read before it is refused.
///
/// The endpoint is remote and its reply is entirely under its control: `response.json()`
/// buffers the whole body with no limit, and `/api/generate` with `stream: true` is an
/// arbitrarily long NDJSON stream by design. A reply larger than this is not a reply netget
/// can do anything with — the content ends up in an event and then in an LLM prompt.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

impl OllamaClientImpl {
    /// The HTTP client for `endpoint`, built once per endpoint and reused.
    ///
    /// Two problems this fixes, both of which used to be paid on **every** request because
    /// each `perform_*` called `reqwest::Client::new()`:
    ///
    /// 1. `Client::builder().build()` sets up the rustls stack and loads the platform root
    ///    store, which on macOS reads the keychain through Security.framework — synchronously
    ///    and serialised across processes. On the async runtime that parks a tokio worker.
    ///    It is built on `spawn_blocking` and kept, so later requests also reuse the
    ///    connection pool rather than rebuilding a TLS stack.
    /// 2. `reqwest` hands the URL host to its resolver unconditionally, and `GaiResolver`
    ///    does not special-case a dotted quad — so `http://127.0.0.1:11434`, which is where
    ///    this client points more often than anywhere else, performed a real
    ///    `getaddrinfo("127.0.0.1")`. Measured at 8.25 s with ~100 processes asking at once.
    ///    `client_for_endpoint_with_timeout` applies the override when, and only when, the
    ///    host parses as an `IpAddr`; a hostname is left to the resolver.
    ///
    /// Keyed by endpoint because the resolver override is per-host. The cache is a plain
    /// `std::sync::Mutex` holding nothing across an await.
    #[cfg(not(target_arch = "wasm32"))]
    async fn reqwest_client(endpoint: &str) -> Result<reqwest::Client> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};

        static CLIENTS: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
        let cache = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));

        if let Some(client) = cache.lock().ok().and_then(|map| map.get(endpoint).cloned()) {
            return Ok(client);
        }

        let owned = endpoint.to_string();
        let built = tokio::task::spawn_blocking(move || {
            crate::llm::ollama_client::client_for_endpoint_with_timeout(&owned, REQUEST_TIMEOUT)
        })
        .await
        .context("Ollama HTTP client build task panicked")?;

        if let Ok(mut map) = cache.lock() {
            return Ok(map.entry(endpoint.to_string()).or_insert(built).clone());
        }
        Ok(built)
    }

    /// The HTTP client for `endpoint`: the cached reqwest client natively
    /// ([`Self::reqwest_client`]); in the browser build the shared hyper transport over the
    /// page's virtual loopback ([`crate::client::http_fetch`]), bounded by the same
    /// [`REQUEST_TIMEOUT`] and [`MAX_RESPONSE_BYTES`].
    async fn http_client(endpoint: &str) -> Result<FetchClient> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = FetchClient::from_reqwest(Self::reqwest_client(endpoint).await?);
        #[cfg(target_arch = "wasm32")]
        let client = {
            let _ = endpoint;
            FetchClient::transport(REQUEST_TIMEOUT).with_max_body(MAX_RESPONSE_BYTES)
        };
        Ok(client)
    }

    /// Read a JSON response body, refusing anything past [`MAX_RESPONSE_BYTES`].
    ///
    /// `response.json()` buffers the whole body first; this refuses as soon as the cap is
    /// passed, so an endpoint answering with an endless stream costs at most the cap.
    async fn json_bounded(mut response: FetchResponse) -> Result<serde_json::Value> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(anyhow::anyhow!(
                    "Ollama endpoint returned more than {} bytes; refusing to buffer the rest",
                    MAX_RESPONSE_BYTES
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).context("Ollama endpoint returned a body that is not JSON")
    }
}

/// How an Ollama API call is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the request and return immediately. Used by the connected-event handler,
    /// which runs inline in `connect()` and must not block client creation.
    Spawn,
    /// Await the API round-trip so the caller can report what actually happened. Used by
    /// the injected-command loop. The response event is still delivered to the LLM, from
    /// its own registered task, so a parked manual handler cannot wedge the command loop.
    Await,
}

/// One completed Ollama exchange.
///
/// Split out of the `make_*` functions so the injected-command loop can await the network
/// round-trip - and report a truthful outcome - without also awaiting the LLM call the
/// response event triggers.
pub struct OllamaExchange {
    /// A short human summary for an injected action's outcome detail.
    pub summary: String,
    /// The `ollama_response_received` payload this exchange produced.
    pub event_data: serde_json::Value,
}

/// What [`OllamaClientImpl::apply_action`] did with one action. The Ollama client owns no
/// socket, so there is no honest byte count to report - only "the API call ran" or "the
/// session should end".
enum Applied {
    /// The action ran; the string says what, for the injected action's outcome detail.
    Executed(String),
    /// The session should end.
    Disconnect,
}
