//! MCP (Model Context Protocol) client implementation
//!
//! Implements JSON-RPC 2.0 client over HTTP for the Model Context Protocol.

pub mod actions;

pub use actions::McpClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::mcp::actions::{MCP_CLIENT_CONNECTED_EVENT, MCP_CLIENT_RESPONSE_RECEIVED_EVENT};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::{json, Value};

/// JSON-RPC 2.0 request message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    id: i64,
}

/// JSON-RPC 2.0 response message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<i64>,
}

/// JSON-RPC 2.0 notification message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JsonRpcNotification {
    jsonrpc: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

/// JSON-RPC 2.0 error object
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// `clientInfo.name` when the `client_name` startup parameter is not set.
const DEFAULT_CLIENT_NAME: &str = "netget-mcp-client";

/// `clientInfo.version` when the `client_version` startup parameter is not set.
const DEFAULT_CLIENT_VERSION: &str = "0.1.0";

/// MCP client that connects to MCP servers
pub struct McpClient;

impl McpClient {
    /// Connect to an MCP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!("MCP client {} connecting to {}", client_id, remote_addr);

        // `client_name` / `client_version` are declared as the identity of this MCP client
        // and were never read: the `clientInfo` of the initialize request was the hardcoded
        // `netget-mcp-client` / `0.1.0` whatever the operator set, so an MCP server logging
        // or gating on who connected saw the wrong name.
        let (client_name, client_version) = match &startup_params {
            Some(params) => (
                params.get_optional_string("client_name")?,
                params.get_optional_string("client_version")?,
            ),
            None => (None, None),
        };
        let client_name = client_name.unwrap_or_else(|| DEFAULT_CLIENT_NAME.to_string());
        let client_version = client_version.unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string());

        // Build HTTP client
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        // Store client data
        let base_url = if remote_addr.starts_with("http://") || remote_addr.starts_with("https://")
        {
            remote_addr.clone()
        } else {
            format!("http://{}", remote_addr)
        };

        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("base_url".to_string(), serde_json::json!(base_url));
                client.set_protocol_field("request_id".to_string(), serde_json::json!(1));
                client.set_protocol_field("initialized".to_string(), serde_json::json!(false));
            })
            .await;

        // Phase 1: Send initialize request
        let init_response = Self::send_initialize_request(
            &http_client,
            &base_url,
            client_id,
            &app_state,
            &status_tx,
            &client_name,
            &client_version,
        )
        .await?;

        // Parse server info from response
        let server_info = init_response
            .get("serverInfo")
            .and_then(|v| v.as_object())
            .context("Missing serverInfo in initialize response")?;

        let server_name = server_info
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let server_version = server_info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let capabilities = init_response
            .get("capabilities")
            .cloned()
            .unwrap_or(json!({}));

        // Store server capabilities
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("server_info".to_string(), json!(server_info));
                client.set_protocol_field("capabilities".to_string(), capabilities.clone());
            })
            .await;

        // Phase 2: Send initialized notification
        Self::send_initialized_notification(&http_client, &base_url, &status_tx).await?;

        // Mark as initialized
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("initialized".to_string(), serde_json::json!(true));
            })
            .await;

        // Update status to connected
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "MCP client {} initialized with server {}",
            client_id, server_name
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        info!("MCP client {} initialization complete", client_id);

        // Create connected event and call LLM
        let event = Event::new(
            &MCP_CLIENT_CONNECTED_EVENT,
            json!({
                "server_name": server_name,
                "server_version": server_version,
                "capabilities": capabilities,
            }),
        );

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
            http_client.clone(),
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn task to handle LLM interactions
        let http_client_clone = http_client.clone();
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let protocol = Arc::new(McpClientProtocol::new());

            // Get instruction and memory
            let instruction = app_state
                .get_instruction_for_client(client_id)
                .await
                .unwrap_or_default();
            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            // Initial LLM call with connected event
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
                    // Update memory
                    if let Some(mem) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute actions from LLM
                    if let Err(e) = Self::execute_llm_actions(
                        client_id,
                        result.actions,
                        &http_client_clone,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        protocol.clone(),
                    )
                    .await
                    {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to execute LLM actions: {}", e));
                    }
                }
                Err(e) => {
                    Log::new(Some(&status_tx)).error(format!("Failed to call LLM: {}", e));
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return dummy local address (MCP is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Send initialize request to MCP server
    ///
    /// `client_name` / `client_version` come from the startup parameters of the same name
    /// and become the `clientInfo` this client presents; they fall back to
    /// [`DEFAULT_CLIENT_NAME`] / [`DEFAULT_CLIENT_VERSION`].
    async fn send_initialize_request(
        http_client: &reqwest::Client,
        base_url: &str,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_name: &str,
        client_version: &str,
    ) -> Result<Value> {
        let request_id: i64 = app_state
            .with_client_mut(client_id, |client| {
                let id = client
                    .get_protocol_field("request_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);
                client.set_protocol_field("request_id".to_string(), json!(id + 1));
                id
            })
            .await
            .context("Client not found")?;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "initialize".to_string(),
            params: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {
                        "listChanged": false
                    }
                },
                "clientInfo": {
                    "name": client_name,
                    "version": client_version
                }
            })),
            id: request_id,
        };

        debug!("Sending initialize request: {:?}", request);
        Log::new(Some(status_tx)).info("Sending MCP initialize request".to_string());

        let response = http_client
            .post(base_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send initialize request")?;

        let status = response.status();
        let response_text = crate::client::http_fetch::read_response_text(
            response,
            crate::client::http_fetch::transport::MAX_RESPONSE_BODY_BYTES,
        )
        .await?;

        debug!(
            "Initialize response status: {}, body: {}",
            status, response_text
        );

        if !status.is_success() {
            return Err(anyhow::anyhow!("HTTP error {}: {}", status, response_text));
        }

        let json_response: JsonRpcResponse =
            serde_json::from_str(&response_text).context("Failed to parse initialize response")?;

        if let Some(error) = json_response.error {
            return Err(anyhow::anyhow!(
                "JSON-RPC error {}: {}",
                error.code,
                error.message
            ));
        }

        json_response
            .result
            .context("Missing result in initialize response")
    }

    /// Send the `notifications/initialized` notification to the MCP server.
    ///
    /// The method name is `notifications/initialized`, not `initialized`. MCP namespaces every
    /// notification under `notifications/`, and this client sent the bare name — so phase 3 of
    /// the handshake was an unrecognised notification to every server it ever talked to,
    /// **including NetGet's own MCP server**, whose router matches `notifications/initialized`
    /// and drops anything else into a `debug!("Unknown MCP notification")`. Nothing failed
    /// visibly because a notification has no reply, which is exactly why it survived: the
    /// client logged "Sending MCP initialized notification", got a 204, and declared the
    /// handshake complete.
    async fn send_initialized_notification(
        http_client: &reqwest::Client,
        base_url: &str,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let notification = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/initialized".to_string(),
            params: Some(json!({})),
        };

        debug!("Sending initialized notification: {:?}", notification);
        Log::new(Some(status_tx)).info("Sending MCP initialized notification".to_string());

        http_client
            .post(base_url)
            .json(&notification)
            .send()
            .await
            .context("Failed to send initialized notification")?;

        Ok(())
    }

    /// Execute actions returned by LLM
    fn execute_llm_actions<'a>(
        client_id: ClientId,
        actions: Vec<Value>,
        http_client: &'a reqwest::Client,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        protocol: Arc<McpClientProtocol>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for action in actions {
                debug!("Executing action: {:?}", action);

                // Parse action
                let action_result = protocol.as_ref().execute_action(action.clone())?;

                match Self::apply_action(
                    client_id,
                    action_result,
                    Notify::Inline,
                    http_client,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol.clone(),
                )
                .await
                {
                    Ok(Applied::Disconnect) => break,
                    Ok(Applied::Executed(_)) => {}
                    Err(e) => {
                        Log::new(Some(status_tx))
                            .error(format!("Failed to execute MCP action: {}", e));
                    }
                }
            }

            Ok(())
        })
    }

    /// Apply one already-executed action result: the single place a JSON-RPC call is
    /// issued and its `mcp_response_received` event fired, shared by the LLM path and by
    /// injected commands so both behave identically.
    ///
    /// Boxed because it recurses through [`Self::execute_llm_actions`] for the follow-up
    /// actions the response event produces.
    #[allow(clippy::too_many_arguments)]
    fn apply_action<'a>(
        client_id: ClientId,
        result: ClientActionResult,
        notify: Notify,
        http_client: &'a reqwest::Client,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        protocol: Arc<McpClientProtocol>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Applied>> + Send + 'a>> {
        Box::pin(async move {
            match result {
                ClientActionResult::Disconnect => {
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    // Every exit path drops the handle so the dashboard stops offering
                    // [ send ] into a dead client.
                    app_state.remove_client_handle(client_id).await;
                    Log::new(Some(status_tx))
                        .info(format!("MCP client {} disconnected", client_id));
                    Ok(Applied::Disconnect)
                }
                ClientActionResult::Custom { name, data } => {
                    let response = Self::execute_mcp_action(
                        client_id,
                        &name,
                        &data,
                        http_client,
                        app_state,
                        status_tx,
                    )
                    .await?;

                    let event_data = json!({
                        "method": name,
                        "result": response,
                    });

                    match notify {
                        Notify::Inline => {
                            Self::notify_response(
                                client_id,
                                event_data,
                                http_client,
                                llm_client,
                                app_state,
                                status_tx,
                                protocol.clone(),
                            )
                            .await;
                        }
                        Notify::Deferred => {
                            // The caller (the injected-command loop) already holds the
                            // truthful JSON-RPC result and must reply to the operator
                            // before this event's handler runs: a dashboard-created client
                            // defaults to a `*` -> manual rule, so the handler can park for
                            // a human's think time (300s by default), far longer than the
                            // composer's 30s send timeout.
                            let http_clone = http_client.clone();
                            let llm_clone = llm_client.clone();
                            let state_clone = app_state.clone();
                            let status_clone = status_tx.clone();
                            let protocol_clone = protocol.clone();
                            let notify_handle = tokio::spawn(async move {
                                McpClient::notify_response(
                                    client_id,
                                    event_data,
                                    &http_clone,
                                    &llm_clone,
                                    &state_clone,
                                    &status_clone,
                                    protocol_clone,
                                )
                                .await;
                            });
                            // Registered so the notification - and the LLM call and any
                            // follow-up JSON-RPC calls it makes - are aborted when the
                            // client is stopped.
                            app_state
                                .register_client_task(client_id, notify_handle)
                                .await;
                        }
                    }

                    Ok(Applied::Executed(format!("{name} completed")))
                }
                other => {
                    debug!("Ignoring non-custom action result: {:?}", other);
                    Ok(Applied::Executed(
                        "action produced no MCP request".to_string(),
                    ))
                }
            }
        })
    }

    /// Fire one `mcp_response_received` event at the LLM, apply any memory update, and
    /// run the follow-up actions it asks for.
    #[allow(clippy::too_many_arguments)]
    async fn notify_response(
        client_id: ClientId,
        event_data: Value,
        http_client: &reqwest::Client,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<McpClientProtocol>,
    ) {
        let event = Event::new(&MCP_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
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
            Some(&event),
            protocol.as_ref(),
            status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                if let Err(e) = Self::execute_llm_actions(
                    client_id,
                    result.actions,
                    http_client,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol.clone(),
                )
                .await
                {
                    error!("Failed to execute nested actions: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to call LLM: {}", e);
            }
        }
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: it writes
    /// `SendData` to a socket, and every MCP verb yields `ClientActionResult::Custom` that
    /// has to become a JSON-RPC POST. So the action goes through [`Self::apply_action`] -
    /// the same function the LLM path uses - and the outcome is recorded and replied
    /// exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        http_client: reqwest::Client,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = Arc::new(McpClientProtocol::new());

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.as_ref().execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // The JSON-RPC call is awaited, so the reported outcome describes a
                // request that has actually completed. Notify::Deferred delivers the
                // mcp_response_received event from its own registered task, so a manual
                // handler parked for a human's think time cannot wedge this loop or time
                // out the dashboard's [ send ].
                Ok(result) => Self::apply_action(
                    client_id,
                    result,
                    Notify::Deferred,
                    &http_client,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    protocol.clone(),
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
                    "MCP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        info!("MCP client {} command loop stopped", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute a specific MCP action
    async fn execute_mcp_action(
        client_id: ClientId,
        action_name: &str,
        data: &Value,
        http_client: &reqwest::Client,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Value> {
        // Read the two fields and bump the counter under one guard, then decide.
        //
        // These were `.expect("Missing base_url")` / `.expect("Missing request_id")` *inside*
        // the `with_client_mut` closure, so a client whose protocol fields had not been set —
        // or had been reset — panicked while the `AppState` write guard was held. The panic
        // landed inside the spawned command loop or notify task, which swallows it, so the
        // symptom was a client that silently stopped answering: no error, no log line, and
        // `[ send ]` timing out on a request that was never made.
        let (base_url, request_id) = app_state
            .with_client_mut(client_id, |client| {
                let url = client
                    .get_protocol_field("base_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let id = client
                    .get_protocol_field("request_id")
                    .and_then(|v| v.as_i64());

                if let Some(id) = id {
                    client.set_protocol_field("request_id".to_string(), json!(id + 1));
                }

                (url, id)
            })
            .await
            .context("Client not found")?;

        let base_url = base_url.context(
            "MCP client has no base_url; it was never initialized or its state was reset",
        )?;
        let request_id = request_id.context(
            "MCP client has no request_id; it was never initialized or its state was reset",
        )?;

        let (method, params) = match action_name {
            "mcp_list_resources" => ("resources/list".to_string(), None),
            "mcp_read_resource" => {
                let uri = data
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .context("Missing uri in read_resource")?;
                ("resources/read".to_string(), Some(json!({"uri": uri})))
            }
            "mcp_list_tools" => ("tools/list".to_string(), None),
            "mcp_call_tool" => {
                let name = data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing name in call_tool")?;
                let arguments = data.get("arguments").cloned().unwrap_or(json!({}));
                (
                    "tools/call".to_string(),
                    Some(json!({
                        "name": name,
                        "arguments": arguments
                    })),
                )
            }
            "mcp_list_prompts" => ("prompts/list".to_string(), None),
            "mcp_get_prompt" => {
                let name = data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing name in get_prompt")?;
                // `arguments` is omitted when absent rather than sent as `null`: MCP declares
                // it optional, and a server that validates the field against its declared
                // object type rejects an explicit null. `Some(json!({... "arguments": None}))`
                // serialised to exactly that.
                let mut params = serde_json::Map::new();
                params.insert("name".to_string(), json!(name));
                if let Some(arguments) = data.get("arguments") {
                    if !arguments.is_null() {
                        params.insert("arguments".to_string(), arguments.clone());
                    }
                }
                ("prompts/get".to_string(), Some(Value::Object(params)))
            }
            _ => return Err(anyhow::anyhow!("Unknown MCP action: {}", action_name)),
        };

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.clone(),
            params,
            id: request_id,
        };

        debug!("Sending MCP request: {:?}", request);
        Log::new(Some(status_tx)).info(format!("Sending MCP request: {}", method));

        let response = http_client
            .post(&base_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send MCP request")?;

        let status = response.status();
        let response_text = crate::client::http_fetch::read_response_text(
            response,
            crate::client::http_fetch::transport::MAX_RESPONSE_BODY_BYTES,
        )
        .await?;

        debug!("MCP response status: {}, body: {}", status, response_text);

        if !status.is_success() {
            return Err(anyhow::anyhow!("HTTP error {}: {}", status, response_text));
        }

        let json_response: JsonRpcResponse =
            serde_json::from_str(&response_text).context("Failed to parse MCP response")?;

        if let Some(error) = json_response.error {
            return Err(anyhow::anyhow!(
                "JSON-RPC error {}: {}",
                error.code,
                error.message
            ));
        }

        json_response
            .result
            .context("Missing result in MCP response")
    }
}

/// When an action's `mcp_response_received` event is delivered to the LLM.
///
/// MCP always awaits the JSON-RPC call itself; only the notification moves. The request is
/// already inside a spawned task on the LLM-driven path, so unlike `http` there is no
/// second "spawn the request" mode here.
#[derive(Clone, Copy)]
enum Notify {
    /// Fire the event and run its follow-up actions before returning. The LLM-driven path.
    Inline,
    /// Fire the event from its own registered task and return at once. The
    /// injected-command path, which must reply to the operator first.
    Deferred,
}

/// What [`McpClient::apply_action`] did with one action. MCP rides on reqwest, so there
/// is no honest byte count to report - only "the JSON-RPC call ran" or "the session
/// should end".
enum Applied {
    /// The action ran; the string says what, for the injected action's outcome detail.
    Executed(String),
    /// The session should end.
    Disconnect,
}
