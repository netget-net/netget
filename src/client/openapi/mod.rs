//! OpenAPI client implementation - spec-driven HTTP requests
pub mod actions;

pub use actions::OpenApiClientProtocol;

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::client::http_fetch::{FetchClient, FetchResponse};
use crate::client::llm_budget::call_llm_for_client;
use crate::client::openapi::actions::{
    OPENAPI_CLIENT_CONNECTED_EVENT, OPENAPI_OPERATION_RESPONSE_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

use openapi_rs::model::parse::OpenAPI;

/// One completed OpenAPI operation.
///
/// Split out of [`OpenApiClient::execute_operation`] so the injected-command loop can await
/// the HTTP round-trip - and report a truthful outcome - without also awaiting the LLM call
/// the `openapi_operation_response` event triggers.
pub struct OpenApiExchange {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: serde_json::Map<String, serde_json::Value>,
    pub body: String,
}

/// What one executed action did.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
}

/// How an OpenAPI operation is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the whole operation and return immediately. Used by the connected-event
    /// handler, which runs inline in `connect()` and must not block client creation on a
    /// request that can take the full 30s timeout.
    Spawn,
    /// Await the HTTP exchange so the caller can report what actually happened, then raise
    /// the response event from its own registered task. Used by the injected-command loop,
    /// so a parked manual handler cannot wedge it for the length of a human's think time.
    Await,
}

/// How much of a response body is read before it is refused.
///
/// The body is remote-controlled and ends up in an event and then in an LLM prompt.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Read a response body as text, refusing anything past [`MAX_RESPONSE_BYTES`].
///
/// Refuses as soon as the cap is passed rather than after buffering, so a server answering
/// with an endless stream costs at most the cap.
async fn read_body_bounded(mut response: FetchResponse) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!(
                "response body exceeded {} bytes; refusing to buffer the rest",
                MAX_RESPONSE_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// OpenAPI client that makes spec-driven requests to HTTP servers
pub struct OpenApiClient;

impl OpenApiClient {
    /// The process-wide HTTP client, built once.
    ///
    /// Same reasoning as the HTTP and DoH clients: `Client::builder().build()` sets up the
    /// rustls stack and loads the platform root store, which on macOS reads the system
    /// keychain synchronously and serialises across processes. It runs on `spawn_blocking`
    /// so it cannot park a tokio worker, and it is kept so operations after the first
    /// reuse the connection pool rather than rebuilding a TLS stack each time.
    #[cfg(not(target_arch = "wasm32"))]
    async fn reqwest_client() -> Result<reqwest::Client> {
        static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
        if let Some(client) = CLIENT.get() {
            return Ok(client.clone());
        }
        let built = tokio::task::spawn_blocking(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .use_rustls_tls()
                .build()
                .context("Failed to build HTTP client")
        })
        .await
        .context("OpenAPI HTTP client build task panicked")??;
        Ok(CLIENT.get_or_init(|| built).clone())
    }

    /// The HTTP client: the process-wide reqwest client natively ([`Self::reqwest_client`]),
    /// the shared hyper transport over the virtual loopback in the browser build
    /// ([`crate::client::http_fetch`]), with the same 30-second bound.
    async fn http_client() -> Result<FetchClient> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = FetchClient::from_reqwest(Self::reqwest_client().await?);
        #[cfg(target_arch = "wasm32")]
        let client = FetchClient::transport(std::time::Duration::from_secs(30));
        Ok(client)
    }

    /// Connect to an OpenAPI server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: serde_json::Value,
    ) -> Result<SocketAddr> {
        info!(
            "OpenAPI client {} initializing for {}",
            client_id, remote_addr
        );

        // Parse startup parameters to get spec
        let spec_yaml = if let Some(spec_str) = startup_params.get("spec").and_then(|v| v.as_str())
        {
            spec_str.to_string()
        } else if let Some(spec_file) = startup_params.get("spec_file").and_then(|v| v.as_str()) {
            // Load spec from file
            std::fs::read_to_string(spec_file)
                .with_context(|| format!("Failed to read spec file: {}", spec_file))?
        } else {
            return Err(anyhow!(
                "OpenAPI client requires 'spec' or 'spec_file' parameter"
            ));
        };

        // Parse OpenAPI spec
        let parsed_spec: OpenAPI =
            serde_yaml::from_str(&spec_yaml).context("Failed to parse OpenAPI spec (YAML)")?;


        // Determine the base URL. Precedence: an explicit `base_url` parameter, then the
        // address the operator named, and the spec's own `servers[0]` only as a last resort.
        //
        // **That order used to be inverted**, and the inversion is the defect `CLAUDE.md`
        // records for the DynamoDB client wearing different clothes: the spec's declared
        // server won over `remote_addr`, so an operator who said "connect to 127.0.0.1:9000"
        // and handed over a spec whose `servers:` block names
        // `https://api.production.example.com` got the production host — silently, with no
        // log line saying so. A spec is data supplied with the request, often by the model;
        // it must not be able to retarget the client away from the address it was given.
        //
        // The tell was in the test suite: `tests/client/openapi/e2e_test.rs` has to rewrite
        // `{port}` inside the spec before every run, which is the workaround you write when
        // `remote_addr` is not what decides. It still passes now, because both agree.
        let base_url =
            if let Some(override_url) = startup_params.get("base_url").and_then(|v| v.as_str()) {
                override_url.to_string()
            } else if !remote_addr.trim().is_empty() {
                let named = if remote_addr.contains("://") {
                    remote_addr.clone()
                } else {
                    // reqwest needs an absolute URL; a bare `host:port` fails every request
                    // with "relative URL without a base".
                    format!("http://{}", remote_addr)
                };
                if let Some(server) = parsed_spec.servers.first() {
                    if server.url != named {
                        info!(
                            "OpenAPI client {} using remote_addr {} rather than the spec's \
                             servers[0] ({}); pass base_url to override",
                            client_id, named, server.url
                        );
                    }
                }
                named
            } else if let Some(server) = parsed_spec.servers.first() {
                // Nothing was named, so the spec is all there is. Say so, rather than
                // arriving at a host nobody in this conversation typed.
                info!(
                    "OpenAPI client {} has no remote_addr; falling back to the spec's \
                     servers[0]: {}",
                    client_id, server.url
                );
                server.url.clone()
            } else {
                return Err(anyhow!(
                    "OpenAPI client needs a target: pass remote_addr, a base_url startup \
                     parameter, or a spec declaring servers[0]"
                ));
            };


        info!("OpenAPI client {} using base URL: {}", client_id, base_url);

        // Warm the shared client rather than building one and dropping it. This used to
        // bind to `_http_client`: a full rustls stack built at connect time and discarded,
        // while every operation built another one.
        Self::http_client().await?;
        // The browser transport has no TLS: an `https://` base URL is refused here, with the
        // reason, rather than on the first operation.
        crate::client::http_fetch::check_url(&base_url)?;

        // Store spec and base URL in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("spec".to_string(), serde_json::json!(spec_yaml));
                client.set_protocol_field("base_url".to_string(), serde_json::json!(base_url));
                client.set_protocol_field(
                    "http_client".to_string(),
                    serde_json::json!("initialized"),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "OpenAPI client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered and *served* before the openapi_client_connected LLM call below:
        // a dashboard-created client defaults to a `*` -> manual routing rule, so that
        // call can park for minutes and [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The command loop replaces the old 5s "is the client gone yet?" poll: when the
        // client is removed its handle is dropped, the channel closes and `recv()`
        // returns None, so the loop notices removal immediately instead of up to 5s later.
        // Registered with AppState so stop_client can abort it —
        // dropping a JoinHandle only detaches it in Tokio.
        let command_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        // Extract operation list for LLM
        let operations = Self::extract_operations(&parsed_spec);


        // Call LLM with openapi_client_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let spec_title = parsed_spec.info.title.clone();
            let spec_version = parsed_spec.info.version.clone();


            let event = Event::new(
                &OPENAPI_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "base_url": base_url.clone(),
                    "spec_title": spec_title,
                    "spec_version": spec_version,
                    "operation_count": operations.len(),
                    "operations": operations,
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(), // No memory yet
                Some(&event),
                &crate::client::openapi::actions::OpenApiClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Execute actions from LLM response
                    Self::execute_llm_actions(
                        client_id,
                        result,
                        app_state.clone(),
                        llm_client.clone(),
                        status_tx.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    error!("LLM error on openapi_client_connected event: {}", e);
                }
            }
        }

        // Return dummy address (HTTP is connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Extract operation list from OpenAPI spec for LLM
    fn extract_operations(spec: &OpenAPI) -> Vec<serde_json::Value> {
        let mut operations = Vec::new();

        for (path, path_item) in &spec.paths {
            // Iterate over HTTP methods in path_item.operations
            for (method_str, operation) in &path_item.operations {
                let operation_id = operation
                    .operation_id
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| format!("{}_{}", method_str, path.replace('/', "_")));

                operations.push(serde_json::json!({
                    "operation_id": operation_id,
                    "method": method_str.to_uppercase(),
                    "path": path,
                    "summary": operation.summary.as_ref().unwrap_or(&String::new()),
                    "description": operation.description.as_ref().unwrap_or(&String::new()),
                }));
            }
        }

        operations
    }

    /// Execute actions returned by LLM.
    ///
    /// Each action goes through the same [`Self::apply_action`] the dashboard's
    /// injected-command path uses; the only difference is that this path spawns it, so
    /// `connect()` can return without waiting for the request to complete.
    async fn execute_llm_actions(
        client_id: ClientId,
        result: ClientLlmResult,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::openapi::actions::OpenApiClientProtocol;

        for action in result.actions {
            match protocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    info!("LLM requested disconnect for OpenAPI client {}", client_id);
                    // The command loop tears the client's handle down when the client
                    // itself is removed; nothing to close here (OpenAPI owns no socket).
                }
                Ok(applied) => {
                    // Dispatch::Spawn so connect() is not blocked on the request.
                    match Self::apply_action(
                        client_id,
                        applied,
                        Dispatch::Spawn,
                        &app_state,
                        &llm_client,
                        &status_tx,
                    )
                    .await
                    {
                        Ok(Applied::Executed(detail)) => {
                            debug!("OpenAPI client {} after connect: {}", client_id, detail)
                        }
                        Ok(Applied::Disconnect) => {
                            info!("LLM requested disconnect for OpenAPI client {}", client_id)
                        }
                        Err(e) => error!("OpenAPI operation execution failed: {}", e),
                    }
                }
                Err(e) => {
                    error!("Action execution error: {}", e);
                }
            }
        }
    }

    /// Apply one already-parsed action against the live OpenAPI client.
    ///
    /// The single place OpenAPI actions become HTTP traffic, so an action injected from the
    /// dashboard behaves exactly like one the model produced. Under [`Dispatch::Await`]
    /// only the **network** half is awaited; the response event - and the LLM call it makes
    /// - is raised from its own registered task afterwards, so a `*` -> manual routing rule
    /// parking that event cannot wedge the command loop for the length of a human's think
    /// time. The outcome stays truthful because it carries the status the server actually
    /// returned, which is known before the event is raised.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        dispatch: Dispatch,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "openapi_operation" => {
                let operation_id = data["operation_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let path_params: HashMap<String, String> = data["path_params"]
                    .as_object()
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                let query_params: HashMap<String, String> = data["query_params"]
                    .as_object()
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                let headers = data["headers"].as_object().cloned();
                let body = data["body"].clone();

                match dispatch {
                    Dispatch::Spawn => {
                        let state_clone = app_state.clone();
                        let llm_clone = llm_client.clone();
                        let status_clone = status_tx.clone();
                        let log_id = operation_id.clone();

                        // Registered with AppState so stop_client can abort this task —
                        // dropping a JoinHandle only detaches it in Tokio.
                        let handle = tokio::spawn(async move {
                            if let Err(e) = Self::execute_operation(
                                client_id,
                                operation_id,
                                path_params,
                                query_params,
                                headers,
                                body,
                                state_clone,
                                llm_clone,
                                status_clone,
                            )
                            .await
                            {
                                error!("OpenAPI operation execution failed: {}", e);
                            }
                        });
                        app_state.register_client_task(client_id, handle).await;
                        Ok(Applied::Executed(format!("operation {log_id} dispatched")))
                    }
                    Dispatch::Await => {
                        let exchange = Self::perform_operation(
                            client_id,
                            operation_id,
                            path_params,
                            query_params,
                            headers,
                            body,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!(
                            "operation {} -> {} {} -> {} ({} byte body)",
                            exchange.operation_id,
                            exchange.method,
                            exchange.path,
                            exchange.status_code,
                            exchange.body.len()
                        );

                        let state_clone = app_state.clone();
                        let llm_clone = llm_client.clone();
                        let status_clone = status_tx.clone();
                        let handle = tokio::spawn(async move {
                            Self::notify_operation_response(
                                client_id,
                                exchange,
                                state_clone,
                                llm_clone,
                                status_clone,
                            )
                            .await;
                        });
                        app_state.register_client_task(client_id, handle).await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            ClientActionResult::Custom { name, .. } => Ok(Applied::Executed(format!(
                "unknown OpenAPI custom result '{name}' was not executed"
            ))),
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::NoAction => Ok(Applied::Executed(
                "no_action (list_operations / get_operation_details are answered from the \
                 spec already sent in openapi_client_connected)"
                    .to_string(),
            )),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::SendData(_) => Ok(Applied::Executed(
                "OpenAPI owns no socket; raw send_data cannot be put on the wire".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Executed(
                "OpenAPI produces no Multiple results; nothing executed".to_string(),
            )),
        }
    }

    /// Serve injected commands until the client goes away.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        let protocol = crate::client::openapi::actions::OpenApiClientProtocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Never `Sent`: reqwest owns the socket and does not report how many bytes
                // the request serialised to, so a byte count here would be invented.
                // `Executed` carries the response status instead.
                Ok(result) => match Self::apply_action(
                    client_id,
                    result,
                    Dispatch::Await,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                {
                    Ok(Applied::Executed(detail)) => Ok(ClientSendOutcome::Executed { detail }),
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
                error!("OpenAPI client {} injected action failed: {}", client_id, e);
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
        }

        info!("OpenAPI client {} command loop finished", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute an OpenAPI operation and hand the response to the LLM.
    #[allow(clippy::too_many_arguments)]
    async fn execute_operation(
        client_id: ClientId,
        operation_id: String,
        path_params: HashMap<String, String>,
        query_params: HashMap<String, String>,
        header_overrides: Option<serde_json::Map<String, serde_json::Value>>,
        body: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_operation(
            client_id,
            operation_id,
            path_params,
            query_params,
            header_overrides,
            body,
            &app_state,
            &status_tx,
        )
        .await?;
        Self::notify_operation_response(client_id, exchange, app_state, llm_client, status_tx)
            .await;
        Ok(())
    }

    /// Resolve the operation against the spec and perform the HTTP round-trip only.
    ///
    /// No LLM involvement, so a caller can await this and know exactly what the server
    /// answered. An `operation_id` the spec does not define fails here, which is why an
    /// injected command for a missing operation reports an error rather than success.
    #[allow(clippy::too_many_arguments)]
    async fn perform_operation(
        client_id: ClientId,
        operation_id: String,
        path_params: HashMap<String, String>,
        query_params: HashMap<String, String>,
        header_overrides: Option<serde_json::Map<String, serde_json::Value>>,
        body: serde_json::Value,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<OpenApiExchange> {
        // Get spec and base URL from client
        let (spec_yaml, base_url) = app_state
            .with_client_mut(client_id, |client| {
                let spec = client
                    .get_protocol_field("spec")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let url = client
                    .get_protocol_field("base_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (spec, url)
            })
            .await
            .unwrap_or((None, None));

        let spec_yaml = spec_yaml.context("No spec found")?;
        let base_url = base_url.context("No base URL found")?;

        // Parse spec
        let parsed_spec: OpenAPI =
            serde_yaml::from_str(&spec_yaml).context("Failed to parse OpenAPI spec")?;

        // Find operation in spec
        let (path_template, method) = Self::find_operation(&parsed_spec, &operation_id)?;


        // Substitute path parameters
        let path = Self::substitute_path_params(&path_template, &path_params)?;

        // Build full URL
        let url = format!("{}{}", base_url, path);

        info!(
            "OpenAPI client {} executing operation '{}': {} {}",
            client_id, operation_id, method, url
        );

        let http_client = Self::http_client().await?;

        // Build request
        let mut request = match method.to_uppercase().as_str() {
            "GET" => http_client.get(&url),
            "POST" => http_client.post(&url),
            "PUT" => http_client.put(&url),
            "DELETE" => http_client.delete(&url),
            "HEAD" => http_client.head(&url),
            "PATCH" => http_client.patch(&url),
            _ => return Err(anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Add query parameters
        if !query_params.is_empty() {
            request = request.query(&query_params);
        }

        // Add headers
        if let Some(hdrs) = header_overrides {
            for (key, value) in hdrs {
                if let Some(val_str) = value.as_str() {
                    request = request.header(&key, val_str);
                }
            }
        }

        // Add body if not null
        if !body.is_null() {
            request = request.json(&body);
        }

        // Execute request
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                // Get headers
                let mut resp_headers = serde_json::Map::new();
                for (name, value) in response.headers() {
                    if let Ok(val_str) = value.to_str() {
                        resp_headers.insert(name.to_string(), serde_json::json!(val_str));
                    }
                }

                // Get body, bounded. `response.text()` buffers the whole thing with no
                // limit, and the body is remote-controlled: it goes into an
                // `openapi_operation_response` event and from there into an LLM prompt,
                // where a megabyte is already useless. `unwrap_or_default()` also turned a
                // read failure into an empty body, which reads downstream as "the server
                // answered with nothing" rather than "we could not read the answer".
                let body_text = match read_body_bounded(response).await {
                    Ok(text) => text,
                    Err(e) => {
                        Log::new(Some(status_tx)).warn(format!(
                            "OpenAPI client {} could not read the response for '{}': {}",
                            client_id, operation_id, e
                        ));
                        return Err(e);
                    }
                };

                info!(
                    "OpenAPI client {} received response for '{}': {} ({})",
                    client_id, operation_id, status_code, status
                );

                Ok(OpenApiExchange {
                    operation_id,
                    method,
                    path,
                    status_code,
                    status_text: status.to_string(),
                    headers: resp_headers,
                    body: body_text,
                })
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "OpenAPI client {} request failed for '{}': {}",
                    client_id, operation_id, e
                ));
                Err(e)
            }
        }
    }

    /// Hand a completed exchange to the LLM as an `openapi_operation_response` event.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded (`actions: _`), so answering openapi_operation_response did
    /// nothing -- the whole point of raising it. Dispatch goes through
    /// `perform_operation`, which raises no event: that bounds the loop and avoids a
    /// notify -> perform -> notify chain rustc cannot prove `Send`.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::openapi::actions::OpenApiClientProtocol::new();
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            if name != "openapi_operation" {
                info!(
                    "OpenAPI client {} follow-up '{}' has no non-notifying path; skipped",
                    client_id, name
                );
                continue;
            }
            let to_map = |v: &serde_json::Value| -> HashMap<String, String> {
                v.as_object()
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let result = Self::perform_operation(
                client_id,
                data["operation_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                to_map(&data["path_params"]),
                to_map(&data["query_params"]),
                data["headers"].as_object().cloned(),
                data.get("body").cloned().unwrap_or(serde_json::Value::Null),
                app_state,
                status_tx,
            )
            .await;
            if let Err(e) = result {
                error!(
                    "OpenAPI client {} follow-up action failed: {}",
                    client_id, e
                );
            }
        }
    }

    async fn notify_operation_response(
        client_id: ClientId,
        exchange: OpenApiExchange,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::openapi::actions::OpenApiClientProtocol::new());
        let event = Event::new(
            &OPENAPI_OPERATION_RESPONSE_EVENT,
            serde_json::json!({
                "operation_id": exchange.operation_id,
                "method": exchange.method,
                "path": exchange.path,
                "status_code": exchange.status_code,
                "status_text": exchange.status_text,
                "headers": exchange.headers,
                "body": exchange.body,
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
                Self::run_follow_ups(client_id, actions, &app_state, &status_tx).await;
                // Note: We don't execute follow-up actions here to avoid recursive async
                // function issues. The LLM can handle follow-up operations by including
                // them in the original response, or the operator can inject them.
            }
            Err(e) => {
                error!("LLM error for OpenAPI client {}: {}", client_id, e);
            }
        }
    }

    /// Find operation in spec by operation_id
    fn find_operation(spec: &OpenAPI, operation_id: &str) -> Result<(String, String)> {
        for (path, path_item) in &spec.paths {
            for (method, operation) in &path_item.operations {
                let op_id = operation
                    .operation_id
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("");

                if op_id == operation_id {
                    return Ok((path.clone(), method.clone()));
                }
            }
        }

        Err(anyhow!(
            "Operation '{}' not found in OpenAPI spec",
            operation_id
        ))
    }

    /// Substitute path parameters in template
    fn substitute_path_params(template: &str, params: &HashMap<String, String>) -> Result<String> {
        let mut path = template.to_string();

        // Replace {param} with values
        for (key, value) in params {
            let pattern = format!("{{{}}}", key);
            path = path.replace(&pattern, value);
        }

        // Check for unsubstituted parameters
        if path.contains('{') {
            return Err(anyhow!(
                "Missing required path parameters in '{}': {}",
                template,
                path
            ));
        }

        Ok(path)
    }
}
