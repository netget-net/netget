//! XML-RPC client implementation
pub mod actions;
pub mod response_guard;

pub use actions::XmlRpcClientProtocol;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::xmlrpc::actions::{
    XMLRPC_CLIENT_CONNECTED_EVENT, XMLRPC_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// What [`XmlRpcClient::apply_action`] did with one executed action. XML-RPC is
/// request/response over HTTP with no socket of our own, so no byte count can honestly be
/// reported - each variant carries a description of the effect instead.
enum Applied {
    /// The action ran; the string describes what happened.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// What a completed XML-RPC call answered.
enum CallOutcome {
    /// The server returned a value (converted to JSON).
    Result(serde_json::Value),
    /// The server returned an XML-RPC `<fault>`; the call reached it and was refused.
    Fault(String),
}

/// Whether the response event is raised inline or from its own task.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Raise it here and now. Used by the connected-event LLM path (which already runs in
    /// its own spawned task) and by the model's own follow-up calls.
    Inline,
    /// Hand it to a registered task. Used by the injected-command loop so a manual
    /// (human-answered) routing rule on `xmlrpc_response_received` cannot hold up the
    /// command's outcome, or the next injected command.
    Deferred,
}

/// Request timeout when the `timeout_secs` startup parameter is not set. Matches the value
/// that parameter's own description names as the default.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Deepest `<array>`/`<struct>` nesting NetGet will walk in either direction.
///
/// Both conversions below are recursive, and one of them walks a value that came off the
/// network. A recursive walk with no counter is a stack overflow, which in Rust is a `SIGSEGV`
/// against the guard page rather than a panic — `tokio::spawn` cannot contain it and the whole
/// NetGet process dies. 64 is far past anything an XML-RPC API expresses; real structs are
/// depth 2 or 3.
///
/// **This bound does not make the client safe against a hostile server, and cannot.** See
/// [`XmlRpcClient::xmlrpc_value_to_json`].
const MAX_VALUE_DEPTH: usize = 64;

/// XML-RPC client that calls methods on remote servers
pub struct XmlRpcClient;

impl XmlRpcClient {
    /// Connect to an XML-RPC server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        _llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // For XML-RPC, "connection" is logical, not a persistent connection
        // The server URL is stored and used for each method call

        // `timeout_secs` was declared as "request timeout in seconds (default: 30)" and
        // read by nothing, so a call to an unresponsive server never returned. See
        // `perform_call` for what it can and cannot bound.
        let timeout_secs = match &startup_params {
            Some(params) => params.get_optional_u64("timeout_secs")?,
            None => None,
        }
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

        info!(
            "XML-RPC client {} initialized for {}",
            client_id, remote_addr
        );

        // Ensure URL is properly formatted
        let server_url =
            if remote_addr.starts_with("http://") || remote_addr.starts_with("https://") {
                remote_addr.clone()
            } else {
                format!("http://{}", remote_addr)
            };

        // Store server URL in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("server_url".to_string(), serde_json::json!(server_url));
                client.set_protocol_field(
                    "timeout_secs".to_string(),
                    serde_json::json!(timeout_secs),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "XML-RPC client {} ready for {}",
            client_id, server_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ call_xmlrpc_method ] /
        // [ disconnect ]). Registered BEFORE the connected-event LLM call below, which is
        // awaited inline and which a manual `*` routing rule can park for minutes - the
        // operator must be able to call a method while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            _llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with initial connected event to trigger first action
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::xmlrpc::actions::XmlRpcClientProtocol::new());
            let event = Event::new(
                &XMLRPC_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "server_url": server_url,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            if let Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) = call_llm_for_client(
                &_llm_client,
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
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Execute initial actions through the same path injected commands use.
                for action in actions {
                    let result = match protocol.execute_action(action) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("XML-RPC client {} rejected action: {}", client_id, e);
                            continue;
                        }
                    };

                    if matches!(result, ClientActionResult::Disconnect) {
                        info!(
                            "XML-RPC client {} disconnecting on initial action",
                            client_id
                        );
                        let _ = Self::apply_action(
                            result,
                            Dispatch::Inline,
                            client_id,
                            &app_state,
                            &_llm_client,
                            &status_tx,
                        )
                        .await;
                        // Nothing can be injected into a session that never started.
                        app_state.remove_client_handle(client_id).await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        return Ok("0.0.0.0:0".parse().unwrap());
                    }

                    // The method call itself is spawned so `connect` still returns
                    // promptly; injected commands await it instead (see `command_loop`).
                    let app_state_clone = app_state.clone();
                    let llm_client_clone = _llm_client.clone();
                    let status_tx_clone = status_tx.clone();
                    // Registered with AppState so stop_client can abort this task —
                    // dropping a JoinHandle only detaches it in Tokio.
                    let task_registrar = app_state.clone();
                    let task_handle = tokio::spawn(async move {
                        if let Err(e) = Self::apply_action(
                            result,
                            Dispatch::Inline,
                            client_id,
                            &app_state_clone,
                            &llm_client_clone,
                            &status_tx_clone,
                        )
                        .await
                        {
                            error!("XML-RPC client {} action failed: {}", client_id, e);
                        }
                    });
                    task_registrar
                        .register_client_task(client_id, task_handle)
                        .await;
                }
            }
        }

        // No idle-poll task: the command loop is this client's long-lived task and it ends
        // when the client is removed (`remove_client` drops the command sender).

        // Return a dummy local address (XML-RPC is connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Run one executed action. Shared by the connected-event LLM path and injected
    /// commands so the `xmlrpc_call` decoding exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "xmlrpc_call" => {
                let method = data
                    .get("method_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method_name' in xmlrpc_call")?
                    .to_string();
                let params = data
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let param_count = params.len();

                let outcome =
                    Self::perform_call(client_id, &method, params, app_state, status_tx).await?;
                let detail = match &outcome {
                    CallOutcome::Result(_) => format!(
                        "xmlrpc_call '{}' with {} param(s): server returned a result",
                        method, param_count
                    ),
                    CallOutcome::Fault(fault) => format!(
                        "xmlrpc_call '{}' with {} param(s): server returned fault: {}",
                        method, param_count, fault
                    ),
                };

                match dispatch {
                    Dispatch::Inline => {
                        Self::notify_call_result(
                            client_id,
                            method,
                            outcome,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        )
                        .await;
                    }
                    Dispatch::Deferred => {
                        let handle = tokio::spawn(Self::notify_call_result(
                            client_id,
                            method,
                            outcome,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        ));
                        // Registered so stop_client aborts an in-flight LLM call.
                        app_state.register_client_task(client_id, handle).await;
                    }
                }
                Ok(Applied::Ran(detail))
            }
            ClientActionResult::Disconnect => {
                info!("XML-RPC client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(Applied::Disconnect)
            }
            ClientActionResult::Custom { name, .. } => Err(anyhow::anyhow!(
                "XML-RPC client cannot execute custom result '{}'",
                name
            )),
            // WaitForMore / NoAction / SendData / nested Multiple: no method call to make.
            _ => Ok(Applied::Ran(
                "no method called (action produced no XML-RPC request)".to_string(),
            )),
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session. The call is awaited, so the reported
    /// [`ClientSendOutcome`] describes a round-trip that really happened - including its
    /// failure, which surfaces as an error rather than a fake success.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = crate::client::xmlrpc::actions::XmlRpcClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(
                    result,
                    Dispatch::Deferred,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Ran(detail) => ClientSendOutcome::Executed { detail },
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
                    "XML-RPC client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("XML-RPC client {} command loop ended", client_id);
    }

    /// Call an XML-RPC method
    pub fn call_method(
        client_id: ClientId,
        method_name: String,
        params: Vec<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            Self::call_method_impl(
                client_id,
                method_name,
                params,
                app_state,
                llm_client,
                status_tx,
            )
            .await
        })
    }

    /// Implementation of call_method: perform the call, then report it.
    async fn call_method_impl(
        client_id: ClientId,
        method_name: String,
        params: Vec<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let outcome =
            Self::perform_call(client_id, &method_name, params, &app_state, &status_tx).await?;
        let failed = match &outcome {
            CallOutcome::Fault(fault) => Some(fault.clone()),
            CallOutcome::Result(_) => None,
        };
        Self::notify_call_result(
            client_id,
            method_name,
            outcome,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        match failed {
            Some(fault) => Err(anyhow::anyhow!("XML-RPC error: {}", fault)),
            None => Ok(()),
        }
    }

    /// Make one XML-RPC call and return what the server answered.
    ///
    /// Split out of [`Self::call_method_impl`] so the injected-command loop can await the
    /// round-trip - and report what really happened - without also awaiting the LLM call
    /// the response event triggers, which a manual routing rule can park for minutes.
    /// A transport failure is an `Err`; an XML-RPC `<fault>` is a `CallOutcome::Fault`,
    /// because the server did answer.
    async fn perform_call(
        client_id: ClientId,
        method_name: &str,
        params: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<CallOutcome> {
        // Server URL and the `timeout_secs` startup parameter, read together under one guard.
        let (server_url, timeout_secs) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("server_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("timeout_secs")
                        .and_then(|v| v.as_u64()),
                )
            })
            .await
            .unwrap_or((None, None));
        let server_url = server_url.context("No server URL found")?;
        let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));

        info!(
            "XML-RPC client {} calling method: {} with {} params",
            client_id,
            method_name,
            params.len()
        );

        // Convert JSON values to xmlrpc::Value
        let mut xmlrpc_params = Vec::new();
        for param in params {
            let xmlrpc_value = Self::json_to_xmlrpc_value(param)?;
            xmlrpc_params.push(xmlrpc_value);
        }

        let method_owned = method_name.to_string();
        let log_name = method_name.to_string();

        // NetGet does the HTTP itself rather than calling `Request::call_url`, and the reason
        // is safety, not convenience. `call_url` owns the fetch *and* the parse, and the
        // crate's parser recurses once per `<value>` with no depth counter and no cap on the
        // body - a hostile server's first reply can stack-overflow the whole process. What
        // gives us a seam is that `Request::call` accepts any `xmlrpc::Transport`, a public
        // trait with an associated `Stream: Read`; the reqwest 0.11 `RequestBuilder` is one
        // provided implementation of it, not the signature. So: serialise here, fetch here
        // under a real per-request timeout, screen the bytes in `response_guard`, then let the
        // crate parse what it is handed. See `response_guard`'s module docs.
        let request_xml = {
            let mut request = xmlrpc::Request::new(&method_owned);
            for param in &xmlrpc_params {
                request = request.arg(param.clone());
            }
            let mut buf = Vec::new();
            request
                .write_as_xml(&mut buf)
                .context("Failed to serialise the XML-RPC request")?;
            buf
        };

        let http = response_guard::http_client_for(&server_url, timeout).await;
        let fetch = async {
            let response = http
                .post(&server_url)
                .header(reqwest::header::USER_AGENT, "Rust xmlrpc")
                .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=utf-8")
                .body(request_xml)
                .send()
                .await?;
            response_guard::check_response(&response)?;
            response_guard::read_body_capped(response).await
        };

        // `timeout_secs` bounds the whole exchange. Unlike the old arrangement it now also
        // *cancels* it: the fetch is an ordinary future rather than a blocking-pool thread
        // holding a socket until its own TCP timeout, and the parse that follows is bounded
        // by `MAX_RESPONSE_BYTES` rather than by whatever the server chose to send.
        let body = match tokio::time::timeout(timeout, fetch).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                // A refusal is a decision, not a transport hiccup, and is logged as one.
                if let Some(refusal) = e.downcast_ref::<response_guard::ResponseRefusal>() {
                    Log::new(Some(status_tx)).error(format!(
                        "XML-RPC client {} refused the reply to '{}' decision={} ({})",
                        client_id,
                        log_name,
                        refusal.decision_tag(),
                        refusal
                    ));
                } else {
                    Log::new(Some(status_tx)).error(format!(
                        "XML-RPC client {} call to {} failed: {}",
                        client_id, log_name, e
                    ));
                }
                return Err(e);
            }
            Err(_) => {
                Log::new(Some(status_tx)).error(format!(
                    "XML-RPC client {} call to {} timed out after {}s",
                    client_id,
                    log_name,
                    timeout.as_secs()
                ));
                return Err(anyhow::anyhow!(
                    "XML-RPC call '{}' timed out after {}s (timeout_secs)",
                    log_name,
                    timeout.as_secs()
                ));
            }
        };

        // The scan and the crate's parser are both CPU-bound over at most
        // `MAX_RESPONSE_BYTES`, so they run on the blocking pool together.
        let scan_and_parse = tokio::task::spawn_blocking(move || {
            response_guard::scan_depth(&body)?;
            let mut request = xmlrpc::Request::new(&method_owned);
            for param in xmlrpc_params {
                request = request.arg(param);
            }
            Ok::<_, anyhow::Error>(request.call(response_guard::PrefetchedTransport::new(body)))
        })
        .await;

        match scan_and_parse {
            Ok(Ok(Ok(response))) => {
                info!(
                    "XML-RPC client {} received response for {}",
                    client_id, log_name
                );
                Ok(CallOutcome::Result(Self::xmlrpc_value_to_json(&response)))
            }
            // The server answered with a `<fault>`: a real answer, reported as one.
            Ok(Ok(Err(err))) if err.fault().is_some() => {
                let fault_msg = err.to_string();
                error!(
                    "XML-RPC client {} fault for {}: {}",
                    client_id, log_name, fault_msg
                );
                Ok(CallOutcome::Fault(fault_msg))
            }
            // A parse failure is not a fault - the server said something unusable.
            Ok(Ok(Err(err))) => {
                Log::new(Some(status_tx)).error(format!(
                    "XML-RPC client {} could not parse the reply to {}: {}",
                    client_id, log_name, err
                ));
                Err(anyhow::anyhow!(
                    "XML-RPC reply to '{}' could not be parsed: {}",
                    log_name,
                    err
                ))
            }
            Ok(Err(refusal)) => {
                if let Some(r) = refusal.downcast_ref::<response_guard::ResponseRefusal>() {
                    Log::new(Some(status_tx)).error(format!(
                        "XML-RPC client {} refused the reply to '{}' decision={} ({})",
                        client_id,
                        log_name,
                        r.decision_tag(),
                        r
                    ));
                }
                Err(refusal)
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("XML-RPC client {} call failed: {}", client_id, e));
                Err(e.into())
            }
        }
    }

    /// Raise `xmlrpc_response_received` for a completed call and run whatever the model
    /// answers with (which may be a follow-up call, hence the boxed recursion).
    fn notify_call_result(
        client_id: ClientId,
        method_name: String,
        outcome: CallOutcome,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                return;
            };

            let protocol = Arc::new(crate::client::xmlrpc::actions::XmlRpcClientProtocol::new());
            let data = match &outcome {
                CallOutcome::Result(result) => serde_json::json!({
                    "method_name": method_name,
                    "result": result,
                }),
                CallOutcome::Fault(fault) => serde_json::json!({
                    "method_name": method_name,
                    "fault": { "error": fault },
                }),
            };
            let event = Event::new(&XMLRPC_CLIENT_RESPONSE_RECEIVED_EVENT, data);

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

                    // Execute the follow-up actions through the shared path.
                    for action in actions {
                        let result = match protocol.execute_action(action) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("XML-RPC client {} rejected action: {}", client_id, e);
                                continue;
                            }
                        };
                        match Self::apply_action(
                            result,
                            Dispatch::Inline,
                            client_id,
                            &app_state,
                            &llm_client,
                            &status_tx,
                        )
                        .await
                        {
                            Ok(Applied::Ran(detail)) => {
                                info!("XML-RPC client {}: {}", client_id, detail)
                            }
                            Ok(Applied::Disconnect) => break,
                            Err(e) => {
                                error!("XML-RPC client {} action failed: {}", client_id, e)
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for XML-RPC client {}: {}", client_id, e);
                }
            }
        })
    }

    /// Convert JSON value to xmlrpc::Value, bounded at [`MAX_VALUE_DEPTH`].
    ///
    /// The input is model output, which `serde_json` already caps at its own 128-level
    /// recursion limit, so this bound is belt-and-braces on that side. It is the *other*
    /// direction that matters — see [`Self::xmlrpc_value_to_json`].
    fn json_to_xmlrpc_value(json: serde_json::Value) -> Result<xmlrpc::Value> {
        Self::json_to_xmlrpc_value_at(json, 0)
    }

    fn json_to_xmlrpc_value_at(json: serde_json::Value, depth: usize) -> Result<xmlrpc::Value> {
        if depth >= MAX_VALUE_DEPTH {
            anyhow::bail!("parameter nesting deeper than {} levels", MAX_VALUE_DEPTH);
        }
        match json {
            serde_json::Value::Null => Ok(xmlrpc::Value::String("".to_string())),
            serde_json::Value::Bool(b) => Ok(xmlrpc::Value::Bool(b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                        Ok(xmlrpc::Value::Int(i as i32))
                    } else {
                        Ok(xmlrpc::Value::Int64(i))
                    }
                } else if let Some(f) = n.as_f64() {
                    Ok(xmlrpc::Value::Double(f))
                } else {
                    Err(anyhow::anyhow!("Invalid number"))
                }
            }
            serde_json::Value::String(s) => Ok(xmlrpc::Value::String(s)),
            serde_json::Value::Array(arr) => {
                let mut xmlrpc_arr = Vec::new();
                for item in arr {
                    xmlrpc_arr.push(Self::json_to_xmlrpc_value_at(item, depth + 1)?);
                }
                Ok(xmlrpc::Value::Array(xmlrpc_arr))
            }
            serde_json::Value::Object(obj) => {
                let mut xmlrpc_struct = BTreeMap::new();
                for (key, value) in obj {
                    xmlrpc_struct.insert(key, Self::json_to_xmlrpc_value_at(value, depth + 1)?);
                }
                Ok(xmlrpc::Value::Struct(xmlrpc_struct))
            }
        }
    }

    /// Convert an `xmlrpc::Value` from a server's reply into JSON for the model, bounded at
    /// [`MAX_VALUE_DEPTH`]. Anything deeper is replaced by a marker string rather than walked.
    ///
    /// The walk is recursive over a value that came off the network, and a recursive walk with
    /// no counter is a stack overflow — `SIGSEGV` against the guard page, not a panic, so
    /// `tokio::spawn` cannot contain it and the whole NetGet process dies.
    ///
    /// **This bound is NetGet's half of the problem, and it is not the whole of it.** `xmlrpc`
    /// 0.15's own `Parser::parse_value` → `parse_value_inner` → `parse_value` recurses with no
    /// depth counter, so a deep enough reply overflows the stack *before* a single value
    /// reaches this function. The crate's half is bounded in
    /// [`response_guard`](super::response_guard), which screens the response bytes for size
    /// and nesting depth before the parser is allowed to touch them. Both bounds are needed:
    /// this one walks the values the parser produced, that one decides whether the parser gets
    /// to run at all.
    fn xmlrpc_value_to_json(value: &xmlrpc::Value) -> serde_json::Value {
        Self::xmlrpc_value_to_json_at(value, 0)
    }

    fn xmlrpc_value_to_json_at(value: &xmlrpc::Value, depth: usize) -> serde_json::Value {
        if depth >= MAX_VALUE_DEPTH {
            return serde_json::json!(format!(
                "<nesting deeper than {} levels was not decoded>",
                MAX_VALUE_DEPTH
            ));
        }
        match value {
            xmlrpc::Value::Int(i) => serde_json::json!(i),
            xmlrpc::Value::Int64(i) => serde_json::json!(i),
            xmlrpc::Value::Bool(b) => serde_json::json!(b),
            xmlrpc::Value::String(s) => serde_json::json!(s),
            xmlrpc::Value::Double(f) => serde_json::json!(f),
            xmlrpc::Value::DateTime(dt) => serde_json::json!(dt.to_string()),
            xmlrpc::Value::Base64(b) => {
                // Convert to base64 string for JSON
                serde_json::json!(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b
                ))
            }
            xmlrpc::Value::Array(arr) => {
                let json_arr: Vec<_> = arr
                    .iter()
                    .map(|v| Self::xmlrpc_value_to_json_at(v, depth + 1))
                    .collect();
                serde_json::json!(json_arr)
            }
            xmlrpc::Value::Struct(s) => {
                let mut obj = serde_json::Map::new();
                for (key, value) in s {
                    obj.insert(key.clone(), Self::xmlrpc_value_to_json_at(value, depth + 1));
                }
                serde_json::json!(obj)
            }
            xmlrpc::Value::Nil => serde_json::Value::Null,
        }
    }
}
