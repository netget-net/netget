//! IPP (Internet Printing Protocol) client implementation

pub mod actions;

pub use actions::IppClientProtocol;

use anyhow::{Context, Result};
use ipp::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::ipp::actions::IPP_CLIENT_CONNECTED_EVENT;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// One completed IPP operation.
///
/// Split out of the operations below so the injected-command loop can await the
/// IPP-over-HTTP round-trip - and report a truthful outcome - without also awaiting the LLM
/// call the `ipp_response_received` event triggers.
pub struct IppExchange {
    pub operation: &'static str,
    pub success: bool,
    pub summary: String,
    pub response_data: serde_json::Value,
}

/// What one executed action did.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
}

/// How an IPP operation is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the whole operation and return immediately. Used by the connected-event
    /// handler, which runs inline in `connect()` and must not block client creation.
    Spawn,
    /// Await the IPP exchange so the caller can report what actually happened, then raise
    /// the response event from its own registered task. Used by the injected-command loop,
    /// so a parked manual handler cannot wedge it for the length of a human's think time.
    Await,
}

/// IPP client that connects to remote IPP print servers
pub struct IppClient;

impl IppClient {
    /// Connect to an IPP print server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        printer_path: Option<String>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("IPP client {} initialized for {}", client_id, remote_addr);

        // Parse the remote address to construct IPP URI
        // IPP typically uses http://host:631/printers/printer-name format
        let base = if remote_addr.starts_with("http://") || remote_addr.starts_with("https://") {
            remote_addr.clone()
        } else if remote_addr.starts_with("ipp://") {
            // Convert ipp:// to http://
            remote_addr.replace("ipp://", "http://")
        } else {
            // Default to http:// with IPP default port 631
            format!("http://{}", remote_addr)
        };

        // The declared `printer_path` parameter, which nothing used to read. IPP addresses a
        // queue rather than a host, so this is what decides *which printer* is talked to.
        //
        // An address that already carries a path wins: the operator spelled the whole URI out,
        // and silently appending to it would produce `/printers/a/printers/b`. Joining is done
        // by hand rather than with a URL crate because the only thing being decided is one
        // slash, and pulling in a parser to decide it would be the larger change.
        let uri_str = match printer_path {
            Some(path) if !path_already_present(&base) => {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    path.trim_start_matches('/')
                )
            }
            _ => base,
        };

        // Store URI in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("ipp_uri".to_string(), serde_json::json!(uri_str));
                client
                    .set_protocol_field("ipp_client".to_string(), serde_json::json!("initialized"));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] IPP client {} ready for {}",
            client_id, uri_str
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered and *served* before the ipp_connected LLM call below: a
        // dashboard-created client defaults to a `*` -> manual routing rule, so that
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

        // Call LLM with ipp_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &IPP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "ipp_uri": uri_str.clone(),
                }),
            );

            let protocol = Arc::new(crate::client::ipp::actions::IppClientProtocol::new());

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(),
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Execute actions from LLM response
                    for action in result.actions {
                        match protocol.execute_action(action) {
                            Ok(ClientActionResult::Disconnect) => {
                                info!("LLM requested disconnect after connect");
                                app_state.remove_client_handle(client_id).await;
                                app_state
                                    .update_client_status(client_id, ClientStatus::Disconnected)
                                    .await;
                                return Ok("0.0.0.0:0".parse().unwrap());
                            }
                            Ok(applied) => {
                                // Dispatch::Spawn so connect() can return; the operation
                                // itself runs through the same apply_action the dashboard's
                                // injected commands use.
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
                                        info!("IPP client {} after connect: {}", client_id, detail)
                                    }
                                    Ok(Applied::Disconnect) => {
                                        info!("IPP client {} disconnecting", client_id)
                                    }
                                    Err(e) => error!("IPP operation failed: {}", e),
                                }
                            }
                            Err(e) => {
                                error!("IPP client {} rejected action: {}", client_id, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on ipp_connected event: {}", e);
                }
            }
        }

        // Return a dummy local address (IPP is HTTP-based, connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Send Get-Printer-Attributes and hand the response to the LLM.
    pub async fn get_printer_attributes(
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange =
            Self::perform_get_printer_attributes(client_id, &app_state, &status_tx).await?;
        Self::notify_response(client_id, exchange, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Send Get-Printer-Attributes only. No LLM involvement, so a caller can await this and
    /// know exactly what the printer answered.
    pub async fn perform_get_printer_attributes(
        client_id: ClientId,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<IppExchange> {
        let uri_str = Self::get_uri(app_state, client_id).await?;
        let uri: Uri = uri_str.parse().context("Invalid IPP URI")?;

        info!(
            "IPP client {} sending Get-Printer-Attributes to {}",
            client_id, uri
        );

        let operation = IppOperationBuilder::get_printer_attributes(uri.clone()).build();
        let client = AsyncIppClient::new(uri);

        match client.send(operation).await {
            Ok(response) => {
                let status_code = response.header().status_code();
                info!(
                    "IPP client {} received response: status={:?}",
                    client_id, status_code
                );

                // Extract printer attributes
                let mut attributes = serde_json::Map::new();
                if status_code.is_success() {
                    if let Some(printer_attrs) = response
                        .attributes()
                        .groups_of(DelimiterTag::PrinterAttributes)
                        .next()
                    {
                        for (_, attr) in printer_attrs.attributes() {
                            attributes.insert(
                                attr.name().to_string(),
                                serde_json::json!(attr.value().to_string()),
                            );
                        }
                    }
                }

                Ok(IppExchange {
                    operation: "get_printer_attributes",
                    success: status_code.is_success(),
                    summary: format!("{:?}, {} attribute(s)", status_code, attributes.len()),
                    response_data: serde_json::json!({
                        "status_code": format!("{:?}", status_code),
                        "attributes": attributes,
                    }),
                })
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "IPP client {} Get-Printer-Attributes failed: {}",
                    client_id, e
                ));
                Err(e.into())
            }
        }
    }

    /// Send Print-Job and hand the response to the LLM.
    pub async fn print_job(
        client_id: ClientId,
        job_name: String,
        document_format: Option<String>,
        document_data: Vec<u8>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_print_job(
            client_id,
            job_name,
            document_format,
            document_data,
            &app_state,
            &status_tx,
        )
        .await?;
        Self::notify_response(client_id, exchange, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Send Print-Job only. No LLM involvement.
    pub async fn perform_print_job(
        client_id: ClientId,
        job_name: String,
        document_format: Option<String>,
        document_data: Vec<u8>,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<IppExchange> {
        let uri_str = Self::get_uri(app_state, client_id).await?;
        let uri: Uri = uri_str.parse().context("Invalid IPP URI")?;

        info!(
            "IPP client {} sending Print-Job to {}: job={}, format={:?}, size={} bytes",
            client_id,
            uri,
            job_name,
            document_format,
            document_data.len()
        );

        // Build Print-Job operation
        // IppPayload needs a Read type, so we convert Vec<u8> to Cursor
        let document_len = document_data.len();
        let cursor = std::io::Cursor::new(document_data);
        let payload = IppPayload::new(cursor);

        let operation = IppOperationBuilder::print_job(uri.clone(), payload)
            .job_title(&job_name)
            .build();

        let client = AsyncIppClient::new(uri);

        match client.send(operation).await {
            Ok(response) => {
                let status_code = response.header().status_code();
                info!(
                    "IPP client {} Print-Job response: status={:?}",
                    client_id, status_code
                );

                // Extract job attributes
                let mut job_attrs = serde_json::Map::new();
                if status_code.is_success() {
                    if let Some(attrs) = response
                        .attributes()
                        .groups_of(DelimiterTag::JobAttributes)
                        .next()
                    {
                        for (_, attr) in attrs.attributes() {
                            job_attrs.insert(
                                attr.name().to_string(),
                                serde_json::json!(attr.value().to_string()),
                            );
                        }
                    }
                }

                Ok(IppExchange {
                    operation: "print_job",
                    success: status_code.is_success(),
                    summary: format!(
                        "{:?} for a {}-byte document, {} job attribute(s)",
                        status_code,
                        document_len,
                        job_attrs.len()
                    ),
                    response_data: serde_json::json!({
                        "status_code": format!("{:?}", status_code),
                        "job_name": job_name,
                        "job_attributes": job_attrs,
                    }),
                })
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("IPP client {} Print-Job failed: {}", client_id, e));
                Err(e.into())
            }
        }
    }

    /// Send Get-Job-Attributes and hand the response to the LLM.
    pub async fn get_job_attributes(
        client_id: ClientId,
        job_id: i32,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange =
            Self::perform_get_job_attributes(client_id, job_id, &app_state, &status_tx).await?;
        Self::notify_response(client_id, exchange, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Send Get-Job-Attributes only. No LLM involvement.
    pub async fn perform_get_job_attributes(
        client_id: ClientId,
        job_id: i32,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<IppExchange> {
        let uri_str = Self::get_uri(app_state, client_id).await?;
        let uri: Uri = uri_str.parse().context("Invalid IPP URI")?;

        info!(
            "IPP client {} sending Get-Job-Attributes to {}: job_id={}",
            client_id, uri, job_id
        );

        let operation = IppOperationBuilder::get_job_attributes(uri.clone(), job_id).build();
        let client = AsyncIppClient::new(uri);

        match client.send(operation).await {
            Ok(response) => {
                let status_code = response.header().status_code();
                info!(
                    "IPP client {} Get-Job-Attributes response: status={:?}",
                    client_id, status_code
                );

                // Extract job attributes
                let mut attributes = serde_json::Map::new();
                if status_code.is_success() {
                    if let Some(job_attrs) = response
                        .attributes()
                        .groups_of(DelimiterTag::JobAttributes)
                        .next()
                    {
                        for (_, attr) in job_attrs.attributes() {
                            attributes.insert(
                                attr.name().to_string(),
                                serde_json::json!(attr.value().to_string()),
                            );
                        }
                    }
                }

                Ok(IppExchange {
                    operation: "get_job_attributes",
                    success: status_code.is_success(),
                    summary: format!(
                        "job {}: {:?}, {} attribute(s)",
                        job_id,
                        status_code,
                        attributes.len()
                    ),
                    response_data: serde_json::json!({
                        "status_code": format!("{:?}", status_code),
                        "job_id": job_id,
                        "attributes": attributes,
                    }),
                })
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "IPP client {} Get-Job-Attributes failed: {}",
                    client_id, e
                ));
                Err(e.into())
            }
        }
    }

    /// Get IPP URI from client state
    async fn get_uri(app_state: &AppState, client_id: ClientId) -> Result<String> {
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("ipp_uri")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No IPP URI found in client state")
    }

    /// Hand a completed exchange to the LLM as an `ipp_response_received` event.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded (`actions: _`), so answering ipp_response_received did nothing at all --
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
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::ipp::actions::IppClientProtocol::new();
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            let outcome: Result<()> = match name.as_str() {
                "ipp_get_printer_attributes" => {
                    Self::perform_get_printer_attributes(client_id, app_state, status_tx)
                        .await
                        .map(|_| ())
                }
                "ipp_print_job" => Self::perform_print_job(
                    client_id,
                    data["job_name"].as_str().unwrap_or("netget").to_string(),
                    data["document_format"].as_str().map(|s| s.to_string()),
                    data["document_data"]
                        .as_str()
                        .map(|s| s.as_bytes().to_vec())
                        .unwrap_or_default(),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                "ipp_get_job_attributes" => Self::perform_get_job_attributes(
                    client_id,
                    data["job_id"].as_i64().unwrap_or(0) as i32,
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                other => {
                    info!(
                        "IPP client {} follow-up '{}' has no non-notifying path; skipped",
                        client_id, other
                    );
                    Ok(())
                }
            };
            if let Err(e) = outcome {
                error!("IPP client {} follow-up action failed: {}", client_id, e);
            }
        }
    }

    async fn notify_response(
        client_id: ClientId,
        exchange: IppExchange,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::ipp::actions::IppClientProtocol::new());
        let event = Event::new(
            &crate::client::ipp::actions::IPP_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "operation": exchange.operation,
                "success": exchange.success,
                "response": exchange.response_data,
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
            }
            Err(e) => {
                error!("LLM error for IPP client {}: {}", client_id, e);
            }
        }
    }

    /// Apply one already-parsed action against the live IPP client.
    ///
    /// The single place IPP actions become IPP-over-HTTP requests, so an action injected
    /// from the dashboard behaves exactly like one the model produced. Under
    /// [`Dispatch::Await`] only the **network** half is awaited; the response event - and
    /// the LLM call it makes - is raised from its own registered task afterwards, so a
    /// `*` -> manual routing rule parking that event cannot wedge the command loop for the
    /// length of a human's think time. The outcome stays truthful because it carries the
    /// IPP status the printer actually returned, which is known before the event is raised.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        dispatch: Dispatch,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        let (name, data) = match result {
            ClientActionResult::Custom { name, data } => (name, data),
            ClientActionResult::Disconnect => return Ok(Applied::Disconnect),
            ClientActionResult::NoAction => return Ok(Applied::Executed("no_action".to_string())),
            ClientActionResult::WaitForMore => {
                return Ok(Applied::Executed("wait_for_more".to_string()))
            }
            ClientActionResult::SendData(_) => {
                return Ok(Applied::Executed(
                    "IPP owns no socket; raw send_data cannot be put on the wire".to_string(),
                ))
            }
            ClientActionResult::Multiple(_) => {
                return Ok(Applied::Executed(
                    "IPP produces no Multiple results; nothing executed".to_string(),
                ))
            }
        };

        match name.as_str() {
            "ipp_get_printer_attributes" => match dispatch {
                Dispatch::Spawn => {
                    Self::spawn_operation(
                        client_id,
                        app_state,
                        Self::get_printer_attributes(
                            client_id,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        ),
                    )
                    .await;
                    Ok(Applied::Executed(
                        "Get-Printer-Attributes dispatched".to_string(),
                    ))
                }
                Dispatch::Await => {
                    let exchange =
                        Self::perform_get_printer_attributes(client_id, app_state, status_tx)
                            .await?;
                    let detail =
                        format!("Get-Printer-Attributes completed -> {}", exchange.summary);
                    Self::spawn_notify(client_id, app_state, exchange, llm_client, status_tx).await;
                    Ok(Applied::Executed(detail))
                }
            },
            "ipp_print_job" => {
                let job_name = data
                    .get("job_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled")
                    .to_string();
                let document_format = data
                    .get("document_format")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let document_data = match data.get("document_data") {
                    None => Vec::new(),
                    Some(value) => crate::client::wire_values::bytes(
                        value
                            .as_array()
                            .context("document_data must be a byte array")?,
                    )?,
                };

                match dispatch {
                    Dispatch::Spawn => {
                        let log_name = job_name.clone();
                        Self::spawn_operation(
                            client_id,
                            app_state,
                            Self::print_job(
                                client_id,
                                job_name,
                                document_format,
                                document_data,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "Print-Job {log_name:?} dispatched"
                        )))
                    }
                    Dispatch::Await => {
                        let log_name = job_name.clone();
                        let exchange = Self::perform_print_job(
                            client_id,
                            job_name,
                            document_format,
                            document_data,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail =
                            format!("Print-Job {log_name:?} completed -> {}", exchange.summary);
                        Self::spawn_notify(client_id, app_state, exchange, llm_client, status_tx)
                            .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            "ipp_get_job_attributes" => {
                let job_id = data.get("job_id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                match dispatch {
                    Dispatch::Spawn => {
                        Self::spawn_operation(
                            client_id,
                            app_state,
                            Self::get_job_attributes(
                                client_id,
                                job_id,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "Get-Job-Attributes for job {job_id} dispatched"
                        )))
                    }
                    Dispatch::Await => {
                        let exchange = Self::perform_get_job_attributes(
                            client_id, job_id, app_state, status_tx,
                        )
                        .await?;
                        let detail =
                            format!("Get-Job-Attributes completed -> {}", exchange.summary);
                        Self::spawn_notify(client_id, app_state, exchange, llm_client, status_tx)
                            .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            other => Ok(Applied::Executed(format!(
                "unknown IPP custom result '{other}' was not executed"
            ))),
        }
    }

    /// Run a whole operation (network + response event) as a registered background task.
    async fn spawn_operation(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        operation: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) {
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let handle = tokio::spawn(async move {
            // Small delay to ensure the printer is ready
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if let Err(e) = operation.await {
                error!("IPP client {} operation failed: {}", client_id, e);
            }
        });
        app_state.register_client_task(client_id, handle).await;
    }

    /// Raise the response event from its own registered task, so the caller does not wait
    /// on the LLM call (which a manual routing rule can park for the intercept timeout).
    async fn spawn_notify(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        exchange: IppExchange,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let state = app_state.clone();
        let llm = llm_client.clone();
        let tx = status_tx.clone();
        let handle = tokio::spawn(async move {
            Self::notify_response(client_id, exchange, state, llm, tx).await;
        });
        app_state.register_client_task(client_id, handle).await;
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
        let protocol = crate::client::ipp::actions::IppClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Never `Sent`: the `ipp` crate owns the HTTP request and does not report
                // how many bytes it serialised to, so a byte count here would be invented.
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
                Log::to(&status_tx).warn(format!(
                    "IPP client {} injected action failed: {}",
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

        info!("IPP client {} command loop finished", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Does this absolute URL already carry a path beyond `/`?
///
/// Used to decide whether the `printer_path` startup parameter applies. An operator who wrote
/// the whole URI out has already chosen the queue, and appending to it would produce
/// `/printers/a/printers/b`.
fn path_already_present(url: &str) -> bool {
    // Skip the scheme, then look for a `/` that starts a non-empty path.
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    match after_scheme.split_once('/') {
        Some((_, path)) => !path.is_empty(),
        None => false,
    }
}
