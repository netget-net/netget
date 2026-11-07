//! SQS client implementation
pub mod actions;

pub use actions::SqsClientProtocol;

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_sqs::types::{MessageAttributeValue, QueueAttributeName};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::sqs::actions::{
    SQS_CLIENT_CONNECTED_EVENT, SQS_MESSAGE_RECEIVED_EVENT, SQS_MESSAGE_SENT_EVENT,
};
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

/// Turn the address the operator actually named into an endpoint the AWS SDK will use.
///
/// Without this, an `SqsClient` whose `remote_addr` is set and whose `endpoint_url` startup
/// parameter is not lets `aws_sdk_sqs` resolve its own default — `https://sqs.<region>.amazonaws.com`
/// — and sign the request with whatever ambient credentials the machine has. A client the
/// operator pointed at localhost then issued **real queue operations against real AWS**.
///
/// That is not hypothetical: it is exactly the DynamoDB defect this repository already fixed,
/// in the next AWS client along. `tests/vendor_default_fallback_test.rs` is the ratchet that
/// found it, and exists so there is not a third.
fn endpoint_url_from_remote_addr(remote_addr: &str) -> Option<String> {
    let trimmed = remote_addr.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Some(trimmed.to_string())
    } else {
        Some(format!("http://{trimmed}"))
    }
}

/// SQS client that connects to an AWS SQS queue
pub struct SqsClient;

/// How many times an answer may provoke another answer.
///
/// `execute_actions -> apply_action -> send_message/receive_messages ->
/// spawn_event_notification -> execute_actions` is a genuine cycle: the model is told a
/// message was sent, and may answer by sending another. Boxing the recursive call made it
/// compile and nothing bounded it, so a model that answers `sqs_message_sent` with another
/// `send_message` loops forever, one AWS call and one LLM call per turn. The root
/// `CLAUDE.md` prescribes the fix: a depth bound, not silence — the chain is allowed to be
/// useful and then stops.
const MAX_FOLLOWUP_DEPTH: u8 = 4;

impl SqsClient {
    /// Connect to an SQS queue with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract startup parameters
        let queue_url = startup_params
            .as_ref()
            .map(|p| p.get_string("queue_url"))
            .transpose()?
            .context("Missing required 'queue_url' parameter")?;

        let region = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("region"))
            .transpose()?
            .flatten();
        // The SDK builds `https://sqs.<region>.amazonaws.com` from this; see `aws_support`.
        if let Some(region) = &region {
            crate::client::aws_support::validate_region("SQS", region)?;
        }

        let endpoint_url = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("endpoint_url"))
            .transpose()?
            .flatten();

        // An explicit `endpoint_url` wins; otherwise the address the operator named decides.
        // The parameter used to be `_remote_addr` and was read nowhere, so neither did.
        let endpoint_url = endpoint_url.or_else(|| endpoint_url_from_remote_addr(&remote_addr));

        let access_key_id = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("access_key_id"))
            .transpose()?
            .flatten();

        let secret_access_key = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("secret_access_key"))
            .transpose()?
            .flatten();

        // A custom endpoint and no credentials would sign with the operator's ambient AWS
        // identity against a host the model may have chosen; see `aws_support`.
        crate::client::aws_support::refuse_ambient_credentials(
            "SQS",
            endpoint_url.as_deref(),
            access_key_id.is_some() && secret_access_key.is_some(),
        )?;

        info!(
            "SQS client {} connecting to queue: {}",
            client_id, queue_url
        );

        // Configure AWS SDK
        let mut config_loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(reg) = &region {
            config_loader = config_loader.region(aws_config::Region::new(reg.clone()));
        }

        // Explicit credentials when the caller supplied them. Without this the SDK's default
        // chain runs — environment, `~/.aws/credentials`, then IMDS — so a client the model
        // created signed with the operator's real AWS identity, with no way to scope it, and
        // on a machine with no credentials the connect additionally paid for an IMDS probe
        // that cannot succeed off EC2.
        let config = config_loader.load().await;

        // Build SQS client
        let mut sqs_builder = aws_sdk_sqs::config::Builder::from(&config);

        if let Some(endpoint) = &endpoint_url {
            sqs_builder = sqs_builder.endpoint_url(endpoint);
        }

        // Explicit credentials when the caller supplied them, overriding whatever the
        // default chain loaded. Without this a client the model created signed with the
        // operator's real AWS identity - environment, ~/.aws/credentials or an instance
        // role - and nothing in the protocol let the caller scope it.
        if let (Some(key_id), Some(secret)) = (&access_key_id, &secret_access_key) {
            sqs_builder = sqs_builder.credentials_provider(aws_sdk_sqs::config::Credentials::new(
                key_id.clone(),
                secret.clone(),
                None, // session token
                None, // expiry
                "netget_sqs_client",
            ));
        }

        let sqs_config = sqs_builder.build();
        let sqs = aws_sdk_sqs::Client::from_conf(sqs_config);

        // Update client status to connected
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] SQS client {} connected to {}",
            client_id, queue_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        info!("SQS client {} connected", client_id);

        let protocol = Arc::new(SqsClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered BEFORE the connected-event LLM call below: a dashboard-created
        // client defaults to a `*` -> manual routing rule, which parks that call until
        // a human answers, and [ send ] has to work for the whole park. It is also the
        // only long-lived task this client has ever had - `connect` used to return with
        // nothing running, so nothing could act on the queue afterwards.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            sqs.clone(),
            queue_url.clone(),
            protocol.clone(),
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Ask the model about the connection from a registered task, not inline.
        //
        // A dashboard-created client defaults to a `*` -> manual routing rule, which parks
        // this call until a human answers or `timeout_secs` (default 300) expires. Awaiting
        // it here meant `ClientForm::create` blocked for up to five minutes on a client the
        // operator had just asked for. The command channel is already registered above, so
        // `[ send ]` works throughout the park — that was anticipated; moving the park off
        // the creation path was not.
        let conn_sqs = sqs.clone();
        let conn_queue = queue_url.clone();
        let conn_protocol = protocol.clone();
        let conn_llm = llm_client.clone();
        let conn_state = app_state.clone();
        let conn_status = status_tx.clone();
        let conn_task = tokio::spawn(async move {
            let event = Event::new(
                &SQS_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "queue_url": conn_queue.clone(),
                }),
            );

            let Some(instruction) = conn_state.get_instruction_for_client(client_id).await else {
                return;
            };
            let memory = conn_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &conn_llm,
                &conn_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                conn_protocol.as_ref(),
                &conn_status,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        conn_state.set_memory_for_client(client_id, mem).await;
                    }

                    if let Err(e) = Self::execute_actions(
                        actions,
                        &conn_sqs,
                        &conn_queue,
                        conn_protocol.clone(),
                        &conn_llm,
                        &conn_state,
                        &conn_status,
                        client_id,
                        0,
                    )
                    .await
                    {
                        error!(
                            "SQS client {} connect-time actions failed: {}",
                            client_id, e
                        );
                    }
                }
                Err(e) => {
                    error!("LLM error for SQS client {}: {}", client_id, e);
                }
            }
        });
        app_state.register_client_task(client_id, conn_task).await;

        // Return a dummy local address (SQS is HTTP-based, no real socket)
        // Use localhost with client_id as port for uniqueness
        // A placeholder: SQS is HTTP and this client owns no socket. Wrapped into the
        // ephemeral range rather than added, because `10000 + client_id` leaves u16 once
        // the id passes 55535 and the parse then failed *after* the command loop was
        // already registered — leaving a running task behind a client marked Error.
        let dummy_port = 10_000u16.wrapping_add((client_id.as_u32() % 50_000) as u16);
        let dummy_addr: SocketAddr = format!("127.0.0.1:{dummy_port}")
            .parse()
            .context("Failed to create dummy socket address")?;

        Ok(dummy_addr)
    }

    /// Execute SQS actions from LLM
    #[allow(clippy::too_many_arguments)]
    fn execute_actions<'a>(
        actions: Vec<serde_json::Value>,
        sqs: &'a aws_sdk_sqs::Client,
        queue_url: &'a str,
        protocol: Arc<SqsClientProtocol>,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        client_id: ClientId,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for action in actions {
                let result = match protocol.execute_action(action) {
                    Ok(result) => result,
                    Err(e) => {
                        error!("SQS client {} rejected action: {}", client_id, e);
                        continue;
                    }
                };
                let outcome = Self::apply_action(
                    result,
                    &sqs,
                    queue_url,
                    protocol.clone(),
                    llm_client,
                    app_state,
                    status_tx,
                    client_id,
                    depth,
                )
                .await;
                if matches!(outcome, ClientSendOutcome::Disconnected) {
                    info!("SQS client {} disconnecting", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    app_state.remove_client_handle(client_id).await;
                    let _ =
                        status_tx.send(format!("[CLIENT] SQS client {} disconnected", client_id));
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    break;
                }
                debug!("SQS client {} action outcome: {:?}", client_id, outcome);
            }
            Ok(())
        })
    }

    /// Apply one executed action against the queue. Shared by the connected-event
    /// LLM path, by response follow-ups, and by injected commands, so the three
    /// cannot diverge.
    ///
    /// The AWS SDK owns the socket and reports no wire byte count, so a completed
    /// operation is `Executed { detail }` naming the operation and its result -
    /// never `Sent`, which would be a fabricated byte count.
    #[allow(clippy::too_many_arguments)]
    fn apply_action<'a>(
        result: ClientActionResult,
        sqs: &'a aws_sdk_sqs::Client,
        queue_url: &'a str,
        protocol: Arc<SqsClientProtocol>,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        client_id: ClientId,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ClientSendOutcome> + Send + 'a>> {
        Box::pin(async move {
            match result {
                ClientActionResult::Custom { name, data } => {
                    let outcome = match name.as_str() {
                        "send_message" => {
                            Self::send_message(
                                sqs,
                                queue_url,
                                &data,
                                protocol.clone(),
                                llm_client,
                                app_state,
                                status_tx,
                                client_id,
                                depth,
                            )
                            .await
                        }
                        "receive_messages" => {
                            Self::receive_messages(
                                sqs,
                                queue_url,
                                &data,
                                protocol.clone(),
                                llm_client,
                                app_state,
                                status_tx,
                                client_id,
                                depth,
                            )
                            .await
                        }
                        "delete_message" => {
                            Self::delete_message(sqs, queue_url, &data, client_id).await
                        }
                        "purge_queue" => Self::purge_queue(sqs, queue_url, client_id).await,
                        "get_queue_attributes" => {
                            Self::get_queue_attributes(sqs, queue_url, &data, client_id).await
                        }
                        other => Err(anyhow::anyhow!("Unknown SQS operation: {}", other)),
                    };
                    match outcome {
                        Ok(value) => ClientSendOutcome::Executed {
                            detail: format!(
                                "{} completed: {}",
                                name,
                                truncate_for_log(&value.to_string(), 200)
                            ),
                        },
                        Err(e) => {
                            Log::to(&status_tx).error(format!(
                                "SQS client {} operation {} failed: {}",
                                client_id, name, e
                            ));
                            // A failed operation is `Rejected`, not `Executed`: both used to
                            // be `Executed`, so a refusal and a completed send rendered the
                            // same way in the dashboard.
                            ClientSendOutcome::Rejected {
                                error: format!(
                                    "{} failed: {}",
                                    name,
                                    truncate_for_log(&e.to_string(), 200)
                                ),
                            }
                        }
                    }
                }
                ClientActionResult::Disconnect => ClientSendOutcome::Disconnected,
                ClientActionResult::WaitForMore => ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                },
                ClientActionResult::NoAction => ClientSendOutcome::Executed {
                    detail: "no_action".to_string(),
                },
                ClientActionResult::SendData(_) => ClientSendOutcome::Executed {
                    detail: "send_data has no meaning for the SQS client: it speaks the SQS API \
                             through the AWS SDK, not a socket this client owns"
                        .to_string(),
                },
                ClientActionResult::Multiple(_) => ClientSendOutcome::Executed {
                    detail:
                        "the SQS client's own verbs never produce Multiple; nothing was applied"
                            .to_string(),
                },
            }
        })
    }

    /// Drain injected commands until the channel closes (the client was removed) or
    /// an injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// every SQS verb yields `ClientActionResult::Custom` and there is no write half
    /// to put bytes on. Actions therefore go through [`Self::apply_action`] - the
    /// same function the LLM path uses - and the outcome is logged and replied
    /// exactly the way the generic arm does it.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        sqs: aws_sdk_sqs::Client,
        queue_url: String,
        protocol: Arc<SqsClientProtocol>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => ClientSendOutcome::Rejected {
                    error: e.to_string(),
                },
                Ok(result) => {
                    // Depth 0: an injected action is a fresh chain, whatever provoked
                    // the operator to send it.
                    Self::apply_action(
                        result,
                        &sqs,
                        &queue_url,
                        protocol.clone(),
                        &llm_client,
                        &app_state,
                        &status_tx,
                        client_id,
                        0,
                    )
                    .await
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
                info!("SQS client {} disconnecting on injected action", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }
        }

        info!("SQS client {} command loop stopped", client_id);
        // Never leave the dashboard offering [ send ] into a client that is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Send a message to the SQS queue
    #[allow(clippy::too_many_arguments)]
    async fn send_message(
        sqs: &aws_sdk_sqs::Client,
        queue_url: &str,
        data: &serde_json::Value,
        protocol: Arc<SqsClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
        depth: u8,
    ) -> Result<serde_json::Value> {
        let message_body = data
            .get("message_body")
            .and_then(|v| v.as_str())
            .context("Missing message_body")?;

        let mut request = sqs
            .send_message()
            .queue_url(queue_url)
            .message_body(message_body);

        // Add delay if specified
        if let Some(delay) = data.get("delay_seconds").and_then(|v| v.as_i64()) {
            // Clamped, not cast: `as i32` wraps silently. 0-900 is SQS's documented range.
            request = request.delay_seconds(delay.clamp(0, 900) as i32);
        }

        // Add message attributes if specified
        if let Some(attrs) = data.get("message_attributes").and_then(|v| v.as_object()) {
            for (key, value) in attrs {
                if let Some(value_str) = value.as_str() {
                    let msg_attr = MessageAttributeValue::builder()
                        .data_type("String")
                        .string_value(value_str)
                        .build()?;
                    request = request.message_attributes(key.clone(), msg_attr);
                }
            }
        }

        let response = request
            .send()
            .await
            .context("Failed to send message to SQS")?;

        let message_id = response.message_id().unwrap_or("unknown").to_string();
        info!("SQS client {} sent message: {}", client_id, message_id);

        // Raise the sent event (and run whatever the model answers with) from its own
        // registered task rather than inline. A dashboard-created client defaults to a
        // `*` -> manual routing rule, so this LLM call can park for minutes waiting for a
        // human; awaiting it here would wedge the command loop and make an injected action
        // that in fact succeeded look to the dashboard like a timeout.
        let event = Event::new(
            &SQS_MESSAGE_SENT_EVENT,
            serde_json::json!({
                "message_id": message_id,
            }),
        );
        Self::spawn_event_notification(
            event,
            sqs.clone(),
            queue_url.to_string(),
            protocol,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
            client_id,
            depth,
        )
        .await;

        Ok(serde_json::json!({ "message_id": message_id }))
    }

    /// Receive messages from the SQS queue
    #[allow(clippy::too_many_arguments)]
    async fn receive_messages(
        sqs: &aws_sdk_sqs::Client,
        queue_url: &str,
        data: &serde_json::Value,
        protocol: Arc<SqsClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
        depth: u8,
    ) -> Result<serde_json::Value> {
        let mut request = sqs.receive_message().queue_url(queue_url);

        // Set max messages (default 1, max 10)
        if let Some(max) = data.get("max_messages").and_then(|v| v.as_i64()) {
            request = request.max_number_of_messages(max.min(10).max(1) as i32);
        }

        // Set wait time for long polling (default 0, max 20)
        if let Some(wait) = data.get("wait_time_seconds").and_then(|v| v.as_i64()) {
            request = request.wait_time_seconds(wait.min(20).max(0) as i32);
        }

        // Set visibility timeout
        if let Some(timeout) = data.get("visibility_timeout").and_then(|v| v.as_i64()) {
            // Clamped, not cast: `as i32` wraps, so 4294967296 silently became 0 — an
            // instant-visibility timeout the model never asked for. 0-43200 is SQS's range.
            request = request.visibility_timeout(timeout.clamp(0, 43_200) as i32);
        }

        let response = request
            .send()
            .await
            .context("Failed to receive messages from SQS")?;

        let messages = response.messages();
        let message_count = messages.len();
        let received_ids: Vec<String> = messages
            .iter()
            .map(|m| m.message_id().unwrap_or("").to_string())
            .collect();
        info!(
            "SQS client {} received {} messages",
            client_id, message_count
        );

        // The event fires even for an empty poll. It used to be raised only when something
        // came back, so a "drain the queue" instruction stopped dead at the first empty
        // response with no way for the model to learn why — short polling returns nothing
        // most of the time, so that was the normal case, not the edge case.
        {
            // Build messages array for LLM
            let messages_json: Vec<serde_json::Value> = messages
                .iter()
                .map(|msg| {
                    // Convert attributes to JSON-serializable format
                    let attributes: std::collections::HashMap<String, String> = msg
                        .attributes()
                        .map(|attrs| {
                            attrs
                                .iter()
                                .map(|(k, v)| (k.as_str().to_string(), v.clone()))
                                .collect()
                        })
                        .unwrap_or_default();

                    let message_attributes: std::collections::HashMap<String, String> = msg
                        .message_attributes()
                        .map(|attrs| {
                            attrs
                                .iter()
                                .map(|(k, v)| {
                                    (k.clone(), v.string_value().unwrap_or("").to_string())
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    serde_json::json!({
                        "message_id": msg.message_id().unwrap_or(""),
                        "receipt_handle": msg.receipt_handle().unwrap_or(""),
                        "body": msg.body().unwrap_or(""),
                        "attributes": attributes,
                        "message_attributes": message_attributes,
                    })
                })
                .collect();

            // Call LLM with received messages
            let event = Event::new(
                &SQS_MESSAGE_RECEIVED_EVENT,
                serde_json::json!({
                    "messages": messages_json,
                }),
            );

            // Spawned for the same reason as in `send_message`: a manual routing rule can
            // park this call, and the command loop must not be held for it.
            Self::spawn_event_notification(
                event,
                sqs.clone(),
                queue_url.to_string(),
                protocol,
                llm_client.clone(),
                app_state.clone(),
                status_tx.clone(),
                client_id,
                depth,
            )
            .await;
        }

        Ok(serde_json::json!({
            "count": message_count,
            "message_ids": received_ids,
        }))
    }

    /// Raise one client event off the caller's task, and run whatever the model answers
    /// with through the normal action path. Never awaited by a caller that holds the
    /// command loop: an event handler may park this call for a human answer.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_event_notification(
        event: Event,
        sqs: aws_sdk_sqs::Client,
        queue_url: String,
        protocol: Arc<SqsClientProtocol>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        depth: u8,
    ) {
        // The cycle stops here rather than in the middle of an operation, so whatever
        // provoked this event has already completed and only the *next* round-trip is
        // refused. Nothing bounded it before: a model answering `sqs_message_sent` with
        // another `send_message` looped forever, one AWS call and one LLM call per turn.
        if depth >= MAX_FOLLOWUP_DEPTH {
            warn!(
                "SQS client {} stopping the follow-up chain at depth {} on {}: the model's \
                 answers have provoked {} rounds of events",
                client_id, depth, event.event_type.id, MAX_FOLLOWUP_DEPTH
            );
            let _ = status_tx.send(format!(
                "[CLIENT] SQS client {client_id} follow-up chain capped at \
                 {MAX_FOLLOWUP_DEPTH} rounds"
            ));
            return;
        }

        let registrar = app_state.clone();
        let handle = tokio::spawn(async move {
            // No instruction means the client has no model persona to consult; that is a
            // configuration, not a failure, so it stays quiet by design.
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                debug!(
                    "SQS client {} has no instruction; not asking the model about {}",
                    client_id, event.event_type.id
                );
                return;
            };
            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            // Logged, not swallowed. This was a `let ... else { return }`, so an LLM
            // outage, a budget refusal or a fail-closed manual timeout on
            // `sqs_message_received` produced no error!, no status line and nothing in the
            // log — the model was asked, the call failed, and the client simply went quiet.
            let (actions, memory_updates) = match call_llm_for_client(
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
                }) => (actions, memory_updates),
                Err(e) => {
                    error!(
                        "SQS client {} LLM error on {}: {}",
                        client_id, event.event_type.id, e
                    );
                    return;
                }
            };

            if let Some(mem) = memory_updates {
                app_state.set_memory_for_client(client_id, mem).await;
            }

            if let Err(e) = Self::execute_actions(
                actions,
                &sqs,
                &queue_url,
                protocol,
                &llm_client,
                &app_state,
                &status_tx,
                client_id,
                depth + 1,
            )
            .await
            {
                error!("SQS client {} follow-up actions failed: {}", client_id, e);
            }
        });
        registrar.register_client_task(client_id, handle).await;
    }

    /// Delete a message from the queue
    async fn delete_message(
        sqs: &aws_sdk_sqs::Client,
        queue_url: &str,
        data: &serde_json::Value,
        client_id: ClientId,
    ) -> Result<serde_json::Value> {
        let receipt_handle = data
            .get("receipt_handle")
            .and_then(|v| v.as_str())
            .context("Missing receipt_handle")?;

        sqs.delete_message()
            .queue_url(queue_url)
            .receipt_handle(receipt_handle)
            .send()
            .await
            .context("Failed to delete message from SQS")?;

        info!("SQS client {} deleted message", client_id);
        Ok(serde_json::json!({ "deleted": true }))
    }

    /// Purge all messages from the queue
    async fn purge_queue(
        sqs: &aws_sdk_sqs::Client,
        queue_url: &str,
        client_id: ClientId,
    ) -> Result<serde_json::Value> {
        sqs.purge_queue()
            .queue_url(queue_url)
            .send()
            .await
            .context("Failed to purge SQS queue")?;

        info!("SQS client {} purged queue", client_id);
        Ok(serde_json::json!({ "purged": true }))
    }

    /// Get queue attributes
    async fn get_queue_attributes(
        sqs: &aws_sdk_sqs::Client,
        queue_url: &str,
        data: &serde_json::Value,
        client_id: ClientId,
    ) -> Result<serde_json::Value> {
        let mut request = sqs.get_queue_attributes().queue_url(queue_url);

        // Add specific attributes if requested
        if let Some(attr_names) = data.get("attribute_names").and_then(|v| v.as_array()) {
            for attr in attr_names {
                if let Some(attr_str) = attr.as_str() {
                    // Convert string to QueueAttributeName enum
                    match attr_str {
                        "ApproximateNumberOfMessages" => {
                            request = request
                                .attribute_names(QueueAttributeName::ApproximateNumberOfMessages);
                        }
                        "QueueArn" => {
                            request = request.attribute_names(QueueAttributeName::QueueArn);
                        }
                        _ => {
                            request = request.attribute_names(QueueAttributeName::from(attr_str));
                        }
                    }
                }
            }
        } else {
            // Request all attributes
            request = request.attribute_names(QueueAttributeName::All);
        }

        let response = request
            .send()
            .await
            .context("Failed to get queue attributes from SQS")?;

        let attributes: std::collections::HashMap<String, String> = response
            .attributes()
            .map(|attrs| {
                attrs
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        info!(
            "SQS client {} got queue attributes: {:?}",
            client_id, attributes
        );
        Ok(serde_json::json!({ "attributes": attributes }))
    }
}
