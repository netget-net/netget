//! S3 client implementation
pub mod actions;

pub use actions::S3ClientProtocol;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::s3::actions::S3_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::utils::truncate::truncate_for_log;

/// Give a bare `host:port` a scheme. The AWS SDK requires an absolute URL, and an operator
/// typing an address into the dashboard does not type one.
fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

/// S3 client that interacts with AWS S3 or S3-compatible services
pub struct S3Client;

impl S3Client {
    /// Connect to an S3 service with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        _llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        info!("S3 client {} initializing for {}", client_id, remote_addr);

        // Read the four parameters this protocol declares. They are read here, from
        // `ctx.startup_params`, because there is nowhere else they could come from: the
        // values used to be read out of `protocol_data`, which nothing populates before
        // connect — `client_startup.rs` builds the instance with `protocol_data: Null` and
        // the only writer is the block below, which runs *after* this read. So every S3
        // client signed with `Credentials::new("", "", ...)`, was pinned to `us-east-1`,
        // and could never use a custom endpoint, while the protocol advertised all four and
        // marked two of them required.
        let access_key_id = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("access_key_id"))
            .transpose()?
            .flatten()
            .unwrap_or_default();

        let secret_access_key = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("secret_access_key"))
            .transpose()?
            .flatten()
            .unwrap_or_default();

        let region = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("region"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "us-east-1".to_string());

        // `remote_addr` is the fallback endpoint, so an operator who typed an address gets a
        // client aimed at it; `endpoint_url` overrides when both are given.
        let endpoint_url = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("endpoint_url"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| remote_addr.clone());

        // Build AWS SDK configuration
        use aws_config::BehaviorVersion;
        use aws_sdk_s3::config::{Credentials, Region};

        let creds = Credentials::new(
            &access_key_id,
            &secret_access_key,
            None, // session token
            None, // expiry
            "netget-s3-client",
        );

        let mut config_builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .credentials_provider(creds);

        // Set the endpoint whenever there is one. The old guard was
        // `endpoint_url != remote_addr`, which could never be true once `endpoint_url`
        // defaults to `remote_addr` — and was never true before either, because
        // `endpoint_url` was always the `remote_addr` fallback.
        if !endpoint_url.is_empty() {
            config_builder = config_builder.endpoint_url(normalize_endpoint(&endpoint_url));
        }

        // Built to prove the configuration is usable before the client is reported
        // connected; each operation builds its own from the same stored fields.
        let config = config_builder.build();
        let _ = aws_sdk_s3::Client::from_conf(config);

        // Store client metadata
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "s3_client_initialized".to_string(),
                    serde_json::json!(true),
                );
                client.set_protocol_field("endpoint".to_string(), serde_json::json!(endpoint_url));
                client.set_protocol_field("region".to_string(), serde_json::json!(region));
                client.set_protocol_field(
                    "access_key_id".to_string(),
                    serde_json::json!(access_key_id),
                );
                client.set_protocol_field(
                    "secret_access_key".to_string(),
                    serde_json::json!(secret_access_key),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] S3 client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered BEFORE the connected-event LLM call below: a dashboard-created
        // client defaults to a `*` -> manual routing rule, which parks that call until
        // a human answers, and [ send ] has to work for the whole park.
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

        // Call LLM initially with connected event
        let remote_addr_clone = remote_addr.clone();
        let llm_client_clone = _llm_client.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let region_clone = region.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            use crate::client::s3::actions::S3_CLIENT_CONNECTED_EVENT;

            // Get initial instruction
            let instruction = match app_state_clone.get_instruction_for_client(client_id).await {
                Some(instr) => instr,
                None => {
                    error!("S3 client {} has no instruction", client_id);
                    return;
                }
            };

            let protocol = Arc::new(crate::client::s3::actions::S3ClientProtocol::new());
            let event = Event::new(
                &S3_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "endpoint": remote_addr_clone,
                    "region": region_clone,
                }),
            );

            let memory = app_state_clone
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client_clone,
                &app_state_clone,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
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

                    // Execute actions through the same path injected commands use.
                    for action in actions {
                        let result = match protocol.execute_action(action) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("S3 client {} action error: {}", client_id, e);
                                continue;
                            }
                        };
                        let outcome = Self::apply_action(
                            result,
                            client_id,
                            &app_state_clone,
                            &llm_client_clone,
                            &status_tx_clone,
                        )
                        .await;
                        match outcome {
                            ClientSendOutcome::Disconnected => {
                                info!("S3 client {} disconnecting", client_id);
                                app_state_clone
                                    .update_client_status(client_id, ClientStatus::Disconnected)
                                    .await;
                                app_state_clone.remove_client_handle(client_id).await;
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                return;
                            }
                            other => debug!("S3 client {} connect action: {:?}", client_id, other),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for S3 client {}: {}", client_id, e);
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return a dummy local address (S3 is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Execute an S3 operation, returning the operation's own JSON result so the
    /// caller can report what actually happened (the command loop puts it in the
    /// `ClientSendOutcome` detail).
    /// Build a client and run one operation. Raises no event, calls no LLM.
    ///
    /// Deliberately free of any path back into `notify_response`: that would make the async
    /// type self-referential (notify -> apply -> operation -> notify), which rustc cannot
    /// prove `Send`, so `tokio::spawn` refuses it. Follow-up actions the model returns for a
    /// response event run through here, which breaks that cycle and bounds the loop -- a
    /// follow-up cannot raise another response event.
    pub async fn run_operation_once(
        client_id: ClientId,
        operation_name: &str,
        operation_data: serde_json::Value,
        app_state: &Arc<AppState>,
    ) -> Result<serde_json::Value> {
        info!(
            "S3 client {} executing operation: {}",
            client_id, operation_name
        );

        // Get S3 client configuration
        let (endpoint_url, region, access_key_id, secret_access_key) = app_state
            .with_client_mut(client_id, |client| {
                let endpoint = client
                    .get_protocol_field("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let region = client
                    .get_protocol_field("region")
                    .and_then(|v| v.as_str())
                    .unwrap_or("us-east-1")
                    .to_string();

                let access_key = client
                    .get_protocol_field("access_key_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let secret_key = client
                    .get_protocol_field("secret_access_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                (endpoint, region, access_key, secret_key)
            })
            .await
            .unwrap_or_else(|| {
                (
                    String::new(),
                    "us-east-1".to_string(),
                    String::new(),
                    String::new(),
                )
            });

        // Build AWS SDK client
        use aws_config::BehaviorVersion;
        use aws_sdk_s3::config::{Credentials, Region};

        let creds = Credentials::new(
            &access_key_id,
            &secret_access_key,
            None,
            None,
            "netget-s3-client",
        );

        let mut config_builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .credentials_provider(creds);

        if !endpoint_url.is_empty() {
            config_builder = config_builder.endpoint_url(&endpoint_url);
        }

        let config = config_builder.build();
        let s3_client = aws_sdk_s3::Client::from_conf(config);

        // Execute the operation
        let result = match operation_name {
            "s3_put_object" => Self::put_object(&s3_client, operation_data).await,
            "s3_get_object" => Self::get_object(&s3_client, operation_data).await,
            "s3_list_buckets" => Self::list_buckets(&s3_client).await,
            "s3_list_objects" => Self::list_objects(&s3_client, operation_data).await,
            "s3_delete_object" => Self::delete_object(&s3_client, operation_data).await,
            "s3_head_object" => Self::head_object(&s3_client, operation_data).await,
            "s3_create_bucket" => Self::create_bucket(&s3_client, operation_data).await,
            "s3_delete_bucket" => Self::delete_bucket(&s3_client, operation_data).await,
            _ => Err(anyhow::anyhow!("Unknown S3 operation: {}", operation_name)),
        };

        result
    }

    pub async fn execute_operation(
        client_id: ClientId,
        operation_name: String,
        operation_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<serde_json::Value> {
        info!(
            "S3 client {} executing operation: {}",
            client_id, operation_name
        );

        let result =
            Self::run_operation_once(client_id, &operation_name, operation_data, &app_state).await;

        // Raise the response event from its own registered task rather than inline. A
        // dashboard-created client defaults to a `*` -> manual routing rule, so this LLM
        // call can park for minutes waiting for a human; awaiting it here would wedge the
        // command loop and make an injected action that in fact succeeded look to the
        // dashboard like a timeout.
        let event_data = match &result {
            Ok(response_data) => serde_json::json!({
                "operation": operation_name,
                "success": true,
                "result": response_data,
            }),
            Err(e) => serde_json::json!({
                "operation": operation_name,
                "success": false,
                "error": e.to_string(),
            }),
        };
        let notify = tokio::spawn(Self::notify_response(
            client_id,
            event_data,
            app_state.clone(),
            llm_client,
            status_tx,
        ));
        app_state.register_client_task(client_id, notify).await;

        result
    }

    /// Apply one executed action against the S3 API. Shared by the connected-event
    /// LLM path and by injected commands, so the two cannot diverge.
    ///
    /// The AWS SDK owns the socket and reports no wire byte count, so a completed
    /// operation is `Executed { detail }` naming the operation and its result -
    /// never `Sent`, which would be a fabricated byte count.
    async fn apply_action(
        result: ClientActionResult,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> ClientSendOutcome {
        match result {
            ClientActionResult::Custom { name, data } => {
                match Self::execute_operation(
                    client_id,
                    name.clone(),
                    data,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
                {
                    Ok(value) => ClientSendOutcome::Executed {
                        detail: format!(
                            "{} completed: {}",
                            name,
                            truncate_for_log(&value.to_string(), 200)
                        ),
                    },
                    Err(e) => {
                        Log::to(&status_tx).error(format!(
                            "S3 client {} operation {} failed: {}",
                            client_id, name, e
                        ));
                        // A failed operation is `Rejected`, not `Executed`: both used to be
                        // `Executed`, so a refusal and a completed write rendered the same
                        // way in the dashboard.
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
                detail: "send_data has no meaning for the S3 client: it speaks the S3 REST API \
                         through the AWS SDK, not a socket this client owns"
                    .to_string(),
            },
            ClientActionResult::Multiple(_) => ClientSendOutcome::Executed {
                detail: "the S3 client's own verbs never produce Multiple; nothing was applied"
                    .to_string(),
            },
        }
    }

    /// Drain injected commands until the channel closes (the client was removed)
    /// or an injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// every S3 verb yields `ClientActionResult::Custom` and there is no write half
    /// to put bytes on. The action therefore goes through [`Self::apply_action`] -
    /// the same function the LLM path uses - and the outcome is logged and replied
    /// exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::s3::actions::S3ClientProtocol::new();

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
                info!("S3 client {} disconnecting on injected action", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }
        }

        // Never leave the dashboard offering [ send ] into a client that is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Raise `s3_response_received` and fold in any memory update. Spawned, never
    /// awaited by a caller that holds the command loop: an event handler may park this
    /// call for a human answer.
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
        let protocol = crate::client::s3::actions::S3ClientProtocol::new();
        let event = Event::new(&S3_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);
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
            &protocol,
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

                // Execute what the model asked for. These were discarded, so answering
                // s3_response_received did nothing -- a model that listed a bucket and
                // wanted to fetch one of the objects it had just seen was ignored.
                //
                // Dispatch goes through `run_operation_once`, which raises no event: that
                // bounds the loop and keeps the async type non-recursive, which is what
                // tokio::spawn's Send bound requires.
                use crate::llm::actions::client_trait::{Client, ClientActionResult};
                let protocol = crate::client::s3::actions::S3ClientProtocol::new();
                for action in actions {
                    // Every arm is accounted for. This was a `let ... else { continue }`,
                    // which dropped `Disconnect` — the answer this protocol's own
                    // static-mode startup example prescribes — and every executor error,
                    // with no log line at all.
                    let (name, data) = match protocol.execute_action(action.clone()) {
                        Ok(ClientActionResult::Custom { name, data }) => (name, data),
                        Ok(ClientActionResult::Disconnect) => {
                            info!(
                                "S3 client {} disconnecting: the model answered the response \
                                 event with `disconnect`",
                                client_id
                            );
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            app_state.remove_client_handle(client_id).await;
                            let _ = status_tx
                                .send(format!("[CLIENT] S3 client {client_id} disconnected"));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return;
                        }
                        Ok(other) => {
                            info!(
                                "S3 client {} follow-up action {:?} needs no S3 operation",
                                client_id, other
                            );
                            continue;
                        }
                        Err(e) => {
                            error!(
                                "S3 client {} could not execute follow-up action {}: {}",
                                client_id, action, e
                            );
                            continue;
                        }
                    };
                    match Self::run_operation_once(client_id, &name, data, &app_state).await {
                        Ok(v) => info!(
                            "S3 client {} follow-up {} -> {}",
                            client_id,
                            name,
                            crate::utils::truncate_for_log(&v.to_string(), 120)
                        ),
                        Err(e) => {
                            error!("S3 client {} follow-up {} failed: {}", client_id, name, e)
                        }
                    }
                }
            }
            Err(e) => {
                error!("LLM error for S3 client {}: {}", client_id, e);
            }
        }
    }

    async fn put_object(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;
        let key = data["key"].as_str().context("Missing key")?;
        let body = data["body"].as_str().context("Missing body")?;
        let content_type = data["content_type"].as_str();

        // The `body` parameter was documented as "text or base64 for binary" while this did
        // `body.as_bytes()`, so a model following the documentation stored the literal base64
        // ASCII in the object. Sniffing is not an option - a string can be valid text and
        // valid base64 at once, and only the sender knows which it means - so the encoding is
        // explicit, exactly as `send_tcp_data` was fixed.
        let body_bytes = match data["encoding"].as_str().unwrap_or("utf8") {
            "utf8" => body.as_bytes().to_vec(),
            "base64" => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .context(
                        "put_object was given encoding=\"base64\" but `body` is not valid \
                         base64. Send the bytes as base64, or set encoding=\"utf8\" to store \
                         the text as written.",
                    )?
            }
            other => anyhow::bail!(
                "Unknown encoding {:?} for put_object; use \"utf8\" (default) or \"base64\"",
                other
            ),
        };

        let mut request = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(body_bytes.into());

        if let Some(ct) = content_type {
            request = request.content_type(ct);
        }

        let response = request.send().await.context("Failed to put object")?;

        Ok(serde_json::json!({
            "bucket": bucket,
            "key": key,
            "etag": response.e_tag().unwrap_or(""),
        }))
    }

    async fn get_object(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;
        let key = data["key"].as_str().context("Missing key")?;

        let response = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .context("Failed to get object")?;

        let content_type = response
            .content_type()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let content_length = response.content_length().unwrap_or(0);

        let body_bytes = response
            .body
            .collect()
            .await
            .context("Failed to read object body")?
            .into_bytes();

        // Report which of the two `body` is, rather than lossily rendering bytes into
        // U+FFFD and losing them. That made the round trip impossible in both directions:
        // binary read back could not be written anywhere, and the model had no way to tell a
        // file containing a replacement character from one that had been mangled.
        let (body, body_encoding) = match std::str::from_utf8(&body_bytes) {
            Ok(text) => (text.to_string(), "utf8"),
            Err(_) => {
                use base64::Engine as _;
                (
                    base64::engine::general_purpose::STANDARD.encode(&body_bytes),
                    "base64",
                )
            }
        };

        Ok(serde_json::json!({
            "bucket": bucket,
            "key": key,
            "content_type": content_type,
            "content_length": content_length,
            "body": body,
            // Feed straight back into put_object's `encoding` to copy an object verbatim.
            "body_encoding": body_encoding,
        }))
    }

    async fn list_buckets(client: &aws_sdk_s3::Client) -> Result<serde_json::Value> {
        let response = client
            .list_buckets()
            .send()
            .await
            .context("Failed to list buckets")?;

        let buckets: Vec<serde_json::Value> = response
            .buckets()
            .iter()
            .map(|b| {
                serde_json::json!({
                    "name": b.name().unwrap_or(""),
                    "creation_date": b.creation_date()
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "buckets": buckets,
            "count": buckets.len(),
        }))
    }

    async fn list_objects(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;
        let prefix = data["prefix"].as_str();
        let max_keys = data["max_keys"].as_i64().map(|n| n as i32);

        let mut request = client.list_objects_v2().bucket(bucket);

        if let Some(p) = prefix {
            request = request.prefix(p);
        }

        if let Some(mk) = max_keys {
            request = request.max_keys(mk);
        }

        let response = request.send().await.context("Failed to list objects")?;

        let objects: Vec<serde_json::Value> = response
            .contents()
            .iter()
            .map(|obj| {
                serde_json::json!({
                    "key": obj.key().unwrap_or(""),
                    "size": obj.size().unwrap_or(0),
                    "last_modified": obj.last_modified()
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                    "etag": obj.e_tag().unwrap_or(""),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "bucket": bucket,
            "objects": objects,
            "count": objects.len(),
            "is_truncated": response.is_truncated(),
        }))
    }

    async fn delete_object(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;
        let key = data["key"].as_str().context("Missing key")?;

        client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .context("Failed to delete object")?;

        Ok(serde_json::json!({
            "bucket": bucket,
            "key": key,
            "deleted": true,
        }))
    }

    async fn head_object(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;
        let key = data["key"].as_str().context("Missing key")?;

        let response = client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .context("Failed to head object")?;

        Ok(serde_json::json!({
            "bucket": bucket,
            "key": key,
            "content_type": response.content_type().unwrap_or(""),
            "content_length": response.content_length().unwrap_or(0),
            "etag": response.e_tag().unwrap_or(""),
            "last_modified": response.last_modified()
                .map(|d| d.to_string())
                .unwrap_or_default(),
        }))
    }

    async fn create_bucket(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;

        client
            .create_bucket()
            .bucket(bucket)
            .send()
            .await
            .context("Failed to create bucket")?;

        Ok(serde_json::json!({
            "bucket": bucket,
            "created": true,
        }))
    }

    async fn delete_bucket(
        client: &aws_sdk_s3::Client,
        data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let bucket = data["bucket"].as_str().context("Missing bucket")?;

        client
            .delete_bucket()
            .bucket(bucket)
            .send()
            .await
            .context("Failed to delete bucket")?;

        Ok(serde_json::json!({
            "bucket": bucket,
            "deleted": true,
        }))
    }
}
