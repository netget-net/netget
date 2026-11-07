//! DynamoDB client implementation
pub mod actions;

pub use actions::DynamoDbClientProtocol;

use anyhow::{Context, Result};
use aws_smithy_types::Blob;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::dynamodb::actions::DYNAMODB_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::utils::truncate::truncate_for_log;

/// Turn a `host:port` (or already-schemed) target into an endpoint URL.
///
/// Returns `None` for an empty address, which is the only case where falling through to the
/// SDK's default AWS endpoint is what the caller asked for.
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

/// DynamoDB client that interacts with AWS DynamoDB or local instances
pub struct DynamoDbClient;

impl DynamoDbClient {
    /// Connect to a DynamoDB instance with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        _llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // All four parameters are declared `required: false`, so they must be read with
        // `get_optional_string`. They were read with `get_string`, which *errors* when the
        // key is absent — so passing any subset of them (the documented local-testing case
        // is `endpoint_url` alone) failed the connect outright with "Required string
        // parameter 'region' is missing". Only passing none of them, or all four, worked.
        let region = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("region"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "us-east-1".to_string());
        // The SDK builds `https://dynamodb.<region>.amazonaws.com` from this; see `aws_support`.
        crate::client::aws_support::validate_region("DynamoDB", &region)?;

        let endpoint_url = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("endpoint_url"))
            .transpose()?
            .flatten();

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

        // `remote_addr` is what the operator or the model actually typed as the target, and
        // it used to be dropped on the floor (`_remote_addr`): without an explicit
        // `endpoint_url` the SDK's default resolver produces
        // `https://dynamodb.<region>.amazonaws.com` and the default credential chain signs
        // with whatever ambient credentials the machine has — so a client aimed at
        // `localhost:8000` issued real reads and writes against real AWS. An address here
        // now means what it says. `endpoint_url` still wins when both are given, and
        // targeting AWS proper is done by passing that URL explicitly.
        let endpoint_url = endpoint_url.or_else(|| endpoint_url_from_remote_addr(&remote_addr));

        // A custom endpoint and no credentials would sign with the operator's ambient AWS
        // identity against a host the model may have chosen; see `aws_support`.
        crate::client::aws_support::refuse_ambient_credentials(
            "DynamoDB",
            endpoint_url.as_deref(),
            access_key_id.is_some() && secret_access_key.is_some(),
        )?;

        info!(
            "DynamoDB client {} initializing for region {}",
            client_id, region
        );

        // Store configuration in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("region".to_string(), serde_json::json!(region.clone()));
                if let Some(endpoint) = &endpoint_url {
                    client.set_protocol_field(
                        "endpoint_url".to_string(),
                        serde_json::json!(endpoint),
                    );
                }
                if let Some(key_id) = &access_key_id {
                    client
                        .set_protocol_field("access_key_id".to_string(), serde_json::json!(key_id));
                }
                if let Some(secret_key) = &secret_access_key {
                    client.set_protocol_field(
                        "secret_access_key".to_string(),
                        serde_json::json!(secret_key),
                    );
                }
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] DynamoDB client {} ready for region {}{}",
            client_id,
            region,
            endpoint_url
                .as_ref()
                .map(|e| format!(" (endpoint: {})", e))
                .unwrap_or_default()
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // This client raises no connected event, so there is no LLM call to register
        // ahead of - but the channel still goes up before `connect` returns, which is
        // what the dashboard waits on.
        //
        // The command loop replaces the 5s "has the client been removed yet" poll this
        // task used to run: `remove_client` drops the handle, the sender goes with it,
        // and `recv()` returns None - promptly, and without a timer.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let task_registrar = app_state.clone();
        let conn_llm = _llm_client.clone();
        let task_handle = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            _llm_client.clone(),
            status_tx.clone(),
        ));
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Raise the connected event.
        //
        // DYNAMODB_CLIENT_CONNECTED_EVENT was declared and nothing raised it, and this
        // client never called the LLM at all -- so the model was never consulted when a
        // DynamoDB client came up, and the injected-command path was the only way an
        // action could reach the wire.
        //
        // From a registered task, not inline: a dashboard-created client defaults to a
        // `*` -> manual rule and awaiting a parked answer would block creation. Operations
        // go through run_operation_once, which raises no event.
        let conn_state = app_state.clone();
        let conn_status = status_tx.clone();
        let conn_region = region.clone();
        let conn_endpoint = endpoint_url.clone();
        let conn_task = tokio::spawn(async move {
            let Some(instruction) = conn_state.get_instruction_for_client(client_id).await else {
                return;
            };
            let protocol = crate::client::dynamodb::actions::DynamoDbClientProtocol::new();
            // The event type declares `region` (required) and `endpoint`; it was raised with
            // an empty object, so the model was documented into reading two fields that were
            // never there.
            let event = Event::new(
                &crate::client::dynamodb::actions::DYNAMODB_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "region": conn_region,
                    "endpoint": conn_endpoint,
                }),
            );
            match crate::client::llm_budget::call_llm_for_client(
                &conn_llm,
                &conn_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                &protocol,
                &conn_status,
            )
            .await
            {
                Ok(result) => {
                    if let Some(mem) = result.memory_updates {
                        conn_state.set_memory_for_client(client_id, mem).await;
                    }
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in result.actions {
                        // Every arm is accounted for. This was a `let ... else { continue }`,
                        // which swallowed `Disconnect` — the answer this protocol's own
                        // static-mode startup example prescribes — along with every executor
                        // error, with no log line at all: the model was asked, answered, and
                        // was ignored in silence.
                        match protocol.execute_action(action.clone()) {
                            Ok(ClientActionResult::Custom { name, data }) => {
                                if let Err(e) =
                                    Self::run_operation_once(client_id, &name, &data, &conn_state)
                                        .await
                                {
                                    error!(
                                        "DynamoDB client {} connect-time {} failed: {}",
                                        client_id, name, e
                                    );
                                }
                            }
                            Ok(other) => info!(
                                "DynamoDB client {} connect-time action {:?} needs no DynamoDB \
                                 operation",
                                client_id, other
                            ),
                            Err(e) => error!(
                                "DynamoDB client {} could not execute connect-time action {}: {}",
                                client_id, action, e
                            ),
                        }
                    }
                }
                Err(e) => error!(
                    "DynamoDB client {} LLM error on connected event: {}",
                    client_id, e
                ),
            }
        });
        task_registrar
            .register_client_task(client_id, conn_task)
            .await;

        // Return a dummy local address (DynamoDB is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Execute one DynamoDB operation by the name `execute_action` produced, and
    /// raise the `dynamodb_response_received` event with its outcome.
    ///
    /// This is the single dispatch point: the command loop and any future LLM path
    /// both come through here, so the six advertised verbs cannot drift apart from
    /// what is actually implemented.
    pub async fn execute_operation(
        client_id: ClientId,
        operation: String,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<serde_json::Value> {
        Self::execute_operation_inner(
            client_id, operation, data, app_state, llm_client, status_tx, true,
        )
        .await
    }

    /// `notify == false` runs the operation without raising
    /// `dynamodb_response_received`.
    ///
    /// Two reasons, and both matter. It bounds the loop: a follow-up action the model
    /// returned for a response event must not raise another response event, or one
    /// operation could drive the model round and round. And it breaks a genuine type
    /// cycle -- notify -> apply_action -> execute_operation -> notify is a recursive
    /// async chain rustc cannot prove `Send`, so `tokio::spawn` rejects it.
    async fn execute_operation_inner(
        client_id: ClientId,
        operation: String,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        notify: bool,
    ) -> Result<serde_json::Value> {
        info!(
            "DynamoDB client {} executing operation: {}",
            client_id, operation
        );

        let (region, endpoint_url, access_key_id, secret_access_key) =
            Self::get_config(&app_state, client_id).await?;

        let config = Self::build_aws_config(
            &region,
            endpoint_url.as_deref(),
            access_key_id.as_deref(),
            secret_access_key.as_deref(),
        )
        .await?;

        let ddb = aws_sdk_dynamodb::Client::new(&config);

        let result = match operation.as_str() {
            "put_item" => Self::put_item(&ddb, &data).await,
            "get_item" => Self::get_item(&ddb, &data).await,
            "query" => Self::query(&ddb, &data).await,
            "scan" => Self::scan(&ddb, &data).await,
            "update_item" => Self::update_item(&ddb, &data).await,
            "delete_item" => Self::delete_item(&ddb, &data).await,
            other => Err(anyhow::anyhow!("Unknown DynamoDB operation: {}", other)),
        };

        let (success, data, error_text) = match &result {
            Ok(value) => {
                info!("DynamoDB client {} {} succeeded", client_id, operation);
                (true, Some(value.clone()), None)
            }
            Err(e) => {
                error!("DynamoDB client {} {} failed: {}", client_id, operation, e);
                (false, None, Some(e.to_string()))
            }
        };

        // Raise the response event from its own registered task rather than inline. A
        // dashboard-created client defaults to a `*` -> manual routing rule, so this LLM
        // call can park for minutes waiting for a human; awaiting it here would wedge the
        // command loop and make an injected action that in fact succeeded look to the
        // dashboard like a timeout.
        if !notify {
            return result;
        }

        let notify_state = app_state.clone();
        let notify = tokio::spawn(async move {
            if let Err(e) = Self::call_llm_with_response(
                client_id,
                &operation,
                success,
                data,
                error_text,
                &app_state,
                &llm_client,
                &status_tx,
            )
            .await
            {
                error!(
                    "DynamoDB client {} response notification failed: {}",
                    client_id, e
                );
            }
        });
        notify_state.register_client_task(client_id, notify).await;

        result
    }

    /// Build a client and run one operation. Raises no event, calls no LLM.
    ///
    /// Deliberately free of any path back into `call_llm_with_response`. That would make
    /// the async type self-referential -- notify -> apply -> operation -> notify -- which
    /// rustc cannot prove `Send`, so `tokio::spawn` refuses it outright. Follow-up actions
    /// the model returns for a response event run through here, which both breaks that
    /// cycle and bounds the loop: a follow-up cannot raise another response event.
    async fn run_operation_once(
        client_id: ClientId,
        operation: &str,
        data: &serde_json::Value,
        app_state: &Arc<AppState>,
    ) -> Result<serde_json::Value> {
        let (region, endpoint_url, access_key_id, secret_access_key) =
            Self::get_config(app_state, client_id).await?;

        let config = Self::build_aws_config(
            &region,
            endpoint_url.as_deref(),
            access_key_id.as_deref(),
            secret_access_key.as_deref(),
        )
        .await?;

        let ddb = aws_sdk_dynamodb::Client::new(&config);

        match operation {
            "put_item" => Self::put_item(&ddb, data).await,
            "get_item" => Self::get_item(&ddb, data).await,
            "query" => Self::query(&ddb, data).await,
            "scan" => Self::scan(&ddb, data).await,
            "update_item" => Self::update_item(&ddb, data).await,
            "delete_item" => Self::delete_item(&ddb, data).await,
            other => Err(anyhow::anyhow!("Unknown DynamoDB operation: {}", other)),
        }
    }

    /// Read an `{":v": {"S": "x"}}` map from action data into AttributeValues.
    fn attribute_values_from(
        data: &serde_json::Value,
        field: &str,
    ) -> Result<Option<std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue>>>
    {
        let Some(map) = data.get(field).and_then(|v| v.as_object()) else {
            return Ok(None);
        };
        let mut out = std::collections::HashMap::new();
        for (key, value) in map {
            out.insert(key.clone(), Self::json_to_attribute_value(key, value)?);
        }
        Ok(Some(out))
    }

    /// Read a `{"id": {"S": "x"}}` key/item map from action data.
    fn attribute_map_from(
        data: &serde_json::Value,
        field: &str,
    ) -> Result<std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue>> {
        let map = data
            .get(field)
            .and_then(|v| v.as_object())
            .with_context(|| format!("Missing '{}' in DynamoDB action data", field))?;
        let mut out = std::collections::HashMap::new();
        for (key, value) in map {
            out.insert(key.clone(), Self::json_to_attribute_value(key, value)?);
        }
        Ok(out)
    }

    fn table_name_from(data: &serde_json::Value) -> Result<String> {
        Ok(data
            .get("table_name")
            .and_then(|v| v.as_str())
            .context("Missing 'table_name' in DynamoDB action data")?
            .to_string())
    }

    /// PutItem
    async fn put_item(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;
        let item = Self::attribute_map_from(data, "item")?;

        ddb.put_item()
            .table_name(&table_name)
            .set_item(Some(item))
            .send()
            .await
            .context("PutItem failed")?;

        Ok(serde_json::json!({ "table_name": table_name, "written": true }))
    }

    /// GetItem
    async fn get_item(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;
        let key = Self::attribute_map_from(data, "key")?;

        let output = ddb
            .get_item()
            .table_name(&table_name)
            .set_key(Some(key))
            .send()
            .await
            .context("GetItem failed")?;

        let item_json = match output.item {
            Some(item) => Self::attribute_map_to_json(&item),
            None => serde_json::json!(null),
        };

        Ok(serde_json::json!({ "table_name": table_name, "item": item_json }))
    }

    /// Query
    async fn query(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;
        let key_condition_expression = data
            .get("key_condition_expression")
            .and_then(|v| v.as_str())
            .context("Missing 'key_condition_expression' in DynamoDB action data")?;

        let output = ddb
            .query()
            .table_name(&table_name)
            .key_condition_expression(key_condition_expression)
            .set_expression_attribute_values(Self::attribute_values_from(
                data,
                "expression_attribute_values",
            )?)
            .send()
            .await
            .context("Query failed")?;

        let items: Vec<serde_json::Value> = output
            .items()
            .iter()
            .map(Self::attribute_map_to_json)
            .collect();

        Ok(serde_json::json!({
            "table_name": table_name,
            "count": items.len(),
            "items": items,
        }))
    }

    /// Scan
    async fn scan(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;

        let mut request = ddb
            .scan()
            .table_name(&table_name)
            .set_expression_attribute_values(Self::attribute_values_from(
                data,
                "expression_attribute_values",
            )?);

        if let Some(filter) = data.get("filter_expression").and_then(|v| v.as_str()) {
            request = request.filter_expression(filter);
        }

        let output = request.send().await.context("Scan failed")?;

        let items: Vec<serde_json::Value> = output
            .items()
            .iter()
            .map(Self::attribute_map_to_json)
            .collect();

        Ok(serde_json::json!({
            "table_name": table_name,
            "count": items.len(),
            "items": items,
        }))
    }

    /// UpdateItem
    async fn update_item(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;
        let key = Self::attribute_map_from(data, "key")?;
        let update_expression = data
            .get("update_expression")
            .and_then(|v| v.as_str())
            .context("Missing 'update_expression' in DynamoDB action data")?;

        let output = ddb
            .update_item()
            .table_name(&table_name)
            .set_key(Some(key))
            .update_expression(update_expression)
            .set_expression_attribute_values(Self::attribute_values_from(
                data,
                "expression_attribute_values",
            )?)
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await
            .context("UpdateItem failed")?;

        let attributes = match output.attributes {
            Some(attrs) => Self::attribute_map_to_json(&attrs),
            None => serde_json::json!(null),
        };

        Ok(serde_json::json!({
            "table_name": table_name,
            "updated": true,
            "attributes": attributes,
        }))
    }

    /// DeleteItem
    async fn delete_item(
        ddb: &aws_sdk_dynamodb::Client,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let table_name = Self::table_name_from(data)?;
        let key = Self::attribute_map_from(data, "key")?;

        ddb.delete_item()
            .table_name(&table_name)
            .set_key(Some(key))
            .send()
            .await
            .context("DeleteItem failed")?;

        Ok(serde_json::json!({ "table_name": table_name, "deleted": true }))
    }

    /// Apply one executed action against DynamoDB. Shared by every path that can
    /// produce an action, so an injected one behaves identically to an LLM one.
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
                        Log::to(status_tx).error(format!(
                            "DynamoDB client {} operation {} failed: {}",
                            client_id, name, e
                        ));
                        // A failed operation is `Rejected`, not `Executed`. Both used to be
                        // `Executed`, so in the dashboard a DynamoDB rejection, an
                        // unconvertible attribute and a completed write rendered identically
                        // and the difference sat in free text. `Rejected` is documented as
                        // "unknown type, bad params", which is exactly what a conversion
                        // failure is; for a service error it is at least honestly distinct
                        // from success.
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
                detail: "send_data has no meaning for the DynamoDB client: it speaks the \
                         DynamoDB API through the AWS SDK, not a socket this client owns"
                    .to_string(),
            },
            ClientActionResult::Multiple(_) => ClientSendOutcome::Executed {
                detail: "the DynamoDB client's own verbs never produce Multiple; nothing was \
                         applied"
                    .to_string(),
            },
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or
    /// an injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// every DynamoDB verb yields `ClientActionResult::Custom` and there is no write
    /// half to put bytes on. Actions therefore go through [`Self::apply_action`], and
    /// the outcome is logged and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::dynamodb::actions::DynamoDbClientProtocol::new();

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
                    "DynamoDB client {} disconnecting on injected action",
                    client_id
                );
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }
        }

        info!("DynamoDB client {} command loop stopped", client_id);
        // Never leave the dashboard offering [ send ] into a client that is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Get DynamoDB configuration from client state
    async fn get_config(
        app_state: &AppState,
        client_id: ClientId,
    ) -> Result<(String, Option<String>, Option<String>, Option<String>)> {
        let region = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("region")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No region found")?;

        let endpoint_url = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("endpoint_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten();

        let access_key_id = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("access_key_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten();

        let secret_access_key = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("secret_access_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten();

        Ok((region, endpoint_url, access_key_id, secret_access_key))
    }

    /// Build AWS SDK config
    async fn build_aws_config(
        region: &str,
        endpoint_url: Option<&str>,
        access_key_id: Option<&str>,
        secret_access_key: Option<&str>,
    ) -> Result<aws_config::SdkConfig> {
        use aws_config::BehaviorVersion;

        crate::client::aws_support::validate_region("DynamoDB", region)?;
        let mut config_loader = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));

        // Set custom endpoint if provided (for DynamoDB Local or LocalStack)
        if let Some(endpoint) = endpoint_url {
            config_loader = config_loader.endpoint_url(endpoint);
        }

        // Set credentials if provided
        if let (Some(key_id), Some(secret_key)) = (access_key_id, secret_access_key) {
            use aws_config::meta::credentials::CredentialsProviderChain;
            use aws_credential_types::Credentials;

            let credentials = Credentials::new(
                key_id,
                secret_key,
                None, // session token
                None, // expiry
                "netget_dynamodb_client",
            );

            let provider = CredentialsProviderChain::first_try(
                "Static",
                aws_credential_types::provider::SharedCredentialsProvider::new(credentials),
            );

            config_loader = config_loader.credentials_provider(provider);
        }

        Ok(config_loader.load().await)
    }

    /// Convert one typed attribute value (`{"S": "x"}`, `{"N": "1"}`, …) into the SDK type.
    ///
    /// Returns `Err` rather than `None`, and the callers propagate it. Both used to *skip*
    /// what this could not convert, so a `put_item` carrying a Map or List attribute wrote
    /// an item missing that attribute and answered `{"written": true}`, and a `get_item`
    /// whose key used one sent a partial key — silently, with nothing logged. Refusing is
    /// the fail-closed choice and the model is told what it got wrong.
    fn json_to_attribute_value(
        name: &str,
        json: &serde_json::Value,
    ) -> Result<aws_sdk_dynamodb::types::AttributeValue> {
        use aws_sdk_dynamodb::types::AttributeValue;

        let map = json.as_object().with_context(|| {
            format!(
                "Attribute '{name}' must be a DynamoDB typed value such as {{\"S\": \"text\"}}, \
                 got {json}"
            )
        })?;
        if map.len() != 1 {
            anyhow::bail!(
                "Attribute '{name}' must carry exactly one type key (\"S\", \"N\", \"B\", \
                 \"BOOL\" or \"NULL\"), got {json}"
            );
        }
        let (type_key, value) = map.iter().next().expect("length checked above");

        let wrong_shape = |expected: &str| {
            anyhow::anyhow!("Attribute '{name}' has type {type_key} so its value must be {expected}, got {value}")
        };

        match type_key.as_str() {
            "S" => Ok(AttributeValue::S(
                value
                    .as_str()
                    .ok_or_else(|| wrong_shape("a string"))?
                    .to_string(),
            )),
            "N" => Ok(AttributeValue::N(
                value
                    .as_str()
                    .ok_or_else(|| wrong_shape("a string holding a number, e.g. \"123\""))?
                    .to_string(),
            )),
            "B" => {
                let encoded = value
                    .as_str()
                    .ok_or_else(|| wrong_shape("a base64 string"))?;
                // A decode failure used to become an empty blob: an unreadable value was
                // written to the table as a present, empty one.
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    encoded,
                )
                .with_context(|| {
                    format!("Attribute '{name}' is type B, so its value must be standard base64")
                })?;
                Ok(AttributeValue::B(Blob::new(bytes)))
            }
            "BOOL" => Ok(AttributeValue::Bool(
                value
                    .as_bool()
                    .ok_or_else(|| wrong_shape("true or false"))?,
            )),
            "NULL" => Ok(AttributeValue::Null(true)),
            other => anyhow::bail!(
                "Attribute '{name}' uses DynamoDB type {other:?}, which this client does not \
                 support. Supported: S (string), N (number as string), B (base64 bytes), BOOL, \
                 NULL. Maps (M), lists (L) and sets (SS/NS/BS) are not implemented — do not \
                 send them rather than expecting them to be dropped."
            ),
        }
    }

    /// Convert DynamoDB AttributeValue map to JSON
    fn attribute_map_to_json(
        map: &std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
    ) -> serde_json::Value {
        use aws_sdk_dynamodb::types::AttributeValue;

        let mut json_map = serde_json::Map::new();
        for (key, value) in map {
            let json_value = match value {
                AttributeValue::S(s) => serde_json::json!({"S": s}),
                AttributeValue::N(n) => serde_json::json!({"N": n}),
                AttributeValue::B(b) => {
                    let b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        b.as_ref(),
                    );
                    serde_json::json!({"B": b64})
                }
                AttributeValue::Bool(b) => serde_json::json!({"BOOL": b}),
                AttributeValue::Null(_) => serde_json::json!({"NULL": true}),
                // Not `{"UNKNOWN": "unsupported_type"}`: that reads as a typed attribute
                // and the model would copy it back into a put_item, where it is now
                // rejected. Say what it is instead.
                other => serde_json::json!({
                    "netget_unsupported_attribute_type": format!("{other:?}")
                }),
            };
            json_map.insert(key.clone(), json_value);
        }
        serde_json::Value::Object(json_map)
    }

    /// Call LLM with DynamoDB response
    async fn call_llm_with_response(
        client_id: ClientId,
        operation: &str,
        success: bool,
        data: Option<serde_json::Value>,
        error: Option<String>,
        // `&Arc<AppState>` rather than `&AppState`: the follow-up actions below run
        // through `apply_action`, which needs the Arc to hand on to `execute_operation`.
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol =
                Arc::new(crate::client::dynamodb::actions::DynamoDbClientProtocol::new());

            let mut event_data = serde_json::json!({
                "operation": operation,
                "success": success,
            });

            if let Some(d) = data {
                event_data["data"] = d;
            }
            if let Some(e) = error {
                event_data["error"] = serde_json::json!(e);
            }

            let event = Event::new(&DYNAMODB_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

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
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute the model's follow-up actions. They used to be discarded
                    // outright (`actions: _`), so answering dynamodb_response_received
                    // did nothing at all -- the point of raising the event.
                    //
                    // They go through `run_operation_once`, which raises no event, so a
                    // follow-up cannot trigger another response event and one operation
                    // cannot drive an unbounded LLM loop.
                    use crate::llm::actions::client_trait::Client;
                    for action in actions {
                        match protocol.execute_action(action.clone()) {
                            Ok(crate::llm::actions::client_trait::ClientActionResult::Custom {
                                name,
                                data,
                            }) => {
                                // `run_operation_once` raises no event and calls no
                                // LLM, so a follow-up cannot raise another response
                                // event -- that bounds the loop -- and the async type
                                // never becomes self-referential, which is what made
                                // the notify -> apply -> operation -> notify chain
                                // impossible for rustc to prove `Send`.
                                let outcome =
                                    Self::run_operation_once(client_id, &name, &data, app_state)
                                        .await;
                                info!(
                                    "DynamoDB client {} follow-up action {:?} -> {:?}",
                                    client_id, action, outcome
                                );
                            }
                            Ok(other) => info!(
                                "DynamoDB client {} follow-up produced no operation: {:?}",
                                client_id, other
                            ),
                            Err(e) => error!(
                                "DynamoDB client {} rejected its own follow-up action: {}",
                                client_id, e
                            ),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for DynamoDB client {}: {}", client_id, e);
                }
            }
        }

        Ok(())
    }
}
