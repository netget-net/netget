//! LDAP client implementation
pub mod actions;

pub use actions::LdapClientProtocol;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::client::ldap::actions::{
    LDAP_CLIENT_BIND_RESPONSE_EVENT, LDAP_CLIENT_CONNECTED_EVENT,
    LDAP_CLIENT_MODIFY_RESPONSE_EVENT, LDAP_CLIENT_SEARCH_RESULTS_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{ClientId, ClientStatus};

use ldap3::{LdapConn, Mod, Scope};

/// What one executed action did to the LDAP connection.
///
/// Returned by [`LdapClient::apply_action`], the single place an LDAP operation reaches the
/// server — the connected-event LLM path and injected dashboard commands both go through it.
enum Applied {
    /// An operation completed. `detail` is the injected-action outcome text; `event` is the
    /// response event the client raises next, exactly as the LLM path does.
    Ran { detail: String, event: Event },
    /// The session should end (the connection has already been unbound).
    Disconnect,
    /// The action executed but touched the connection in no way.
    Nothing(&'static str),
}

/// How many action -> operation -> response -> action turns one client will take.
///
/// Every operation raises a response event whose answer may be another operation, so the chain
/// is self-referential and needs a bound rather than silence: a model that answers every search
/// with another search would otherwise run forever. Four covers bind → search → add → react,
/// and a runaway costs five LLM calls. The response at the bound is still shown to the model;
/// its answer is dropped with a warning.
const MAX_FOLLOWUP_DEPTH: usize = 4;

/// LDAP client that connects to an LDAP server
pub struct LdapClient;

impl LdapClient {
    /// Connect to an LDAP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("LDAP client {} connecting to {}", client_id, remote_addr);

        // Parse remote_addr to get host and port
        let ldap_url = if remote_addr.starts_with("ldap://") || remote_addr.starts_with("ldaps://")
        {
            remote_addr.clone()
        } else {
            format!("ldap://{}", remote_addr)
        };

        // Connect to LDAP server (blocking, so we use tokio::task::spawn_blocking)
        let ldap = tokio::task::spawn_blocking(move || LdapConn::new(&ldap_url))
            .await
            .context("Failed to spawn LDAP connection task")??;

        // Extract the actual socket address from the connection
        // Since ldap3 doesn't expose the underlying socket address directly,
        // we'll parse it from the URL
        let socket_addr: SocketAddr = remote_addr
            .split("://")
            .last()
            .unwrap_or(&remote_addr)
            .parse()
            .context(format!(
                "Failed to parse socket address from {}",
                remote_addr
            ))?;

        info!("LDAP client {} connected to {}", client_id, socket_addr);

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] LDAP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap ldap connection in Arc<Mutex> for sharing across tasks: the connected-event
        // LLM task and the injected-command loop both drive it, one operation at a time.
        let ldap = Arc::new(tokio::sync::Mutex::new(ldap));
        let protocol = Arc::new(LdapClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes — the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            Arc::clone(&ldap),
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Clone references for the task
        let protocol_clone = protocol.clone();
        let ldap_clone = Arc::clone(&ldap);
        let app_state_clone = Arc::clone(&app_state);
        let status_tx_clone = status_tx.clone();

        // Send initial connected event to LLM
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            if let Some(instruction) = app_state_clone.get_instruction_for_client(client_id).await {
                let event = Event::new(
                    &LDAP_CLIENT_CONNECTED_EVENT,
                    serde_json::json!({
                        "remote_addr": socket_addr.to_string(),
                    }),
                );

                let memory = app_state_clone
                    .get_memory_for_client(client_id)
                    .await
                    .unwrap_or_default();

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
                            if let Err(e) = Self::execute_ldap_action(
                                action,
                                &ldap_clone,
                                &protocol_clone,
                                &llm_client,
                                &app_state_clone,
                                &status_tx_clone,
                                client_id,
                                &instruction,
                                0,
                            )
                            .await
                            {
                                error!("Failed to execute LDAP action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for LDAP client {}: {}", client_id, e);
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(socket_addr)
    }

    /// Drain injected commands until the channel closes (the client was removed or stopped)
    /// or an injected `disconnect` ends the session.
    ///
    /// `ldap3`'s synchronous `LdapConn` owns the socket, so every verb yields
    /// `ClientActionResult::Custom` and the generic split-stream arm cannot serve it; the
    /// effect goes through the shared [`Self::apply_action`], which is also what the LLM
    /// path calls.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<LdapClientProtocol>,
        ldap: Arc<tokio::sync::Mutex<LdapConn>>,
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
                Ok(result) => match Self::apply_action(result, &ldap, client_id).await {
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
                Log::to(&status_tx).warn(format!(
                    "LDAP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::mark_disconnected(client_id, &app_state, &status_tx).await;
                break;
            }

            // The model sees an injected operation's response exactly as it sees one it asked
            // for — after the reply, so the dashboard is not held for an LLM round-trip.
            if let Some(event) = follow_up {
                let instruction = app_state
                    .get_instruction_for_client(client_id)
                    .await
                    .unwrap_or_default();
                if let Err(e) = Self::call_llm_with_event(
                    &llm_client,
                    &app_state,
                    &status_tx,
                    client_id,
                    &instruction,
                    &protocol,
                    &ldap,
                    event,
                    0,
                )
                .await
                {
                    error!("LDAP client {} response event failed: {}", client_id, e);
                }
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a client whose loop is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one action from the model and hand the operation's response back to it.
    ///
    /// Boxed `+ Send` because this and [`Self::call_llm_with_event`] call each other; `depth`
    /// counts the turns so far and [`MAX_FOLLOWUP_DEPTH`] bounds them.
    #[allow(clippy::too_many_arguments)]
    fn execute_ldap_action<'a>(
        action: serde_json::Value,
        ldap: &'a Arc<tokio::sync::Mutex<LdapConn>>,
        protocol: &'a Arc<LdapClientProtocol>,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        client_id: ClientId,
        instruction: &'a str,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match Self::apply_action(protocol.execute_action(action)?, ldap, client_id).await? {
                Applied::Ran { event, .. } => {
                    Self::call_llm_with_event(
                        llm_client,
                        app_state,
                        status_tx,
                        client_id,
                        instruction,
                        protocol,
                        ldap,
                        event,
                        depth,
                    )
                    .await?;
                }
                Applied::Disconnect => {
                    info!("LDAP client {} disconnecting", client_id);
                    Self::mark_disconnected(client_id, app_state, status_tx).await;
                }
                Applied::Nothing(what) => {
                    trace!("LDAP client {} action had no effect: {}", client_id, what);
                }
            }

            Ok(())
        })
    }

    /// Run one executed action against the LDAP connection. Shared by the LLM path and
    /// injected commands so each operation's encoding exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        ldap: &Arc<tokio::sync::Mutex<LdapConn>>,
        client_id: ClientId,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "ldap_bind" => {
                    let dn = data
                        .get("dn")
                        .and_then(|v| v.as_str())
                        .context("Missing 'dn' in bind action")?;
                    let password = data
                        .get("password")
                        .and_then(|v| v.as_str())
                        .context("Missing 'password' in bind action")?;

                    debug!("LDAP client {} binding as {}", client_id, dn);

                    let dn_owned = dn.to_string();
                    let password_owned = password.to_string();
                    let ldap_clone = Arc::clone(ldap);

                    // Perform bind in blocking task
                    let bind_result = tokio::task::spawn_blocking(move || {
                        let mut ldap_guard = ldap_clone.blocking_lock();
                        ldap_guard.simple_bind(&dn_owned, &password_owned)
                    })
                    .await
                    .context("Failed to spawn bind task")??;

                    let (success, message) = match bind_result.success() {
                        Ok(_) => (true, "Bind successful".to_string()),
                        Err(e) => (false, format!("Bind failed: {:?}", e)),
                    };

                    info!("LDAP client {} bind result: {}", client_id, message);

                    Ok(Applied::Ran {
                        detail: format!("bind as {}: {}", dn, message),
                        event: Event::new(
                            &LDAP_CLIENT_BIND_RESPONSE_EVENT,
                            serde_json::json!({
                                "dn": dn,
                                "success": success,
                                "message": message,
                            }),
                        ),
                    })
                }
                "ldap_search" => {
                    let base_dn = data
                        .get("base_dn")
                        .and_then(|v| v.as_str())
                        .context("Missing 'base_dn' in search action")?;
                    let filter = data
                        .get("filter")
                        .and_then(|v| v.as_str())
                        .context("Missing 'filter' in search action")?;
                    let attributes: Vec<String> = data
                        .get("attributes")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let scope_str = data
                        .get("scope")
                        .and_then(|v| v.as_str())
                        .unwrap_or("subtree");

                    let scope = match scope_str {
                        "base" => Scope::Base,
                        "one" => Scope::OneLevel,
                        _ => Scope::Subtree,
                    };

                    debug!(
                        "LDAP client {} searching: base={}, filter={}, scope={:?}",
                        client_id, base_dn, filter, scope
                    );

                    let base_dn_owned = base_dn.to_string();
                    let filter_owned = filter.to_string();
                    let attrs_owned: Vec<String> = if attributes.is_empty() {
                        vec!["*".to_string()]
                    } else {
                        attributes.clone()
                    };

                    let ldap_clone = Arc::clone(ldap);

                    // Perform search in blocking task
                    let search_result = tokio::task::spawn_blocking(move || {
                        let mut ldap_guard = ldap_clone.blocking_lock();
                        let attrs: Vec<&str> = attrs_owned.iter().map(|s| s.as_str()).collect();
                        ldap_guard.search(&base_dn_owned, scope, &filter_owned, attrs)
                    })
                    .await
                    .context("Failed to spawn search task")??;

                    // A search the server refused (noSuchObject, a bad filter, insufficient
                    // access) is the server's answer, not a transport error: the model is told,
                    // exactly as it is told of a failed bind or add. Returning the error here
                    // would end the chain with nothing raised, and the model would never learn
                    // why its search came back empty.
                    let entries = match search_result.success() {
                        Ok((entries, _)) => entries,
                        Err(e) => {
                            let message = format!("Search failed: {:?}", e);
                            info!("LDAP client {} search result: {}", client_id, message);
                            return Ok(Applied::Ran {
                                detail: format!(
                                    "search base={} filter={}: {}",
                                    base_dn, filter, message
                                ),
                                event: Event::new(
                                    &LDAP_CLIENT_SEARCH_RESULTS_EVENT,
                                    serde_json::json!({
                                        "base_dn": base_dn,
                                        "filter": filter,
                                        "success": false,
                                        "message": message,
                                        "entries": [],
                                        "count": 0,
                                    }),
                                ),
                            });
                        }
                    };

                    // Convert entries to JSON
                    let mut json_entries = Vec::new();
                    for entry in entries {
                        use ldap3::SearchEntry;
                        let search_entry = SearchEntry::construct(entry);
                        let mut attrs_map = serde_json::Map::new();
                        for (attr_name, attr_values) in search_entry.attrs {
                            attrs_map.insert(attr_name, serde_json::json!(attr_values));
                        }
                        json_entries.push(serde_json::json!({
                            "dn": search_entry.dn,
                            "attributes": attrs_map,
                        }));
                    }

                    let count = json_entries.len();
                    info!(
                        "LDAP client {} search returned {} entries",
                        client_id, count
                    );

                    Ok(Applied::Ran {
                        detail: format!(
                            "search base={} filter={} returned {} entries",
                            base_dn, filter, count
                        ),
                        event: Event::new(
                            &LDAP_CLIENT_SEARCH_RESULTS_EVENT,
                            serde_json::json!({
                                "base_dn": base_dn,
                                "filter": filter,
                                "success": true,
                                "entries": json_entries,
                                "count": count,
                            }),
                        ),
                    })
                }
                "ldap_add" => {
                    let dn = data
                        .get("dn")
                        .and_then(|v| v.as_str())
                        .context("Missing 'dn' in add action")?;
                    let attributes = data
                        .get("attributes")
                        .context("Missing 'attributes' in add action")?;

                    debug!("LDAP client {} adding entry: {}", client_id, dn);

                    // Convert attributes JSON to Vec<(attribute, HashSet<value>)>. A value may be
                    // an array of strings or a single string: `{"cn": "Ada"}` is how a model
                    // naturally writes a single-valued attribute, and dropping it would send an
                    // entry without it — which the server then rejects as an object class
                    // violation, naming an attribute the model did supply.
                    let attrs_obj = attributes
                        .as_object()
                        .context("'attributes' in add action must be an object")?;
                    let mut attrs_vec = Vec::new();
                    for (attr_name, attr_values) in attrs_obj {
                        let values: std::collections::HashSet<String> = match attr_values {
                            serde_json::Value::String(v) => std::iter::once(v.clone()).collect(),
                            serde_json::Value::Array(arr) => arr
                                .iter()
                                .map(|v| {
                                    v.as_str().map(str::to_string).with_context(|| {
                                        format!("attribute '{attr_name}' has a non-string value")
                                    })
                                })
                                .collect::<Result<_>>()?,
                            _ => anyhow::bail!(
                                "attribute '{attr_name}' must be a string or an array of strings"
                            ),
                        };
                        attrs_vec.push((attr_name.clone(), values));
                    }

                    let dn_owned = dn.to_string();
                    let ldap_clone = Arc::clone(ldap);

                    // Perform add in blocking task
                    let add_result = tokio::task::spawn_blocking(move || {
                        let mut ldap_guard = ldap_clone.blocking_lock();
                        ldap_guard.add(&dn_owned, attrs_vec)
                    })
                    .await
                    .context("Failed to spawn add task")??;

                    let (success, message) = match add_result.success() {
                        Ok(_) => (true, "Entry added successfully".to_string()),
                        Err(e) => (false, format!("Add failed: {:?}", e)),
                    };

                    info!("LDAP client {} add result: {}", client_id, message);

                    Ok(Applied::Ran {
                        detail: format!("add {}: {}", dn, message),
                        event: Event::new(
                            &LDAP_CLIENT_MODIFY_RESPONSE_EVENT,
                            serde_json::json!({
                                "operation": "add",
                                "dn": dn,
                                "success": success,
                                "message": message,
                            }),
                        ),
                    })
                }
                "ldap_modify" => {
                    let dn_owned = data
                        .get("dn")
                        .and_then(|v| v.as_str())
                        .context("Missing 'dn' in modify action")?
                        .to_string();
                    let operation_owned = data
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .context("Missing 'operation' in modify action")?
                        .to_string();
                    let attribute_owned = data
                        .get("attribute")
                        .and_then(|v| v.as_str())
                        .context("Missing 'attribute' in modify action")?
                        .to_string();
                    let values_owned: Vec<String> = data
                        .get("values")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    debug!(
                        "LDAP client {} modifying entry: {} ({} {})",
                        client_id, dn_owned, operation_owned, attribute_owned
                    );

                    let dn_for_detail = dn_owned.clone();
                    let ldap_clone = Arc::clone(ldap);

                    // Perform modify in blocking task
                    // Create Mod inside the closure to avoid lifetime issues
                    let modify_result = tokio::task::spawn_blocking(move || {
                        let mut ldap_guard = ldap_clone.blocking_lock();

                        // Convert values to HashSet<&str>
                        let values_refs: std::collections::HashSet<&str> =
                            values_owned.iter().map(|s| s.as_str()).collect();

                        // Create Mod operation
                        let mod_op = match operation_owned.as_str() {
                            "add" => Mod::Add(attribute_owned.as_str(), values_refs.clone()),
                            "delete" => Mod::Delete(attribute_owned.as_str(), values_refs.clone()),
                            "replace" => Mod::Replace(attribute_owned.as_str(), values_refs),
                            _ => {
                                return Err(anyhow::anyhow!(
                                    "Invalid operation: {}",
                                    operation_owned
                                ))
                            }
                        };

                        ldap_guard
                            .modify(&dn_owned, vec![mod_op])
                            .context("Failed to modify entry")
                    })
                    .await
                    .context("Failed to spawn modify task")??;

                    let (success, message) = match modify_result.success() {
                        Ok(_) => (true, "Entry modified successfully".to_string()),
                        Err(e) => (false, format!("Modify failed: {:?}", e)),
                    };

                    info!("LDAP client {} modify result: {}", client_id, message);

                    Ok(Applied::Ran {
                        event: Event::new(
                            &LDAP_CLIENT_MODIFY_RESPONSE_EVENT,
                            serde_json::json!({
                                "operation": "modify",
                                "dn": dn_for_detail,
                                "success": success,
                                "message": message,
                            }),
                        ),
                        detail: format!("modify {}: {}", dn_for_detail, message),
                    })
                }
                "ldap_delete" => {
                    let dn = data
                        .get("dn")
                        .and_then(|v| v.as_str())
                        .context("Missing 'dn' in delete action")?;

                    debug!("LDAP client {} deleting entry: {}", client_id, dn);

                    let dn_owned = dn.to_string();
                    let ldap_clone = Arc::clone(ldap);

                    // Perform delete in blocking task
                    let delete_result = tokio::task::spawn_blocking(move || {
                        let mut ldap_guard = ldap_clone.blocking_lock();
                        ldap_guard.delete(&dn_owned)
                    })
                    .await
                    .context("Failed to spawn delete task")??;

                    let (success, message) = match delete_result.success() {
                        Ok(_) => (true, "Entry deleted successfully".to_string()),
                        Err(e) => (false, format!("Delete failed: {:?}", e)),
                    };

                    info!("LDAP client {} delete result: {}", client_id, message);

                    Ok(Applied::Ran {
                        detail: format!("delete {}: {}", dn, message),
                        event: Event::new(
                            &LDAP_CLIENT_MODIFY_RESPONSE_EVENT,
                            serde_json::json!({
                                "operation": "delete",
                                "dn": dn,
                                "success": success,
                                "message": message,
                            }),
                        ),
                    })
                }
                other => {
                    trace!("Unknown LDAP custom action: {}", other);
                    Ok(Applied::Nothing("custom result not handled by this client"))
                }
            },
            ClientActionResult::Disconnect => {
                // Close the LDAP connection before reporting the disconnect, so the outcome
                // is true the moment it is reported.
                let ldap_clone = Arc::clone(ldap);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut ldap_guard = ldap_clone.blocking_lock();
                    ldap_guard.unbind()
                })
                .await;
                Ok(Applied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more")),
            ClientActionResult::NoAction => Ok(Applied::Nothing("no_action")),
            ClientActionResult::SendData(_) => Ok(Applied::Nothing(
                "send_data is not meaningful for an ldap3 connection",
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Nothing(
                "multiple results not handled by this client",
            )),
        }
    }

    /// Show the model an operation's response and execute what it answers, one level deeper.
    #[allow(clippy::too_many_arguments)]
    async fn call_llm_with_event(
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
        instruction: &str,
        protocol: &Arc<LdapClientProtocol>,
        ldap: &Arc<tokio::sync::Mutex<LdapConn>>,
        event: Event,
        depth: usize,
    ) -> Result<()> {
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            instruction,
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

                if !actions.is_empty() && depth >= MAX_FOLLOWUP_DEPTH {
                    warn!(
                        "LDAP client {} reached the follow-up depth bound ({}); dropping {} \
                         action(s) rather than looping",
                        client_id,
                        MAX_FOLLOWUP_DEPTH,
                        actions.len()
                    );
                    return Ok(());
                }

                // Execute actions
                for action in actions {
                    if let Err(e) = Self::execute_ldap_action(
                        action,
                        ldap,
                        protocol,
                        llm_client,
                        app_state,
                        status_tx,
                        client_id,
                        instruction,
                        depth + 1,
                    )
                    .await
                    {
                        error!("Failed to execute LDAP action: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("LLM error for LDAP client {}: {}", client_id, e);
            }
        }

        Ok(())
    }

    async fn mark_disconnected(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] LDAP client {} disconnected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}
