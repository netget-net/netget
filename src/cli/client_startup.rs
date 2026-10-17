//! Client startup logic for TUI mode
//!
//! Handles connecting clients based on application state

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::events::ActionExecutionError;
use crate::llm::OllamaClient;
use crate::state::app_state::AppState;
use crate::state::ClientId;

/// Resolve a caller-supplied client protocol name to the registry's canonical
/// key, accepting any casing (and the registry's keyword aliases).
///
/// `CLIENT_REGISTRY` is keyed by each protocol's own spelling — "TCP", "Redis",
/// "HTTP" — so a plain `get("tcp")` misses. This mirrors what
/// `server_startup::start_server_from_action` gets from
/// `ServerRegistry::parse_from_str`.
pub fn resolve_client_protocol(protocol: &str) -> Option<String> {
    let registry = &crate::protocol::CLIENT_REGISTRY;
    if registry.get(protocol).is_some() {
        return Some(protocol.to_string());
    }
    let upper = protocol.to_uppercase();
    if registry.get(&upper).is_some() {
        return Some(upper);
    }
    let lower = protocol.to_lowercase();
    if registry.get(&lower).is_some() {
        return Some(lower);
    }
    // Case-insensitive scan, then the registry's keyword parser as a last resort.
    registry
        .list_protocols()
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case(protocol))
        .or_else(|| registry.parse_from_str(protocol))
}

/// Build the error for a client protocol name that `resolve_client_protocol`
/// could not map to a compiled-in protocol.
///
/// Defers to `ClientRegistry::resolve()`, which distinguishes "exists but is not
/// compiled into this build (rebuild with --features X)" from "no such protocol"
/// and offers a did-you-mean suggestion. `resolve_client_protocol` stays the
/// lookup, because it also matches spellings `resolve()` does not; this only
/// supplies the diagnostic once that lookup has already failed.
fn unknown_client_protocol_error(protocol: &str) -> anyhow::Error {
    match crate::protocol::CLIENT_REGISTRY.resolve(protocol) {
        Err(e) => anyhow::anyhow!("{e}"),
        // resolve() succeeded where resolve_client_protocol() did not; keep a
        // sensible message rather than claiming success.
        Ok(_) => anyhow::anyhow!("Unknown client protocol: {}", protocol),
    }
}

/// Start a specific client by ID
pub async fn start_client_by_id(
    state: &AppState,
    client_id: ClientId,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<(), ActionExecutionError> {
    // Get client info
    let client = match state
        .with_client_mut(client_id, |current| {
            crate::protocol::StartupParams::preflight_owned(&mut current.startup_params)?;
            Ok::<_, crate::protocol::StartupParamError>(current.clone())
        })
        .await
    {
        Some(Ok(current)) => current,
        Some(Err(error)) => return Err(ActionExecutionError::Fatal(error.into())),
        None => {
            let _ = status_tx.send(format!("[ERROR] Client #{} not found", client_id.as_u32()));
            return Ok(());
        }
    };

    let protocol_name = client.protocol_name.clone();
    let remote_addr = client.remote_addr.clone();

    let msg = format!(
        "[CLIENT] Starting client #{} ({}) connecting to {}",
        client_id.as_u32(),
        protocol_name,
        remote_addr
    );
    let _ = status_tx.send(msg.clone());

    // Actually connect the client using the registry
    use crate::state::client::ClientStatus;

    // Get protocol implementation from registry (accepting any casing)
    let protocol = match resolve_client_protocol(&protocol_name)
        .and_then(|name| crate::protocol::CLIENT_REGISTRY.get(&name))
    {
        Some(p) => p,
        None => return Err(unknown_client_protocol_error(&protocol_name).into()),
    };

    // === --min-stability gate ===
    // Refuse a protocol below the operator's maturity floor before connecting.
    if let Some(min) = state.get_min_stability().await {
        let actual = protocol.metadata().state;
        if actual < min {
            let msg = crate::cli::server_startup::min_stability_refusal(
                "client",
                &protocol_name,
                actual,
                min,
            );
            state
                .update_client_status(client_id, ClientStatus::Error(msg.clone()))
                .await;
            let _ = status_tx.send(format!("[ERROR] {}", msg));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return Err(ActionExecutionError::Fatal(anyhow::anyhow!(msg)));
        }
    }

    // Runtime dependencies a start with these params needs (a binary on PATH, a system
    // library). Only a dependency the probe established is absent refuses — see
    // `dependencies::startup_blocker`, shared with server startup.
    let system_caps = state.get_system_capabilities().await;
    if let Some(dep) = crate::protocol::dependencies::startup_blocker(
        &protocol.startup_dependencies(client.startup_params.as_ref()),
        &system_caps,
    ) {
        let msg = format!(
            "Cannot start {} client: {}. {}",
            protocol_name,
            dep.description(),
            dep.installation_hint()
        );
        state
            .update_client_status(client_id, ClientStatus::Error(msg.clone()))
            .await;
        let _ = status_tx.send(format!("[ERROR] {}", msg));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        return Err(ActionExecutionError::Fatal(anyhow::anyhow!(msg)));
    }

    // Build type-safe startup params if provided
    //
    // The JSON comes from the LLM or an MCP client, so a bad key must become a
    // reported error (and an `Error` client status), never a panic.
    let startup_params = if let Some(params_json) = client.startup_params.clone() {
        // Get the parameter schema from the protocol
        let schema = protocol.get_startup_parameters();
        // Create validated StartupParams
        match crate::protocol::StartupParams::new_validated(params_json, schema) {
            Ok(p) => Some(p),
            Err(e) => {
                let msg = format!("Invalid startup_params for {}: {}", protocol_name, e);
                state
                    .update_client_status(client_id, ClientStatus::Error(msg.clone()))
                    .await;
                let _ = status_tx.send(format!("[ERROR] {}", msg));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return Err(ActionExecutionError::Fatal(anyhow::anyhow!(msg)));
            }
        }
    } else {
        None
    };

    // Build connect context
    let connect_ctx = crate::protocol::ConnectContext {
        remote_addr: remote_addr.clone(),
        llm_client: llm_client.clone(),
        state: Arc::new(state.clone()),
        status_tx: status_tx.clone(),
        client_id,
        startup_params,
    };

    // Connect the client using the protocol's connect method
    match protocol.connect(connect_ctx).await {
        Ok(local_addr) => {
            // Update client status to connected
            state
                .update_client_status(client_id, ClientStatus::Connected)
                .await;
            let _ = status_tx.send(format!(
                "[CLIENT] {} client #{} connected to {} (local: {})",
                protocol_name,
                client_id.as_u32(),
                remote_addr,
                local_addr
            ));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        }
        Err(e) => {
            // For connection errors, set client status to error
            state
                .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                .await;
            let _ = status_tx.send(format!(
                "[ERROR] Failed to connect {} client #{} to {}: {}",
                protocol_name,
                client_id.as_u32(),
                remote_addr,
                e
            ));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return Err(ActionExecutionError::Fatal(e));
        }
    }

    Ok(())
}

/// Start a client from action parameters (used by /load command)
/// Returns the client ID on success
#[allow(clippy::too_many_arguments)]
pub async fn start_client_from_action(
    state: &AppState,
    protocol: &str,
    remote_addr: &str,
    instruction: String,
    mut startup_params: Option<serde_json::Value>,
    initial_memory: Option<String>,
    event_handlers: Option<Vec<serde_json::Value>>,
    scheduled_tasks: Option<Vec<crate::llm::actions::common::ServerTaskDefinition>>,
    feedback_instructions: Option<String>,
    conversation: crate::protocol::metadata::ConversationOverrides,
    llm_client: OllamaClient,
    status_tx: Option<mpsc::UnboundedSender<String>>,
) -> Result<ClientId> {
    use crate::state::client::ClientStatus;
    crate::protocol::StartupParams::preflight_owned(&mut startup_params)?;
    let prepared_tasks = crate::state::task::prepare_tasks(
        scheduled_tasks.as_deref(),
        crate::state::task::TaskScope::Global,
    )?;

    // Get protocol from registry. Registry keys are the protocols' own casing
    // ("TCP", "Redis", …), so resolve the caller's spelling to the canonical name
    // first — the same normalization `start_server_from_action` does — and store
    // that canonical name on the instance so later lookups by protocol_name work.
    let protocol = match resolve_client_protocol(protocol) {
        Some(name) => name,
        None => return Err(unknown_client_protocol_error(protocol)),
    };
    let protocol_impl = match crate::protocol::CLIENT_REGISTRY.get(&protocol) {
        Some(p) => p,
        None => return Err(unknown_client_protocol_error(&protocol)),
    };

    // History and batching, resolved and refused exactly as for a server.
    let (history_entries, batching) = conversation.resolve(&protocol_impl.metadata(), &protocol)?;

    // === --min-stability gate ===
    // Refuse a protocol below the operator's maturity floor before building
    // anything — no client instance exists yet, so there is nothing to strand.
    if let Some(min) = state.get_min_stability().await {
        let actual = protocol_impl.metadata().state;
        if actual < min {
            return Err(anyhow::anyhow!(
                crate::cli::server_startup::min_stability_refusal("client", &protocol, actual, min)
            ));
        }
    }

    // === Runtime dependencies, BEFORE registering the client ===
    //
    // Same gate and same reasoning as `start_server_from_action`: refuse only a dependency the
    // probe established is absent, name it with its install hint, and leave nothing stranded.
    let system_caps = state.get_system_capabilities().await;
    if let Some(dep) = crate::protocol::dependencies::startup_blocker(
        &protocol_impl.startup_dependencies(startup_params.as_ref()),
        &system_caps,
    ) {
        return Err(anyhow::anyhow!(
            "Cannot start {} client: {}. {}",
            protocol,
            dep.description(),
            dep.installation_hint()
        ));
    }

    // === Validate startup params BEFORE registering the client ===
    //
    // This JSON is untrusted (LLM `open_client` / MCP `start_client`), so
    // validating here means a malformed request errors out without leaving a
    // `ClientInstance` stranded in `ClientStatus::Connecting`.
    let startup_params_obj = match startup_params.clone() {
        Some(params_json) => {
            let schema = protocol_impl.get_startup_parameters();
            Some(
                crate::protocol::StartupParams::new_validated(params_json, schema).map_err(
                    |e| anyhow::anyhow!("Invalid startup_params for {}: {}", protocol, e),
                )?,
            )
        }
        None => {
            crate::protocol::StartupParams::new_validated(
                serde_json::json!({}),
                protocol_impl.get_startup_parameters(),
            )?;
            None
        }
    };

    // === Parse event handlers BEFORE registering the client ===
    //
    // This used to be a lenient `filter_map(.. .ok())` *after* `add_client`,
    // which silently dropped malformed handlers — the caller believed their
    // script/static routing was in place and every event went to the LLM
    // instead. Parse strictly (same validator as the server path) while there
    // is still nothing to strand.
    let event_handler_config = match event_handlers {
        Some(handlers) if !handlers.is_empty() => Some(
            crate::events::handler::EventHandler::parse_event_handlers(handlers)
                .map_err(|e| anyhow::anyhow!("Invalid event_handlers for {}: {}", protocol, e))?,
        ),
        _ => None,
    };

    // Create client instance
    let client = crate::state::client::ClientInstance {
        id: ClientId::new(0), // Will be assigned by add_client
        remote_addr: remote_addr.to_string(),
        protocol_name: protocol.clone(),
        instruction: instruction.clone(),
        memory: String::new(),
        status: ClientStatus::Connecting,
        connection: None,
        created_at: crate::utils::clock::Instant::now(),
        status_changed_at: crate::utils::clock::Instant::now(),
        startup_params: startup_params.clone(),
        event_handler_config,
        protocol_data: serde_json::Value::Null,
        log_files: Default::default(),
        feedback_instructions,
        feedback_buffer: Vec::new(),
        last_feedback_processed: None,
        connection_history: Default::default(),
        history_entries,
        batching,
        exchange_history: Default::default(),
    };

    let client_id = state.add_client(client).await;
    let mut startup_guard = super::startup_guard::StartupGuard::client(state, client_id);

    // Set initial memory if provided
    if let Some(mem) = initial_memory {
        state
            .with_client_mut(client_id, |c| {
                c.memory = mem;
            })
            .await;
    }

    // Definitions were prepared before the owner was registered.
    for mut task in prepared_tasks {
        task.scope = crate::state::task::TaskScope::Client(client_id);
        state.add_task(task).await;
    }

    // `startup_params_obj` was built and validated above, before `add_client`.

    // Use the caller's status channel when one exists (the dashboard/TUI wants
    // the client's lifecycle lines). Headless callers (the /load command, the
    // open_client action, the MCP start_client tool) pass `None`; dropping the
    // receiver would make every `status_tx.send()` in the client's connection
    // loop fail silently, so drain a fresh channel to tracing instead.
    let status_tx = match status_tx {
        Some(tx) => tx,
        None => {
            let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();
            tokio::spawn(async move {
                while let Some(msg) = status_rx.recv().await {
                    if msg == "__UPDATE_UI__" {
                        continue;
                    }
                    tracing::info!("{}", msg);
                }
            });
            status_tx
        }
    };

    // Build connect context
    let connect_ctx = crate::protocol::ConnectContext {
        remote_addr: remote_addr.to_string(),
        llm_client: llm_client.clone(),
        state: Arc::new(state.clone()),
        status_tx,
        client_id,
        startup_params: startup_params_obj,
    };

    // Connect the client
    match protocol_impl.connect(connect_ctx).await {
        Ok(_local_addr) => {
            state
                .update_client_status(client_id, ClientStatus::Connected)
                .await;
            startup_guard.disarm();
            Ok(client_id)
        }
        Err(e) => {
            state
                .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                .await;
            state.remove_client(client_id).await;
            startup_guard.disarm();
            Err(e)
        }
    }
}
