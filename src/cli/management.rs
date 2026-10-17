//! Management surface for creating and updating servers and clients.
//!
//! This module is the single source of truth for the *shape* of a server or
//! client instance — every field the `open_server` / `open_client` actions and
//! the MCP `start_server` / `start_client` tools accept — and for the two
//! operations that surface takes: **create** (spawn a brand new instance) and
//! **update** (mutate a running one, in place where possible, with a clean
//! stop+start where a change genuinely requires rebinding).
//!
//! Design rules (see the root `CLAUDE.md`):
//!
//! - **No per-protocol logic here.** Create routes through
//!   `server_startup::start_server_from_action` /
//!   `client_startup::start_client_from_action`; update reuses those same
//!   executors for the restart path. There is no per-protocol match statement.
//! - **Validate before mutating.** Startup parameters are validated against the
//!   protocol's `get_startup_parameters()` *before* the running instance is
//!   touched, so a bad update names the offending key (via `StartupParamError`,
//!   propagated with `?`) and leaves the old instance running.
//! - **Storage-free.** This is orchestration; it persists nothing itself.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::llm::actions::common::ServerTaskDefinition;
use crate::llm::actions::ParameterDefinition;
use crate::llm::OllamaClient;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ServerId};

/// The management "form": everything a caller can specify about a server
/// instance. Optional fields mean "unspecified" — on **create** an unspecified
/// field falls back to its protocol default, on **update** an unspecified field
/// is left unchanged.
///
/// This is the struct both create and update consume, so the two paths can
/// never drift apart on which fields exist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerForm {
    /// Protocol name (e.g. "http", "tcp", "dns"). Required to create; on update
    /// it is immutable — supplying a different protocol is an error.
    pub protocol: String,
    /// Port to bind (socket protocols). `Some(0)` asks the OS to assign one.
    pub port: Option<u16>,
    /// Host/IP to bind (socket protocols). Defaults to the protocol default.
    pub host: Option<String>,
    /// Interface to bind (layer-2 / raw protocols such as arp, datalink, icmp).
    pub interface: Option<String>,
    /// Source MAC (layer-2 protocols), only meaningful with `interface`.
    pub mac_address: Option<String>,
    /// Speak first on connect (FTP/SMTP-style greeting). Only honoured by
    /// protocols that declare a `send_first` startup parameter.
    #[serde(default)]
    pub send_first: bool,
    /// Natural-language LLM instruction (the fallback handling path).
    pub instruction: Option<String>,
    /// Seed the instance's LLM memory.
    pub initial_memory: Option<String>,
    /// Protocol-specific startup parameters (validated against the schema).
    pub startup_params: Option<Value>,
    /// Deterministic event handlers (script / static / llm), matched in order.
    pub event_handlers: Option<Vec<Value>>,
    /// Scheduled LLM tasks scoped to this server.
    pub scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
    /// Instructions for the automatic feedback loop.
    pub feedback_instructions: Option<String>,
    /// How many earlier entries of a connection's exchange the model is shown with each event;
    /// `0` turns history off. Omitted keeps the protocol's declared default
    /// ([`crate::protocol::metadata::HistoryMode`]). Applied in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<u16>,
    /// Deliver events arriving during a call together, in one follow-up call. Omitted keeps
    /// the protocol's declared default; refused on a protocol that cannot batch
    /// ([`crate::protocol::metadata::BatchingMode`]). Applied in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batching: Option<bool>,
}

/// The management form for a client instance. Mirrors [`ServerForm`] against the
/// `open_client` / `start_client` surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientForm {
    /// Protocol name (e.g. "redis", "http"). Required to create; immutable on
    /// update.
    pub protocol: String,
    /// Remote server address, "host:port". Required to create; changing it on
    /// update forces a reconnect (restart).
    pub remote_addr: Option<String>,
    /// Natural-language LLM instruction (the fallback handling path).
    pub instruction: Option<String>,
    /// Seed the client's LLM memory.
    pub initial_memory: Option<String>,
    /// Protocol-specific startup parameters (validated against the schema).
    pub startup_params: Option<Value>,
    /// Deterministic event handlers, matched in order.
    pub event_handlers: Option<Vec<Value>>,
    /// Scheduled LLM tasks scoped to this client.
    pub scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
    /// Instructions for the automatic feedback loop.
    pub feedback_instructions: Option<String>,
    /// How many earlier entries of a connection's exchange the model is shown with each event;
    /// `0` turns history off. Omitted keeps the protocol's declared default
    /// ([`crate::protocol::metadata::HistoryMode`]). Applied in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<u16>,
    /// Deliver events arriving during a call together, in one follow-up call. Omitted keeps
    /// the protocol's declared default; refused on a protocol that cannot batch
    /// ([`crate::protocol::metadata::BatchingMode`]). Applied in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batching: Option<bool>,
}

/// Outcome of an update: which instance it now is, and whether applying it
/// required a stop+start (which drops live connections) rather than an in-place
/// change.
#[derive(Debug, Clone)]
pub struct UpdateOutcome {
    /// The instance id after the update. Equal to the input id for a hot update;
    /// a **new** id when a restart was required (stop+start allocates a fresh id).
    pub id: u32,
    /// True when the change forced a clean stop+start.
    pub restarted: bool,
    /// Human-readable summary of what changed, for the TUI / MCP / status stream.
    pub summary: String,
}

/// Declared startup parameters for a server protocol, or `None` if the protocol
/// is not compiled into this build. Used by the TUI create form to show what a
/// chosen protocol accepts.
pub fn server_declared_params(protocol: &str) -> Option<Vec<ParameterDefinition>> {
    crate::protocol::server_registry::registry()
        .resolve(protocol)
        .ok()
        .map(|p| p.get_startup_parameters())
}

/// Declared startup parameters for a client protocol, or `None` if it is not
/// compiled into this build.
pub fn client_declared_params(protocol: &str) -> Option<Vec<ParameterDefinition>> {
    crate::protocol::CLIENT_REGISTRY
        .resolve(protocol)
        .ok()
        .map(|p| p.get_startup_parameters())
}

/// Validate declared keys, required fields and JSON types against the schema,
/// *before* any running instance is touched.
///
/// Delegates to the built-in [`StartupParams::new_validated`] check — the same validation
/// `start_server_from_action` applies at spawn — so an undeclared key is reported
/// (naming the key, via `StartupParamError`) and the running instance is left
/// alone. Running it here, before `remove_server`, is what preserves the old
/// instance when a restart-triggering `startup_params` update is bad.
fn validate_params_declared(
    params: &Value,
    schema: &[ParameterDefinition],
    protocol: &str,
) -> Result<()> {
    crate::protocol::StartupParams::preflight(params)?;
    crate::protocol::spawn_context::StartupParams::new_validated(params.clone(), schema.to_vec())
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Invalid startup_params for {}: {}", protocol, e))
}

/// Preflight shared TLS material while the current listener is still serving.
/// File access/certificate parsing can fail independently of JSON shape.
pub(crate) fn validate_server_startup_params(
    params: &Value,
    schema: &[ParameterDefinition],
    protocol: &str,
) -> Result<()> {
    validate_params_declared(params, schema, protocol)?;
    {
        let names: std::collections::HashSet<_> = schema.iter().map(|p| p.name.as_str()).collect();
        if [
            "cert_path",
            "key_path",
            "common_name",
            "san_dns_names",
            "validity_days",
            "organization",
            "organizational_unit",
        ]
        .iter()
        .all(|name| names.contains(name))
        {
            let validated =
                crate::protocol::StartupParams::new_validated(params.clone(), schema.to_vec())?;
            if names.contains("tls_enabled") {
                crate::server::tls_cert_manager::extract_tls_config_from_params(&validated)?;
            } else {
                crate::server::tls_cert_manager::extract_required_tls_config_from_params(
                    &validated,
                )?;
            }
        }
    }
    Ok(())
}

impl ServerForm {
    /// Create a brand new server from this form. Thin wrapper over the shared
    /// `start_server_from_action` executor — no logic is duplicated.
    pub async fn create(
        mut self,
        state: &AppState,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<ServerId> {
        crate::protocol::StartupParams::preflight_owned(&mut self.startup_params)?;
        let instruction = self.instruction.clone().unwrap_or_else(|| {
            format!(
                "You are a {} server. Handle requests appropriately.",
                self.protocol
            )
        });
        crate::cli::server_startup::start_server_from_action(
            state,
            self.mac_address,
            self.interface,
            self.host,
            self.port,
            &self.protocol,
            self.send_first,
            self.initial_memory,
            instruction,
            self.startup_params,
            self.event_handlers,
            self.scheduled_tasks,
            self.feedback_instructions,
            crate::protocol::metadata::ConversationOverrides {
                history: self.history,
                batching: self.batching,
            },
            status_tx,
        )
        .await
    }
}

impl ClientForm {
    /// Create a brand new client from this form. Thin wrapper over the shared
    /// `start_client_from_action` executor.
    pub async fn create(
        mut self,
        state: &AppState,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<ClientId> {
        crate::protocol::StartupParams::preflight_owned(&mut self.startup_params)?;
        let remote_addr = self
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow::anyhow!("remote_addr is required to open a client"))?;
        let instruction = self.instruction.clone().unwrap_or_else(|| {
            format!(
                "You are a {} client connected to {}. Handle responses appropriately.",
                self.protocol, remote_addr
            )
        });
        crate::cli::client_startup::start_client_from_action(
            state,
            &self.protocol,
            &remote_addr,
            instruction,
            self.startup_params,
            self.initial_memory,
            self.event_handlers,
            self.scheduled_tasks,
            self.feedback_instructions,
            crate::protocol::metadata::ConversationOverrides {
                history: self.history,
                batching: self.batching,
            },
            llm_client,
            Some(status_tx),
        )
        .await
    }
}

/// Merge a partial `overlay` object into `base`, overlay keys winning. Returns
/// the merged object. Used so a partial `startup_params` update keeps the params
/// it does not mention.
fn merge_params(base: Option<&Value>, overlay: &Value) -> Result<Value> {
    // Budget the entire borrowed input batch before cloning either object.
    if !crate::utils::json_budget::within_values_budget(
        base.into_iter().chain(std::iter::once(overlay)),
        crate::protocol::spawn_context::MAX_STARTUP_PARAM_BYTES,
        crate::protocol::spawn_context::MAX_STARTUP_PARAM_NODES,
        crate::protocol::spawn_context::MAX_STARTUP_PARAM_DEPTH,
    ) {
        return Err(anyhow::anyhow!(
            "startup_params exceeds the merged JSON size, node or depth budget"
        ));
    }
    let map = overlay
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("startup_params must be a JSON object"))?;
    let mut out = base
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for (k, v) in map {
        out.insert(k.clone(), v.clone());
    }
    Ok(Value::Object(out))
}

/// Fields on a [`ServerForm`] whose change requires a rebind (a clean stop+start
/// rather than an in-place mutation).
fn server_needs_restart(form: &ServerForm) -> bool {
    form.port.is_some()
        || form.host.is_some()
        || form.interface.is_some()
        || form.mac_address.is_some()
        || form.startup_params.is_some()
}

/// Update a running server by id, applying only the fields the caller set.
///
/// - Unknown id → clean error, nothing mutated.
/// - Protocol mismatch → error (protocol is immutable; recreate to change it).
/// - `startup_params` / `event_handlers` are validated **before** the running
///   instance is touched, so a bad update leaves the old instance working.
/// - Hot fields (instruction, memory, event handlers, feedback instructions, history, batching,
///   scheduled tasks) are applied in place, preserving live connections.
/// - Binding fields (port, host, interface, mac) or a `startup_params` change
///   force a clean stop+start; this drops connections and is reported as such.
pub async fn update_server(
    state: &AppState,
    server_id: ServerId,
    mut form: ServerForm,
    status_tx: mpsc::UnboundedSender<String>,
) -> Result<UpdateOutcome> {
    crate::protocol::StartupParams::preflight_owned(&mut form.startup_params)?;
    let current = state
        .with_server_mut(server_id, |current| {
            crate::protocol::StartupParams::preflight_owned(&mut current.startup_params)?;
            Ok::<_, crate::protocol::StartupParamError>(current.clone())
        })
        .await
        .ok_or_else(|| anyhow::anyhow!("Server #{} not found", server_id.as_u32()))??;

    // Protocol is immutable on update.
    if !form.protocol.is_empty() && !form.protocol.eq_ignore_ascii_case(&current.protocol_name) {
        return Err(anyhow::anyhow!(
            "Cannot change protocol of server #{} from '{}' to '{}'. Stop it and open a new one instead.",
            server_id.as_u32(),
            current.protocol_name,
            form.protocol
        ));
    }

    // Look the protocol up in the registry (case-insensitive via `resolve`) so we
    // can read its declared startup-parameter schema for validation.
    let protocol_impl = crate::protocol::server_registry::registry()
        .resolve(&current.protocol_name)
        .map_err(|_| {
            anyhow::anyhow!("Server protocol '{}' not available", current.protocol_name)
        })?;

    // === Validate BEFORE mutating ===
    // Compute the merged startup params that would take effect, and validate the
    // whole thing against the schema. A bad key is reported (naming the key) and
    // the running server is left untouched.
    let prepared_tasks = crate::state::task::prepare_tasks(
        form.scheduled_tasks.as_deref(),
        crate::state::task::TaskScope::Server(server_id),
    )?;
    let merged_params: Option<Value> = match &form.startup_params {
        Some(overlay) => Some(merge_params(current.startup_params.as_ref(), overlay)?),
        None => current.startup_params.clone(),
    };
    if let Some(params) = &merged_params {
        let schema = protocol_impl.get_startup_parameters();
        validate_server_startup_params(params, &schema, &current.protocol_name)?;
    }

    // Validate event handlers before mutating, too.
    if let Some(handlers) = &form.event_handlers {
        crate::events::handler::EventHandler::parse_event_handlers(handlers.clone())
            .map_err(|e| anyhow::anyhow!("Invalid event_handlers: {}", e))?;
    }

    // History and batching: what is asked for, else what the instance already has.
    let (history_entries, batching) = crate::protocol::metadata::ConversationOverrides {
        history: form.history.or(Some(current.history_entries)),
        batching: form.batching.or(Some(current.batching)),
    }
    .resolve(&protocol_impl.metadata(), &current.protocol_name)?;

    if server_needs_restart(&form) {
        // === Restart path: clean stop + start with merged config ===
        let mut changed = Vec::new();
        if form.port.is_some() {
            changed.push("port");
        }
        if form.host.is_some() {
            changed.push("host");
        }
        if form.interface.is_some() {
            changed.push("interface");
        }
        if form.mac_address.is_some() {
            changed.push("mac_address");
        }
        if form.startup_params.is_some() {
            changed.push("startup_params");
        }

        // Merge current config with the requested overrides.
        let instruction = form
            .instruction
            .clone()
            .unwrap_or(current.instruction.clone());
        let initial_memory = match &form.initial_memory {
            Some(m) => Some(m.clone()),
            None if !current.memory.is_empty() => Some(current.memory.clone()),
            None => None,
        };
        // Event handlers: use the override, else re-serialize the current config
        // so a rebind does not silently drop deterministic handlers.
        let event_handlers: Option<Vec<Value>> = match &form.event_handlers {
            Some(h) => Some(h.clone()),
            None => current.event_handler_config.as_ref().and_then(|cfg| {
                serde_json::to_value(&cfg.handlers)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
            }),
        };
        let feedback_instructions = form
            .feedback_instructions
            .clone()
            .or(current.feedback_instructions.clone());
        let port = form.port.or(Some(current.port));

        // Release the old socket and its tasks, then start fresh.
        state.remove_server(server_id).await;
        let _ = status_tx.send(format!(
            "[SERVER] Restarting server #{} ({}) to apply {}",
            server_id.as_u32(),
            current.protocol_name,
            changed.join(", ")
        ));

        let new_id = crate::cli::server_startup::start_server_from_action(
            state,
            form.mac_address,
            form.interface,
            form.host,
            port,
            &current.protocol_name,
            form.send_first,
            initial_memory,
            instruction,
            merged_params,
            event_handlers,
            form.scheduled_tasks,
            feedback_instructions,
            crate::protocol::metadata::ConversationOverrides {
                history: Some(history_entries),
                batching: Some(batching),
            },
            status_tx.clone(),
        )
        .await?;

        let summary = format!(
            "Server #{} restarted as #{} (changed: {}); live connections were dropped.",
            server_id.as_u32(),
            new_id.as_u32(),
            changed.join(", ")
        );
        let _ = status_tx.send(format!("[SERVER] {}", summary));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        return Ok(UpdateOutcome {
            id: new_id.as_u32(),
            restarted: true,
            summary,
        });
    }

    // === Hot path: mutate in place, connections preserved ===
    let mut changed = Vec::new();

    if let Some(instruction) = &form.instruction {
        state.set_instruction(server_id, instruction.clone()).await;
        changed.push("instruction");
    }
    if let Some(memory) = &form.initial_memory {
        state.set_memory(server_id, memory.clone()).await;
        changed.push("memory");
    }
    if let Some(handlers) = &form.event_handlers {
        // Already validated above.
        let config = crate::events::handler::EventHandler::parse_event_handlers(handlers.clone())
            .map_err(|e| anyhow::anyhow!("Invalid event_handlers: {}", e))?;
        state
            .with_server_mut(server_id, |s| {
                s.event_handler_config = Some(config);
            })
            .await;
        changed.push("event_handlers");
    }
    if let Some(fb) = &form.feedback_instructions {
        state
            .with_server_mut(server_id, |s| {
                s.feedback_instructions = Some(fb.clone());
            })
            .await;
        changed.push("feedback_instructions");
    }
    if form.history.is_some() || form.batching.is_some() {
        state
            .set_server_conversation_settings(server_id, history_entries, batching)
            .await;
        if form.history.is_some() {
            changed.push("history");
        }
        if form.batching.is_some() {
            changed.push("batching");
        }
    }
    if let Some(tasks) = form.scheduled_tasks {
        let n = tasks.len();
        for task in prepared_tasks {
            state.add_task(task).await;
        }
        if n > 0 {
            changed.push("scheduled_tasks");
        }
    }

    let summary = if changed.is_empty() {
        format!("Server #{}: nothing to update.", server_id.as_u32())
    } else {
        format!(
            "Server #{} updated in place ({}); connections preserved.",
            server_id.as_u32(),
            changed.join(", ")
        )
    };
    let _ = status_tx.send(format!("[SERVER] {}", summary));
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    Ok(UpdateOutcome {
        id: server_id.as_u32(),
        restarted: false,
        summary,
    })
}

/// Fields on a [`ClientForm`] whose change requires a reconnect.
fn client_needs_restart(form: &ClientForm) -> bool {
    form.remote_addr.is_some() || form.startup_params.is_some()
}

/// Update a running client by id. Mirror of [`update_server`]: unknown id and
/// bad params error cleanly without touching the instance; a `remote_addr` or
/// `startup_params` change reconnects, everything else is applied in place.
pub async fn update_client(
    state: &AppState,
    client_id: ClientId,
    mut form: ClientForm,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
) -> Result<UpdateOutcome> {
    crate::protocol::StartupParams::preflight_owned(&mut form.startup_params)?;
    let current = state
        .with_client_mut(client_id, |current| {
            crate::protocol::StartupParams::preflight_owned(&mut current.startup_params)?;
            Ok::<_, crate::protocol::StartupParamError>(current.clone())
        })
        .await
        .ok_or_else(|| anyhow::anyhow!("Client #{} not found", client_id.as_u32()))??;

    if !form.protocol.is_empty() && !form.protocol.eq_ignore_ascii_case(&current.protocol_name) {
        return Err(anyhow::anyhow!(
            "Cannot change protocol of client #{} from '{}' to '{}'. Stop it and open a new one instead.",
            client_id.as_u32(),
            current.protocol_name,
            form.protocol
        ));
    }

    // Look the client protocol up (case-insensitive via `resolve`) for its
    // declared startup-parameter schema.
    let protocol_impl = crate::protocol::CLIENT_REGISTRY
        .resolve(&current.protocol_name)
        .map_err(|_| {
            anyhow::anyhow!("Client protocol '{}' not available", current.protocol_name)
        })?;

    // Validate merged params before mutating.
    let prepared_tasks = crate::state::task::prepare_tasks(
        form.scheduled_tasks.as_deref(),
        crate::state::task::TaskScope::Client(client_id),
    )?;
    let merged_params: Option<Value> = match &form.startup_params {
        Some(overlay) => Some(merge_params(current.startup_params.as_ref(), overlay)?),
        None => current.startup_params.clone(),
    };
    if let Some(params) = &merged_params {
        let schema = protocol_impl.get_startup_parameters();
        validate_params_declared(params, &schema, &current.protocol_name)?;
    }

    // Validate event handlers before mutating (clients parse each handler value).
    if let Some(handlers) = &form.event_handlers {
        validate_client_handlers(handlers)?;
    }

    // History and batching: what is asked for, else what the client already has.
    let (history_entries, batching) = crate::protocol::metadata::ConversationOverrides {
        history: form.history.or(Some(current.history_entries)),
        batching: form.batching.or(Some(current.batching)),
    }
    .resolve(&protocol_impl.metadata(), &current.protocol_name)?;

    if client_needs_restart(&form) {
        let mut changed = Vec::new();
        if form.remote_addr.is_some() {
            changed.push("remote_addr");
        }
        if form.startup_params.is_some() {
            changed.push("startup_params");
        }

        let remote_addr = form
            .remote_addr
            .clone()
            .unwrap_or(current.remote_addr.clone());
        let instruction = form
            .instruction
            .clone()
            .unwrap_or(current.instruction.clone());
        let initial_memory = match &form.initial_memory {
            Some(m) => Some(m.clone()),
            None if !current.memory.is_empty() => Some(current.memory.clone()),
            None => None,
        };
        let event_handlers: Option<Vec<Value>> = match &form.event_handlers {
            Some(h) => Some(h.clone()),
            None => current.event_handler_config.as_ref().and_then(|cfg| {
                serde_json::to_value(&cfg.handlers)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
            }),
        };
        let feedback_instructions = form
            .feedback_instructions
            .clone()
            .or(current.feedback_instructions.clone());

        // Release the old client (aborts its tasks / socket) then reconnect.
        state.remove_client(client_id).await;
        let _ = status_tx.send(format!(
            "[CLIENT] Reconnecting client #{} ({}) to apply {}",
            client_id.as_u32(),
            current.protocol_name,
            changed.join(", ")
        ));

        let new_id = crate::cli::client_startup::start_client_from_action(
            state,
            &current.protocol_name,
            &remote_addr,
            instruction,
            merged_params,
            initial_memory,
            event_handlers,
            form.scheduled_tasks,
            feedback_instructions,
            crate::protocol::metadata::ConversationOverrides {
                history: Some(history_entries),
                batching: Some(batching),
            },
            llm_client,
            Some(status_tx.clone()),
        )
        .await?;

        let summary = format!(
            "Client #{} reconnected as #{} (changed: {}).",
            client_id.as_u32(),
            new_id.as_u32(),
            changed.join(", ")
        );
        let _ = status_tx.send(format!("[CLIENT] {}", summary));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        return Ok(UpdateOutcome {
            id: new_id.as_u32(),
            restarted: true,
            summary,
        });
    }

    // Hot path.
    let mut changed = Vec::new();
    if let Some(instruction) = &form.instruction {
        state
            .set_instruction_for_client(client_id, instruction.clone())
            .await;
        changed.push("instruction");
    }
    if let Some(memory) = &form.initial_memory {
        state.set_memory_for_client(client_id, memory.clone()).await;
        changed.push("memory");
    }
    if let Some(handlers) = &form.event_handlers {
        let config = parse_client_handlers(handlers)?;
        state
            .with_client_mut(client_id, |c| {
                c.event_handler_config = Some(config);
            })
            .await;
        changed.push("event_handlers");
    }
    if let Some(fb) = &form.feedback_instructions {
        state
            .with_client_mut(client_id, |c| {
                c.feedback_instructions = Some(fb.clone());
            })
            .await;
        changed.push("feedback_instructions");
    }
    if form.history.is_some() || form.batching.is_some() {
        state
            .set_client_conversation_settings(client_id, history_entries, batching)
            .await;
        if form.history.is_some() {
            changed.push("history");
        }
        if form.batching.is_some() {
            changed.push("batching");
        }
    }
    if let Some(tasks) = form.scheduled_tasks {
        let n = tasks.len();
        for task in prepared_tasks {
            state.add_task(task).await;
        }
        if n > 0 {
            changed.push("scheduled_tasks");
        }
    }

    let summary = if changed.is_empty() {
        format!("Client #{}: nothing to update.", client_id.as_u32())
    } else {
        format!(
            "Client #{} updated in place ({}).",
            client_id.as_u32(),
            changed.join(", ")
        )
    };
    let _ = status_tx.send(format!("[CLIENT] {}", summary));
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    Ok(UpdateOutcome {
        id: client_id.as_u32(),
        restarted: false,
        summary,
    })
}

/// Validate client event handler JSON without mutating anything.
fn validate_client_handlers(handlers: &[Value]) -> Result<()> {
    parse_client_handlers(handlers).map(|_| ())
}

/// Parse client event handler JSON into an [`EventHandlerConfig`].
///
/// Clients deserialize each handler value directly (as `start_client_from_action`
/// does); an entry that fails to parse is a hard error rather than silently
/// dropped, so a bad update is reported instead of applied partially.
fn parse_client_handlers(handlers: &[Value]) -> Result<crate::scripting::EventHandlerConfig> {
    use crate::scripting::{EventHandler, EventHandlerConfig};
    let mut parsed = Vec::with_capacity(handlers.len());
    for (i, h) in handlers.iter().enumerate() {
        let handler: EventHandler = serde_json::from_value(h.clone())
            .map_err(|e| anyhow::anyhow!("Invalid event_handlers[{}]: {}", i, e))?;
        parsed.push(handler);
    }
    Ok(EventHandlerConfig { handlers: parsed })
}

// ===========================================================================
// Interactive form (TUI `/create` and `/edit`)
// ===========================================================================
//
// The interactive create/update form walks one field at a time: the operator is
// shown a field's name/type/required flag/help, the footer input is prefilled
// with the field's default (create) or current value (update), they edit it, and
// Enter advances to the next field. On the last field the collected values are
// assembled into a [`ServerForm`]/[`ClientForm`] and handed to the existing
// `.create()` / [`update_server`] / [`update_client`] executors — no create or
// update logic is duplicated here, and startup params are validated by those
// executors exactly as any other caller's would be.
//
// The field *model*, prefill, and the collected-values → form assembly all live
// here (next to `ServerForm`/`ClientForm`, and unit-testable without a live TUI);
// The UI owns only the keystroke plumbing that drives it.

/// Which operation an [`InteractiveForm`] will perform on submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormTarget {
    /// Create a new server of `protocol`.
    CreateServer,
    /// Create a new client of `protocol`.
    CreateClient,
    /// Update the running server with this unified id.
    UpdateServer(u32),
    /// Update the running client with this unified id.
    UpdateClient(u32),
}

/// How a filled-in [`FormField`] maps onto a `ServerForm`/`ClientForm`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldTarget {
    Port,
    RemoteAddr,
    Instruction,
    Memory,
    EventHandlers,
    FeedbackInstructions,
    /// A protocol-declared startup parameter, carrying its declared type hint so
    /// the entered text can be coerced to the right JSON shape.
    StartupParam {
        type_hint: String,
    },
}

/// One editable field in an interactive form.
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name — a common field label (`port`, `instruction`, …) or a startup
    /// parameter's declared key.
    pub name: String,
    /// Type hint shown to the operator (`u16`, `string`, `json`, the declared
    /// param type, …).
    pub type_label: String,
    /// Whether the field is required (only startup params are ever required; the
    /// common fields all fall back to protocol defaults / current values).
    pub required: bool,
    /// Human-readable help.
    pub help: String,
    /// Text the footer input is prefilled with when this field becomes active.
    pub prefill: String,
    /// The value the operator submitted (trimmed). `None` until submitted; an
    /// empty string means "unspecified" — protocol default on create, unchanged
    /// on update.
    pub value: Option<String>,
    target: FieldTarget,
}

/// An in-progress interactive create/update form.
#[derive(Debug, Clone)]
pub struct InteractiveForm {
    /// What the form will do on submit.
    pub target: FormTarget,
    /// The protocol name (immutable — not itself an editable field).
    pub protocol: String,
    /// The ordered fields.
    pub fields: Vec<FormField>,
    /// Index of the field currently being edited.
    pub index: usize,
}

/// Current server config used to prefill an update form. A plain snapshot so the
/// form builder stays decoupled from the live state types (and unit-testable).
#[derive(Debug, Clone, Default)]
pub struct ServerPrefill {
    pub instruction: String,
    pub memory: String,
    pub port: u16,
    pub startup_params: Option<Value>,
    pub event_handlers: Option<Vec<Value>>,
    pub feedback_instructions: Option<String>,
}

impl ServerPrefill {
    /// Snapshot a running server for an update form.
    ///
    /// `port` is the port the server is **actually bound to** — `local_addr`, falling back to
    /// the requested `port` only when nothing has bound yet. Those two differ exactly when the
    /// request was `port: 0`, and prefilling the literal `0` there is not cosmetic: an update
    /// form is a snapshot the operator edits in place, so a form showing `0` invites
    /// submitting `0`, which is a request to bind *a different* random port. The operator
    /// changes one handler and the server moves out from under every client connected to it.
    ///
    /// Constructing this by hand is what let the three call sites drift: the dashboard tree
    /// resolved the bound port, and the legacy TUI's edit form did not.
    pub fn from_server(server: &crate::state::server::ServerInstance) -> Self {
        Self {
            instruction: server.instruction.clone(),
            memory: server.memory.clone(),
            port: server
                .local_addr
                .map(|a| a.port())
                .filter(|p| *p != 0)
                .unwrap_or(server.port),
            startup_params: server.startup_params.clone(),
            event_handlers: server.event_handler_config.as_ref().and_then(|c| {
                serde_json::to_value(&c.handlers)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
            }),
            feedback_instructions: server.feedback_instructions.clone(),
        }
    }
}

/// Current client config used to prefill an update form.
#[derive(Debug, Clone, Default)]
pub struct ClientPrefill {
    pub remote_addr: String,
    pub instruction: String,
    pub memory: String,
    pub startup_params: Option<Value>,
    pub event_handlers: Option<Vec<Value>>,
    pub feedback_instructions: Option<String>,
}

/// Render a startup-param value already present in a config back to the text an
/// operator would edit: a JSON string yields its bare contents, everything else
/// its compact JSON form.
fn param_value_to_prefill(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Turn a protocol's declared startup parameters into form fields, prefilling from
/// `current` (an update's existing `startup_params`) when present, else from the
/// declared example for a required param (so a required field is not left blank).
fn startup_param_fields(schema: &[ParameterDefinition], current: Option<&Value>) -> Vec<FormField> {
    let current_obj = current.and_then(|v| v.as_object());
    schema
        .iter()
        .map(|p| {
            let prefill = current_obj
                .and_then(|o| o.get(&p.name))
                .map(param_value_to_prefill)
                .unwrap_or_default();
            FormField {
                name: p.name.clone(),
                type_label: p.type_hint.clone(),
                required: p.required,
                help: p.description.clone(),
                prefill,
                value: None,
                target: FieldTarget::StartupParam {
                    type_hint: p.type_hint.clone(),
                },
            }
        })
        .collect()
}

fn field(name: &str, ty: &str, help: &str, prefill: String, target: FieldTarget) -> FormField {
    FormField {
        name: name.to_string(),
        type_label: ty.to_string(),
        required: false,
        help: help.to_string(),
        prefill,
        value: None,
        target,
    }
}

/// Serialize existing event handlers to the compact JSON array text an operator
/// edits. Empty / absent handlers prefill as empty.
fn handlers_to_prefill(handlers: &Option<Vec<Value>>) -> String {
    match handlers {
        Some(h) if !h.is_empty() => serde_json::to_string(h).unwrap_or_default(),
        _ => String::new(),
    }
}

impl InteractiveForm {
    /// Build a create form for a server protocol from its declared startup params.
    pub fn create_server(protocol: &str, schema: &[ParameterDefinition]) -> Self {
        let mut fields = common_server_fields(&ServerPrefill::default(), false);
        fields.extend(startup_param_fields(schema, None));
        Self {
            target: FormTarget::CreateServer,
            protocol: protocol.to_string(),
            fields,
            index: 0,
        }
    }

    /// Build a create form for a client protocol.
    pub fn create_client(protocol: &str, schema: &[ParameterDefinition]) -> Self {
        let mut fields = common_client_fields(&ClientPrefill::default(), false);
        fields.extend(startup_param_fields(schema, None));
        Self {
            target: FormTarget::CreateClient,
            protocol: protocol.to_string(),
            fields,
            index: 0,
        }
    }

    /// Build an update form for a running server, prefilled from its current
    /// config plus the current values of any declared startup params.
    pub fn update_server(
        id: u32,
        protocol: &str,
        schema: &[ParameterDefinition],
        current: &ServerPrefill,
    ) -> Self {
        let mut fields = common_server_fields(current, true);
        fields.extend(startup_param_fields(
            schema,
            current.startup_params.as_ref(),
        ));
        Self {
            target: FormTarget::UpdateServer(id),
            protocol: protocol.to_string(),
            fields,
            index: 0,
        }
    }

    /// Build an update form for a running client.
    pub fn update_client(
        id: u32,
        protocol: &str,
        schema: &[ParameterDefinition],
        current: &ClientPrefill,
    ) -> Self {
        let mut fields = common_client_fields(current, true);
        fields.extend(startup_param_fields(
            schema,
            current.startup_params.as_ref(),
        ));
        Self {
            target: FormTarget::UpdateClient(id),
            protocol: protocol.to_string(),
            fields,
            index: 0,
        }
    }

    /// The field currently being edited, if the form is not yet complete.
    pub fn current_field(&self) -> Option<&FormField> {
        self.fields.get(self.index)
    }

    /// A one-line prompt describing the current field.
    pub fn prompt(&self) -> String {
        match self.current_field() {
            None => "Form complete.".to_string(),
            Some(f) => {
                let req = if f.required { ", required" } else { "" };
                let hint = if f.required {
                    "  (required)"
                } else if matches!(
                    self.target,
                    FormTarget::CreateServer | FormTarget::CreateClient
                ) {
                    "  (empty = protocol default)"
                } else {
                    "  (empty = keep current)"
                };
                format!(
                    "Field {}/{}: {} ({}{}) — {}{}",
                    self.index + 1,
                    self.fields.len(),
                    f.name,
                    f.type_label,
                    req,
                    f.help,
                    hint,
                )
            }
        }
    }

    /// A short title for the whole form, e.g. `Create http server`.
    pub fn title(&self) -> String {
        match self.target {
            FormTarget::CreateServer => format!("Create {} server", self.protocol),
            FormTarget::CreateClient => format!("Create {} client", self.protocol),
            FormTarget::UpdateServer(id) => {
                format!("Update {} server #{}", self.protocol, id)
            }
            FormTarget::UpdateClient(id) => {
                format!("Update {} client #{}", self.protocol, id)
            }
        }
    }

    /// The prefill text for the current field (what the input should show).
    pub fn current_prefill(&self) -> String {
        self.current_field()
            .map(|f| f.prefill.clone())
            .unwrap_or_default()
    }

    /// Record `raw` as the current field's value (trimmed) and advance.
    pub fn submit_current(&mut self, raw: &str) {
        if let Some(f) = self.fields.get_mut(self.index) {
            f.value = Some(raw.trim().to_string());
        }
        self.index += 1;
    }

    /// Directly set a field's value by name (used by tests and any non-sequential
    /// caller). Returns false if no such field.
    pub fn set_field_value(&mut self, name: &str, value: &str) -> bool {
        if let Some(f) = self.fields.iter_mut().find(|f| f.name == name) {
            f.value = Some(value.trim().to_string());
            true
        } else {
            false
        }
    }

    /// True once every field has been submitted.
    pub fn is_complete(&self) -> bool {
        self.index >= self.fields.len()
    }

    fn is_client(&self) -> bool {
        matches!(
            self.target,
            FormTarget::CreateClient | FormTarget::UpdateClient(_)
        )
    }

    fn is_update(&self) -> bool {
        matches!(
            self.target,
            FormTarget::UpdateServer(_) | FormTarget::UpdateClient(_)
        )
    }

    /// The value a field contributes to the built form, or `None` if it should be
    /// left out.
    ///
    /// - **Create**: a non-empty submitted value is used; empty means "use the
    ///   protocol default".
    /// - **Update**: a non-empty value that *differs from the prefill* is used;
    ///   an unchanged (equal to prefill) or empty value means "leave as-is". This
    ///   is what keeps an update that only touches, say, the instruction from
    ///   re-submitting the unchanged port and forcing a needless restart.
    fn effective_value<'a>(&self, f: &'a FormField) -> Option<&'a str> {
        let trimmed = f.value.as_deref().unwrap_or("").trim();
        if trimmed.is_empty() {
            return None;
        }
        if self.is_update() && trimmed == f.prefill.trim() {
            return None;
        }
        Some(trimmed)
    }

    /// Assemble the collected field values into a [`ServerForm`]. Errors (naming
    /// the field) on an unparseable value; the executors do the schema validation.
    pub fn into_server_form(&self) -> Result<ServerForm> {
        if self.is_client() {
            anyhow::bail!("into_server_form called on a client form");
        }
        let mut form = ServerForm {
            protocol: self.protocol.clone(),
            ..Default::default()
        };
        let mut params = serde_json::Map::new();
        for f in &self.fields {
            let v = match self.effective_value(f) {
                Some(v) => v,
                None => continue, // unspecified (create) / unchanged (update)
            };
            apply_common_field(f, v, &mut params, |t, val| match t {
                FieldTarget::Port => {
                    form.port = Some(parse_port(val, &f.name)?);
                    Ok(())
                }
                FieldTarget::Instruction => {
                    form.instruction = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::Memory => {
                    form.initial_memory = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::EventHandlers => {
                    form.event_handlers = Some(parse_handlers(val)?);
                    Ok(())
                }
                FieldTarget::FeedbackInstructions => {
                    form.feedback_instructions = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::RemoteAddr => Ok(()), // not a server field
                FieldTarget::StartupParam { .. } => unreachable!(),
            })?;
        }
        if !params.is_empty() {
            form.startup_params = Some(Value::Object(params));
        }
        Ok(form)
    }

    /// Assemble the collected field values into a [`ClientForm`].
    pub fn into_client_form(&self) -> Result<ClientForm> {
        if !self.is_client() {
            anyhow::bail!("into_client_form called on a server form");
        }
        let mut form = ClientForm {
            protocol: self.protocol.clone(),
            ..Default::default()
        };
        let mut params = serde_json::Map::new();
        for f in &self.fields {
            let v = match self.effective_value(f) {
                Some(v) => v,
                None => continue,
            };
            apply_common_field(f, v, &mut params, |t, val| match t {
                FieldTarget::RemoteAddr => {
                    form.remote_addr = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::Instruction => {
                    form.instruction = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::Memory => {
                    form.initial_memory = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::EventHandlers => {
                    form.event_handlers = Some(parse_handlers(val)?);
                    Ok(())
                }
                FieldTarget::FeedbackInstructions => {
                    form.feedback_instructions = Some(val.to_string());
                    Ok(())
                }
                FieldTarget::Port => Ok(()), // not a client field
                FieldTarget::StartupParam { .. } => unreachable!(),
            })?;
        }
        if !params.is_empty() {
            form.startup_params = Some(Value::Object(params));
        }
        Ok(form)
    }
}

/// The common (non-startup-param) fields of a server form, prefilled from
/// `current` when `update` is true.
fn common_server_fields(current: &ServerPrefill, update: bool) -> Vec<FormField> {
    let (port, instr, mem, fb) = if update {
        (
            current.port.to_string(),
            current.instruction.clone(),
            current.memory.clone(),
            current.feedback_instructions.clone().unwrap_or_default(),
        )
    } else {
        ("0".to_string(), String::new(), String::new(), String::new())
    };
    vec![
        field(
            "port",
            "u16",
            "Port to bind (0 = OS-assigns a free port)",
            port,
            FieldTarget::Port,
        ),
        field(
            "instruction",
            "string",
            "Natural-language LLM instruction (fallback handling path)",
            instr,
            FieldTarget::Instruction,
        ),
        field(
            "initial_memory",
            "string",
            "Seed the instance's LLM memory",
            mem,
            FieldTarget::Memory,
        ),
        field(
            "event_handlers",
            "json array",
            "Deterministic handlers, e.g. [{\"event_pattern\":\"http_request\",\"handler\":{\"type\":\"static\",...}}]",
            if update { handlers_to_prefill(&current.event_handlers) } else { String::new() },
            FieldTarget::EventHandlers,
        ),
        field(
            "feedback_instructions",
            "string",
            "Instructions for the automatic feedback loop",
            fb,
            FieldTarget::FeedbackInstructions,
        ),
    ]
}

/// The common fields of a client form.
fn common_client_fields(current: &ClientPrefill, update: bool) -> Vec<FormField> {
    let (instr, mem, fb) = if update {
        (
            current.instruction.clone(),
            current.memory.clone(),
            current.feedback_instructions.clone().unwrap_or_default(),
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    let mut remote = field(
        "remote_addr",
        "string",
        "Remote server address, host:port",
        if update {
            current.remote_addr.clone()
        } else {
            String::new()
        },
        FieldTarget::RemoteAddr,
    );
    // remote_addr is the one required common field on create.
    remote.required = !update;
    vec![
        remote,
        field(
            "instruction",
            "string",
            "Natural-language LLM instruction (fallback handling path)",
            instr,
            FieldTarget::Instruction,
        ),
        field(
            "initial_memory",
            "string",
            "Seed the instance's LLM memory",
            mem,
            FieldTarget::Memory,
        ),
        field(
            "event_handlers",
            "json array",
            "Deterministic handlers (JSON array)",
            if update {
                handlers_to_prefill(&current.event_handlers)
            } else {
                String::new()
            },
            FieldTarget::EventHandlers,
        ),
        field(
            "feedback_instructions",
            "string",
            "Instructions for the automatic feedback loop",
            fb,
            FieldTarget::FeedbackInstructions,
        ),
    ]
}

/// Dispatch a non-empty field value: startup params are coerced and inserted into
/// `params`; everything else is handed to `set_common` (which writes the matching
/// form field).
fn apply_common_field(
    f: &FormField,
    v: &str,
    params: &mut serde_json::Map<String, Value>,
    set_common: impl FnOnce(&FieldTarget, &str) -> Result<()>,
) -> Result<()> {
    if let FieldTarget::StartupParam { type_hint } = &f.target {
        params.insert(f.name.clone(), coerce_param_value(v, type_hint, &f.name)?);
        Ok(())
    } else {
        set_common(&f.target, v)
    }
}

fn parse_port(v: &str, name: &str) -> Result<u16> {
    v.parse::<u16>().map_err(|_| {
        anyhow::anyhow!(
            "field '{}' must be a port number 0-65535, got '{}'",
            name,
            v
        )
    })
}

fn parse_handlers(v: &str) -> Result<Vec<Value>> {
    let parsed: Value = serde_json::from_str(v)
        .map_err(|e| anyhow::anyhow!("field 'event_handlers' is not valid JSON: {}", e))?;
    parsed
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("field 'event_handlers' must be a JSON array"))
}

/// Coerce entered text to a JSON value according to the declared type hint.
/// Numbers/booleans/objects/arrays are parsed; anything else stays a string. On a
/// declared numeric/boolean field that fails to parse, error (naming the field)
/// rather than silently shipping a string the schema will reject.
fn coerce_param_value(raw: &str, type_hint: &str, name: &str) -> Result<Value> {
    let hint = type_hint.to_lowercase();
    if hint.contains("bool") {
        return raw
            .parse::<bool>()
            .map(Value::Bool)
            .map_err(|_| anyhow::anyhow!("field '{}' must be true/false, got '{}'", name, raw));
    }
    if hint.contains("int")
        || hint.contains("number")
        || hint.contains("u16")
        || hint.contains("u32")
    {
        if let Ok(n) = raw.parse::<i64>() {
            return Ok(Value::from(n));
        }
        if let Ok(fl) = raw.parse::<f64>() {
            return Ok(Value::from(fl));
        }
        anyhow::bail!("field '{}' must be a number, got '{}'", name, raw);
    }
    if hint.contains("object") || hint.contains("array") || hint.contains("json") {
        return serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("field '{}' must be valid JSON: {}", name, e));
    }
    Ok(Value::String(raw.to_string()))
}
