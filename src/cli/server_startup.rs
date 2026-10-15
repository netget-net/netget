//! Server startup logic for TUI mode
//!
//! Handles spawning TCP and HTTP servers based on application state

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::events::ActionExecutionError;
use crate::llm::OllamaClient;
use crate::protocol::metadata::DevelopmentState;
use crate::state::app_state::AppState;
use crate::state::ServerId;

/// Format the refusal message when a protocol is below the operator's
/// `--min-stability` floor.
///
/// Names the protocol, its actual declared state and the required minimum, so
/// the reason is legible in the TUI, the status stream and any MCP tool error —
/// mirroring how the privilege and dependency gates report a refusal. Shared
/// with `client_startup` so servers and clients speak with one voice.
pub(crate) fn min_stability_refusal(
    kind: &str,
    protocol: &str,
    actual: DevelopmentState,
    min: DevelopmentState,
) -> String {
    format!(
        "Cannot start {protocol} {kind}: its stability is {} but --min-stability requires at least \
         {}. Raise the protocol's maturity or lower --min-stability.",
        actual.as_str(),
        min.as_str()
    )
}

/// Did `spawn()` actually bind a listening socket?
///
/// `ProtocolServer::spawn` returns a `SocketAddr` for every protocol, but not
/// every protocol listens: WebRTC is peer-to-peer and returns a placeholder
/// `0.0.0.0:0`, and a couple of others fall back to the same placeholder when
/// they have no address to report. Port 0 is never a real bound port (the OS
/// resolves it to a concrete one at bind time), so it is an exact test for the
/// placeholder - and printing "listening on 0.0.0.0:0" for those servers told
/// the user, the TUI and every log reader something untrue.
fn is_bound_addr(addr: &SocketAddr) -> bool {
    addr.port() != 0
}

/// Check if an error is due to address already in use
fn is_addr_in_use_error(err: &anyhow::Error) -> bool {
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        io_err.kind() == std::io::ErrorKind::AddrInUse
    } else {
        false
    }
}

/// Start a specific server by ID
pub async fn start_server_by_id(
    state: &AppState,
    server_id: ServerId,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<(), ActionExecutionError> {
    // Get server info
    let server = match state
        .with_server_mut(server_id, |current| {
            crate::protocol::StartupParams::preflight_owned(&mut current.startup_params)?;
            Ok::<_, crate::protocol::StartupParamError>(current.clone())
        })
        .await
    {
        Some(Ok(current)) => current,
        Some(Err(error)) => return Err(ActionExecutionError::Fatal(error.into())),
        None => {
            let _ = status_tx.send(format!("[ERROR] Server #{} not found", server_id.as_u32()));
            return Ok(());
        }
    };

    // Build listen address
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", server.port)
        .parse()
        .map_err(|e| ActionExecutionError::Fatal(anyhow::anyhow!("Invalid address: {}", e)))?;

    let protocol_name = server.protocol_name.clone();

    // Actually spawn the server using the registry
    use crate::state::server::ServerStatus;

    // Get protocol implementation from registry
    let protocol = crate::protocol::server_registry::registry()
        .resolve(&protocol_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Check privilege requirements before spawning
    let metadata = protocol.metadata();

    // === --min-stability gate ===
    // Refuse a protocol below the operator's maturity floor before any spawn.
    // This is the authoritative enforcement point: even if the LLM was somehow
    // offered a forbidden protocol, it cannot be started.
    if let Some(min) = state.get_min_stability().await {
        if metadata.state < min {
            let full_error = min_stability_refusal("server", &protocol_name, metadata.state, min);
            state
                .update_server_status(server_id, ServerStatus::Error(full_error.clone()))
                .await;
            let _ = status_tx.send(format!("[ERROR] {}", full_error));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return Err(ActionExecutionError::Fatal(anyhow::anyhow!(full_error)));
        }
    }

    let system_caps = state.get_system_capabilities().await;
    // The requirement for this start: a protocol's unprivileged test transport needs none.
    let privilege_requirement =
        protocol.startup_privilege_requirement(server.startup_params.as_ref());

    // Decide whether this start is blocked for lack of privilege.
    //
    // `is_met_by()` is the single source of truth: it maps each requirement onto
    // the capability that actually satisfies it (`RawSockets` -> raw-socket
    // access, `Root` -> root, `PrivilegedPort` -> privileged-port binding).
    // Anything else ANDed in here silently overrides it - in particular, gating a
    // `RawSockets` protocol on `can_bind_privileged_ports` let it through on a
    // host that cannot open raw sockets.
    let privilege_met = privilege_requirement.is_met_by(&system_caps);

    let requires_privileges = match &privilege_requirement {
        crate::protocol::metadata::PrivilegeRequirement::PrivilegedPort(_) => {
            // Only require privileges if actually binding to a privileged port.
            // Port 0 means OS-assigned port, which will always be unprivileged (>1024)
            server.port > 0 && server.port < 1024 && !privilege_met
        }
        // RawSockets, Root, None: the requirement itself is the whole test.
        _ => !privilege_met,
    };

    if requires_privileges {
        let error_msg = format!(
            "Cannot start {} server on port {}: {}. Current capabilities: {}",
            protocol_name,
            server.port,
            privilege_requirement.description(),
            system_caps.description()
        );

        // Provide helpful suggestion based on platform
        let suggestion = if cfg!(target_os = "linux") {
            match &privilege_requirement {
                crate::protocol::metadata::PrivilegeRequirement::PrivilegedPort(port) => {
                    format!("\nSuggestion: Run as root (sudo) or use a port >= 1024 (e.g., {}, {}, {})",
                        port + 8000, port + 10000, 8080)
                }
                crate::protocol::metadata::PrivilegeRequirement::RawSockets => {
                    "\nSuggestion: Run as root or grant CAP_NET_RAW: sudo setcap cap_net_raw+ep /path/to/netget".to_string()
                }
                crate::protocol::metadata::PrivilegeRequirement::Root => {
                    "\nSuggestion: Run as root (sudo netget ...)".to_string()
                }
                _ => String::new(),
            }
        } else if cfg!(target_os = "macos") {
            "\nSuggestion: Run as root (sudo netget ...)".to_string()
        } else {
            "\nSuggestion: Run as Administrator".to_string()
        };

        let full_error = format!("{}{}", error_msg, suggestion);

        state
            .update_server_status(server_id, ServerStatus::Error(full_error.clone()))
            .await;
        let _ = status_tx.send(format!("[ERROR] {}", full_error));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        return Err(ActionExecutionError::PrivilegeDenied {
            requirement: privilege_requirement.description(),
            message: full_error,
        });
    }

    // Non-privilege dependencies: a missing system library or tool in PATH.
    //
    // `Protocol::get_dependencies()` derives from `privilege_requirement`, which the block
    // above already enforced — re-checking those here would report the same failure twice with
    // a worse message. What it cannot express is a library or binary the protocol needs at
    // runtime, which a protocol supplies by overriding `get_dependencies()`. Those had no gate
    // at all: the TUI and the model's protocol list would exclude such a protocol while a
    // direct `start_server` still attempted it and failed with whatever raw error the
    // underlying library produced.
    //
    // Only definitively-unmet dependencies refuse (`dependencies::startup_blocker`): a probe
    // that could not answer is logged and let through. `DeviceAccess` deliberately derives no
    // dependency because no probe can answer honestly for an adapter or reader, and this gate
    // must never turn "we could not tell" into "no".
    let blocker = crate::protocol::dependencies::startup_blocker(
        &protocol.startup_dependencies(server.startup_params.as_ref()),
        &system_caps,
    );

    if let Some(dep) = blocker {
        let full_error = format!(
            "Cannot start {} server on port {}: {}. {}",
            protocol_name,
            server.port,
            dep.description(),
            dep.installation_hint()
        );

        state
            .update_server_status(server_id, ServerStatus::Error(full_error.clone()))
            .await;
        let _ = status_tx.send(format!("[ERROR] {}", full_error));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        return Err(ActionExecutionError::PrivilegeDenied {
            requirement: dep.name(),
            message: full_error,
        });
    }

    // Build type-safe startup params if provided
    //
    // The JSON comes from the LLM or an MCP client, so a bad key must become a
    // reported error (and an `Error` server status), never a panic.
    let startup_params = if let Some(params_json) = server.startup_params.clone() {
        // Get the parameter schema from the protocol
        let schema = protocol.get_startup_parameters();
        // Create validated StartupParams
        match crate::protocol::StartupParams::new_validated(params_json, schema) {
            Ok(p) => Some(p),
            Err(e) => {
                let msg = format!("Invalid startup_params for {}: {}", protocol_name, e);
                state
                    .update_server_status(server_id, ServerStatus::Error(msg.clone()))
                    .await;
                let _ = status_tx.send(format!("[ERROR] {}", msg));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return Err(ActionExecutionError::Fatal(anyhow::anyhow!(msg)));
            }
        }
    } else {
        None
    };

    // Build spawn context
    // NOTE: This is the legacy path for unmigrated protocols
    // Migrated protocols should be started via start_server_from_action
    #[allow(deprecated)]
    let spawn_ctx = crate::protocol::SpawnContext {
        listen_addr,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        // Attach the per-server status channel so event-template lifecycle logs
        // (rendered via EventLogContext) reach the TUI, not just netget.log.
        llm_client: llm_client.clone().with_status_tx(status_tx.clone()),
        state: Arc::new(state.clone()),
        status_tx: status_tx.clone(),
        server_id,
        startup_params,
    };

    // Spawn the server using the protocol's spawn method
    match protocol.spawn(spawn_ctx).await {
        Ok(actual_addr) => {
            let bound = is_bound_addr(&actual_addr);

            // Send startup message with actual port
            let msg = if bound {
                format!(
                    "[SERVER] Starting server #{} ({}) on {}",
                    server_id.as_u32(),
                    protocol_name,
                    actual_addr
                )
            } else {
                format!(
                    "[SERVER] Starting server #{} ({}) (no listening socket)",
                    server_id.as_u32(),
                    protocol_name
                )
            };
            let _ = status_tx.send(msg);

            // Update server with actual listen address (only if one was bound;
            // recording the 0.0.0.0:0 placeholder would surface it in the TUI
            // and in server_status as though it were an endpoint)
            if bound {
                state.update_server_local_addr(server_id, actual_addr).await;
            }
            state
                .update_server_status(server_id, ServerStatus::Running)
                .await;
            // Send update message with actual bound address (for tests that use port 0)
            if bound && (server.port == 0 || server.port != actual_addr.port()) {
                let update_msg = format!(
                    "[SERVER] Server #{} ({}) listening on {}",
                    server_id.as_u32(),
                    protocol_name,
                    actual_addr
                );
                let _ = status_tx.send(update_msg);
            }
            // Note: protocol-specific "listening on" message is also sent by the protocol's spawn method to tracing
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        }
        Err(e) => {
            // Check if error is due to port already in use
            if is_addr_in_use_error(&e) {
                // Return retryable error with context for LLM
                let _ = status_tx.send(format!(
                    "[INFO] Port {} is already in use for {} server, will retry with LLM suggestion",
                    server.port,
                    protocol_name
                ));
                return Err(ActionExecutionError::PortConflict {
                    port: server.port,
                    protocol: protocol_name.clone(),
                    underlying_error: e.to_string(),
                });
            }

            // For other errors, fail immediately
            state
                .update_server_status(server_id, ServerStatus::Error(e.to_string()))
                .await;
            let _ = status_tx.send(format!(
                "[ERROR] Failed to start {} server #{}: {}",
                protocol_name,
                server_id.as_u32(),
                e
            ));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return Err(ActionExecutionError::Fatal(e));
        }
    }

    Ok(())
}

/// Start a server from action parameters (used by /load command)
/// Returns the server ID on success
#[allow(clippy::too_many_arguments)]
/// The address a protocol without `default_binding()` listens on: loopback by default, the
/// caller's host when one is named. `localhost` is accepted as loopback; any other name is
/// refused, because this path binds an address and never resolves one.
pub fn legacy_bind_ip(host: Option<&str>) -> Result<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    match host.map(str::trim) {
        None | Some("") | Some("localhost") => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| anyhow::anyhow!("host {h:?} is not an IP address (or \"localhost\")")),
    }
}

pub async fn start_server_from_action(
    state: &AppState,
    // NEW: Flexible binding parameters (all optional)
    mac_address: Option<String>,
    interface: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    protocol: &str,
    send_first: bool,
    initial_memory: Option<String>,
    instruction: String,
    mut startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
    scheduled_tasks: Option<Vec<crate::llm::actions::common::ServerTaskDefinition>>,
    feedback_instructions: Option<String>,
    status_tx: mpsc::UnboundedSender<String>,
) -> Result<ServerId> {
    use crate::state::server::ServerStatus;
    crate::protocol::StartupParams::preflight_owned(&mut startup_params)?;
    let prepared_tasks = crate::state::task::prepare_tasks(
        scheduled_tasks.as_deref(),
        crate::state::task::TaskScope::Global,
    )?;

    // Resolve the protocol from the registry. `resolve()` is case-insensitive and
    // distinguishes "compiled out of this build" from "no such protocol", with a
    // did-you-mean suggestion for the latter.
    let registry = crate::protocol::server_registry::registry();
    let protocol_impl = registry
        .resolve(protocol)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // === --min-stability gate ===
    // Refuse a protocol below the operator's maturity floor before building
    // anything — no server instance exists yet, so there is nothing to strand.
    if let Some(min) = state.get_min_stability().await {
        let actual = protocol_impl.metadata().state;
        if actual < min {
            let msg = min_stability_refusal("server", protocol, actual, min);
            let _ = status_tx.send(format!("[ERROR] {}", msg));
            return Err(anyhow::anyhow!(msg));
        }
    }

    // === Default port ===
    //
    // Only when the caller named no port at all. An explicit port — `0` included — is the
    // caller's decision and is never replaced. Without a port, a protocol with a well-known
    // port takes it when this process can bind it and nothing already holds it, and otherwise
    // starts on an OS-assigned port and says why; see `protocol::default_port`. A protocol with
    // no well-known port and no `default_binding()` gets 0, so the unmigrated path below always
    // receives a port.
    let port = match port {
        Some(explicit) => Some(explicit),
        None => {
            let caps = state.get_system_capabilities().await;
            match crate::protocol::default_port::default_port_for_server(
                protocol_impl.as_ref(),
                host.as_deref(),
                &caps,
            ) {
                Some(default) => {
                    let _ = status_tx.send(format!(
                        "[INFO] {} server: no port given; {}",
                        protocol,
                        default.describe()
                    ));
                    Some(default.port)
                }
                None => None,
            }
        }
    };

    // === send_first ===
    //
    // `send_first` is a top-level parameter of this function (and of the
    // `open_server` action / MCP `start_server` tool), but protocols consume it
    // as a startup parameter: TCP, Redis, PostgreSQL, MySQL, MongoDB, JSON-RPC,
    // IRC and LDAP all read `startup_params.send_first`. Fold the top-level flag
    // into `startup_params` so the two spellings mean the same thing.
    //
    // Only inject when the protocol actually declares the parameter -
    // `StartupParams` rejects undeclared keys. An explicit value already present
    // in `startup_params` wins, so callers can still set it per-protocol.
    let declares_send_first = protocol_impl
        .get_startup_parameters()
        .iter()
        .any(|p| p.name == "send_first");

    let mut startup_params = if send_first && declares_send_first {
        let mut params = startup_params.unwrap_or_else(|| serde_json::json!({}));
        match params.as_object_mut() {
            Some(map) => {
                map.entry("send_first")
                    .or_insert(serde_json::Value::Bool(true));
                Some(params)
            }
            None => {
                return Err(anyhow::anyhow!(
                    "startup_params must be a JSON object, got: {}",
                    crate::utils::redact::redact_sensitive(&params)
                ));
            }
        }
    } else {
        if send_first && !declares_send_first {
            let _ = status_tx.send(format!(
                "[WARN] Protocol '{}' does not support send_first; ignoring it",
                protocol
            ));
            tracing::warn!(
                "send_first requested for protocol '{}', which declares no send_first startup parameter - ignoring",
                protocol
            );
        }
        startup_params
    };

    crate::protocol::StartupParams::preflight_owned(&mut startup_params)?;

    // === Validate startup params BEFORE registering the server ===
    //
    // This JSON comes straight from the LLM (`open_server`) or an MCP client
    // (`start_server`), so it is untrusted. Validating here means a malformed
    // request returns an error to the caller and leaves no `ServerInstance`
    // stranded in `ServerStatus::Starting`.
    let startup_params_obj = match startup_params.clone() {
        Some(params_json) => {
            let schema = protocol_impl.get_startup_parameters();
            crate::cli::management::validate_server_startup_params(
                &params_json,
                &schema,
                protocol,
            )?;
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

    // === DUAL PATH LOGIC: Migrated vs Unmigrated Protocols ===
    //
    // Migrated protocols return Some(...) from default_binding()
    // Unmigrated protocols return None and use legacy listen_addr
    //
    let (final_mac, final_interface, final_host, final_port, _use_new_path, listen_addr) =
        if let Some(defaults) = protocol_impl.default_binding() {
            // NEW PATH: Protocol has been migrated, use flexible binding
            let (mac, iface, host_str, port_num) =
                defaults.apply(mac_address.clone(), interface.clone(), host.clone(), port);

            // Port 0 is passed straight through to the protocol's own bind, so the OS
            // assigns it atomically.
            //
            // This used to bind a probe listener, read the port it was given, drop it, and
            // let the protocol bind that same port a moment later. Between the drop and
            // the real bind the port belonged to nobody, so a concurrent starter could
            // take it -- under a hundred parallel tests `ServerForm::create` failed every
            // few runs with "Address already in use" for a request that asked for port 0,
            // which is the one request that should never be able to collide.
            //
            // Nothing downstream needs the number early: `spawn()` returns the bound
            // address, `update_server_local_addr` records it, and the "listening on"
            // status line is already emitted whenever the requested port was 0.
            let final_port_num = port_num;

            // Construct legacy listen_addr for backwards compatibility
            // (protocols still receive this field, but new protocols should ignore it)
            let legacy_addr = match (&host_str, final_port_num) {
                (Some(h), Some(p)) => format!("{}:{}", h, p)
                    .parse()
                    .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
                _ => "127.0.0.1:0".parse().unwrap(),
            };

            (mac, iface, host_str, final_port_num, true, legacy_addr)
        } else {
            // OLD PATH: Protocol hasn't been migrated, use backwards-compatible behavior
            // Port field is required for unmigrated protocols
            let port_value = port.ok_or_else(|| {
                anyhow::anyhow!(
                    "Protocol '{}' requires 'port' parameter (unmigrated protocol)",
                    protocol
                )
            })?;

            // Port 0 goes through to the protocol's bind, same as the migrated path
            // above and for the same reason: resolving it here and binding it later loses
            // the port to whoever asks in between.
            let actual_port = port_value;

            // Loopback unless the caller named a host. An explicit host used to be dropped
            // here without a word, so `host: "0.0.0.0"` quietly bound 127.0.0.1; a host that
            // is not an address is refused rather than replaced.
            let ip = legacy_bind_ip(host.as_deref())?;
            let listen_addr = SocketAddr::new(ip, actual_port);

            (
                None,
                None,
                Some(ip.to_string()),
                Some(actual_port),
                false,
                listen_addr,
            )
        };

    // Check privilege requirements — for this start, so an unprivileged test transport is
    // not refused for the privilege its real transport needs.
    let privilege_requirement =
        protocol_impl.startup_privilege_requirement(startup_params.as_ref());
    let system_caps = state.get_system_capabilities().await;

    // Decide whether this start is blocked for lack of privilege.
    //
    // As in `start_server_by_id`, `is_met_by()` is the only test: it already maps
    // each requirement onto the capability that satisfies it. ANDing an unrelated
    // capability on top (e.g. `can_bind_privileged_ports` for a `RawSockets`
    // protocol) let unprivileged starts through.
    let privilege_met = privilege_requirement.is_met_by(&system_caps);

    let requires_privileges = match &privilege_requirement {
        crate::protocol::metadata::PrivilegeRequirement::PrivilegedPort(_) => {
            // Only require privileges if actually binding to a privileged port.
            // Port 0 means OS-assigned port, which will always be unprivileged (>1024)
            // final_port has already been resolved to an actual port number
            let privileged_port = match final_port {
                Some(p) => p > 0 && p < 1024,
                None => false, // Interface-based protocols don't use ports
            };
            privileged_port && !privilege_met
        }
        // RawSockets, Root, None: the requirement itself is the whole test.
        _ => !privilege_met,
    };

    if requires_privileges {
        let error_msg = format!(
            "Cannot start {} server: {}. Current capabilities: {}",
            protocol,
            privilege_requirement.description(),
            system_caps.description()
        );
        return Err(anyhow::anyhow!(error_msg));
    }

    // Runtime dependencies privilege cannot express — a system library, a binary on PATH.
    //
    // Refused here, before `add_server`, like privilege and --min-stability: a server that
    // cannot start is never registered, so no `Error` row is stranded in `list_servers` (the
    // same reason a failed `spawn()` below removes its row), and the caller — the MCP tool
    // error, the model's `open_server` result, a non-interactive run's exit status — gets the
    // dependency and its install hint instead of whatever the library says part-way through
    // spawning. Only a dependency the probe established is absent refuses; see
    // `dependencies::startup_blocker`.
    if let Some(dep) = crate::protocol::dependencies::startup_blocker(
        &protocol_impl.startup_dependencies(startup_params.as_ref()),
        &system_caps,
    ) {
        let msg = format!(
            "Cannot start {} server: {}. {}",
            protocol,
            dep.description(),
            dep.installation_hint()
        );
        let _ = status_tx.send(format!("[ERROR] {}", msg));
        return Err(anyhow::anyhow!(msg));
    }

    let parsed_handlers = event_handlers
        .map(crate::events::handler::EventHandler::parse_event_handlers)
        .transpose()
        .map_err(|error| anyhow::anyhow!("Invalid event handler configuration: {}", error))?;

    // Create server instance
    // NOTE: For unmigrated protocols, port is always Some(_)
    // For migrated protocols, port may be None (interface-based protocols like ICMP)
    let display_port = final_port.unwrap_or(0);

    let server = crate::state::server::ServerInstance {
        id: ServerId::new(0), // Will be assigned by add_server
        port: display_port,
        protocol_name: protocol.to_string(),
        instruction: instruction.clone(),
        memory: String::new(),
        status: ServerStatus::Starting,
        connections: Default::default(),
        local_addr: None,
        created_at: crate::utils::clock::Instant::now(),
        status_changed_at: crate::utils::clock::Instant::now(),
        startup_params: startup_params.clone(),
        event_handler_config: None,
        protocol_data: serde_json::Value::Null,
        log_files: Default::default(),
        feedback_instructions,
        feedback_buffer: Vec::new(),
        last_feedback_processed: None,
        recent_connections: Default::default(),
        connection_opened_at: Default::default(),
    };

    let server_id = state.add_server(server).await;
    let mut startup_guard = super::startup_guard::StartupGuard::server(state, server_id);

    // Set initial memory if provided
    if let Some(mem) = initial_memory {
        state.set_memory(server_id, mem).await;
    }

    if let Some(config) = parsed_handlers {
        state
            .with_server_mut(server_id, |server| {
                server.event_handler_config = Some(config)
            })
            .await;
        let _ = status_tx.send("[INFO] Event handler configuration applied".to_string());
    }

    // Definitions were prepared before the owner was registered.
    for (task_def, mut task) in scheduled_tasks
        .unwrap_or_default()
        .into_iter()
        .zip(prepared_tasks)
    {
        task.scope = crate::state::task::TaskScope::Server(server_id);
        let task_name = task.name.clone();
        let task_id_num = state.add_task(task).await;
        // Report it exactly as the standalone `schedule_task` action does
        // (src/events/handler.rs). Creating a task through `open_server`'s
        // `scheduled_tasks` array used to be completely silent - nothing in
        // the TUI, nothing over MCP - so the two paths disagreed about
        // whether task creation is an observable event. It is.
        if task_def.recurring {
            let interval = task_def.interval_secs.unwrap_or(60);
            let max_info = match task_def.max_executions {
                Some(max) => format!(" (max {} executions)", max),
                None => String::new(),
            };
            let msg = format!(
                "[TASK] Scheduled recurring task '{}' (ID: {}) to execute every {}s{}",
                task_name, task_id_num, interval, max_info
            );
            tracing::info!("{}", msg);
            let _ = status_tx.send(msg);
        } else {
            let msg = format!(
                "[TASK] Scheduled one-shot task '{}' (ID: {}) to execute in {}s",
                task_name,
                task_id_num,
                task_def.delay_secs.unwrap_or(0)
            );
            tracing::info!("{}", msg);
            let _ = status_tx.send(msg);
        }
    }

    // `startup_params_obj` was built and validated above, before `add_server`.

    // Build spawn context
    // Use the configured LLM client from state (includes mock config, lock settings, etc.)
    // If not available (shouldn't happen), fall back to creating a new client
    let llm_client = if let Some(client) = state.get_llm_client().await {
        client
    } else {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let ollama_url = state.get_ollama_url().await;
            OllamaClient::new(ollama_url)
        }
        #[cfg(target_arch = "wasm32")]
        {
            anyhow::bail!("no LLM client is configured; the browser build installs one at startup")
        }
    }
    // Attach the per-server status channel so event-template lifecycle logs
    // (rendered via EventLogContext) reach the TUI, not just netget.log.
    .with_status_tx(status_tx.clone());

    #[allow(deprecated)]
    let spawn_ctx = crate::protocol::SpawnContext {
        listen_addr,
        mac_address: final_mac,
        interface: final_interface,
        host: final_host,
        port: final_port,
        llm_client,
        state: Arc::new(state.clone()),
        status_tx: status_tx.clone(),
        server_id,
        startup_params: startup_params_obj,
    };

    // Spawn the server
    match protocol_impl.spawn(spawn_ctx).await {
        Ok(actual_addr) => {
            let bound = is_bound_addr(&actual_addr);

            // Send startup message with actual address
            let msg = if bound {
                format!(
                    "[SERVER] Starting server #{} ({}) on {}",
                    server_id.as_u32(),
                    protocol,
                    actual_addr
                )
            } else {
                format!(
                    "[SERVER] Starting server #{} ({}) (no listening socket)",
                    server_id.as_u32(),
                    protocol
                )
            };
            let _ = status_tx.send(msg);

            // Update server with actual listen address (only if one was bound;
            // see is_bound_addr)
            if bound {
                state.update_server_local_addr(server_id, actual_addr).await;
            }
            state
                .update_server_status(server_id, ServerStatus::Running)
                .await;

            // Send update message with actual bound address (for tests that use port 0)
            if bound
                && (final_port.unwrap_or(0) == 0 || final_port.unwrap_or(0) != actual_addr.port())
            {
                let update_msg = format!(
                    "[SERVER] Server #{} ({}) listening on {}",
                    server_id.as_u32(),
                    protocol,
                    actual_addr
                );
                let _ = status_tx.send(update_msg);
            }

            startup_guard.disarm();
            Ok(server_id)
        }
        Err(e) => {
            // The server never came up, so nothing about it is inspectable or
            // controllable: it has no listener, no connections and no task. Leaving
            // the instance registered only makes `list_servers` accumulate zombie
            // `Error` rows that can never transition anywhere, each holding a
            // ServerId and any log files it opened. The error is returned to the
            // caller (and, for MCP, becomes the tool error), so dropping the
            // registration loses nothing.
            state
                .update_server_status(server_id, ServerStatus::Error(e.to_string()))
                .await;
            state.remove_server(server_id).await;
            startup_guard.disarm();
            let _ = status_tx.send(format!(
                "[ERROR] Server #{} ({}) failed to start: {}",
                server_id.as_u32(),
                protocol,
                e
            ));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            Err(e)
        }
    }
}
