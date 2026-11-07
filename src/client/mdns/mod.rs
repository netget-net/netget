//! mDNS client implementation
pub mod actions;

pub use actions::MdnsClientProtocol;

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::mdns::actions::{
    MDNS_CLIENT_CONNECTED_EVENT, MDNS_CLIENT_SERVICE_FOUND_EVENT,
    MDNS_CLIENT_SERVICE_RESOLVED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// What applying one executed action did. Shared by the LLM path and the command
/// channel.
///
/// There is no `Sent(usize)` variant, and that is the honest shape for this client:
/// `mdns-sd`'s `ServiceDaemon` owns the multicast socket and reports neither the
/// query bytes it emits nor when it emits them, so no byte count we could produce
/// would be a real one.
enum Applied {
    /// The action ran; the detail says what the daemon was asked to do.
    Executed(String),
    /// The session should end.
    Disconnect,
}

/// mDNS client that performs service discovery on the local network
pub struct MdnsClient;

impl MdnsClient {
    /// Initialize mDNS client with integrated LLM actions
    pub async fn connect_with_llm_actions(
        _remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("mDNS client {} initializing", client_id);

        // Create mDNS service daemon
        let mdns = ServiceDaemon::new().context("Failed to create mDNS service daemon")?;

        // Store daemon handle in protocol_data
        // Note: mdns daemon is not directly serializable, so we just mark it as initialized
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("mdns_initialized".to_string(), serde_json::json!(true));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] mDNS client {} initialized", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel: lets the dashboard (and any programmatic caller) inject
        // actions into this client via AppState::send_to_client.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing rule can
        // park that event at the dashboard for minutes, and until registration the UI
        // reports "no command channel" - reading as a protocol limitation when it is
        // only a queue.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The command task gets a clone of the *same* daemon handle - `ServiceDaemon`
        // is a cloneable handle onto one running daemon, so an injected browse goes out
        // of the same sockets, to the same multicast group, as one the LLM asked for.
        // It also keeps the daemon alive when the client has no instruction at all.
        let cmd_daemon = mdns.clone();
        let cmd_llm = llm_client.clone();
        let cmd_state = app_state.clone();
        let cmd_status = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx, cmd_daemon, client_id, cmd_llm, cmd_state, cmd_status,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event to get initial instructions
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::mdns::actions::MdnsClientProtocol::new());
            let event = Event::new(
                &MDNS_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "status": "connected",
                    "message": "mDNS client ready for service discovery"
                }),
            );

            let llm_client_clone = llm_client.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client_clone,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    "",
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

                        // Execute initial actions
                        for action in actions {
                            if let Err(e) = Self::execute_mdns_action(
                                client_id,
                                action,
                                &mdns,
                                llm_client_clone.clone(),
                                app_state_clone.clone(),
                                status_tx_clone.clone(),
                            )
                            .await
                            {
                                error!("Failed to execute mDNS action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for mDNS client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        // Spawn monitoring task to check for client disconnection
        let app_state_monitor = app_state.clone();
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;

                // Check if client was removed
                if app_state_monitor.get_client(client_id).await.is_none() {
                    info!("mDNS client {} stopped", client_id);
                    break;
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return a dummy local address (mDNS is multicast UDP)
        Ok("224.0.0.251:5353".parse().unwrap())
    }

    /// Execute an mDNS action (browse, resolve, etc.)
    ///
    /// Shared by the connected-event path and injected commands, so a `[ send ]` from
    /// the dashboard drives exactly the same daemon calls the LLM would.
    /// Run one mDNS verb against the daemon. Raises no event and calls no LLM.
    ///
    /// Follow-up actions the model returns for a service-found or service-resolved event
    /// run through here. Routing them back through `execute_mdns_action` would recurse
    /// directly -- those events are raised from inside that very function -- and would let
    /// one discovered service spawn another browse loop, and that one another, without
    /// bound.
    ///
    /// `browse_service` is therefore drained for a bounded window here rather than given
    /// its own long-lived task: a follow-up browse is a look, not a subscription.
    async fn run_mdns_op(
        client_id: ClientId,
        mdns: &ServiceDaemon,
        name: &str,
        data: &serde_json::Value,
    ) -> Result<String> {
        match name {
            "resolve_hostname" => {
                let hostname = data["hostname"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing hostname"))?;
                let events = mdns.resolve_hostname(hostname, Some(5000))?;
                let mut found: Vec<String> = Vec::new();
                while let Ok(event) = events.recv_async().await {
                    match event {
                        mdns_sd::HostnameResolutionEvent::AddressesFound(_, addrs) => {
                            found.extend(addrs.iter().map(|a| a.to_string()));
                            break;
                        }
                        mdns_sd::HostnameResolutionEvent::SearchTimeout(_)
                        | mdns_sd::HostnameResolutionEvent::SearchStopped(_) => break,
                        _ => continue,
                    }
                }
                found.sort();
                Ok(format!("resolve_hostname '{hostname}' -> {found:?}"))
            }
            "browse_service" => {
                let service_type = data["service_type"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing service_type"))?;
                let rx = mdns.browse(service_type)?;
                let mut seen: Vec<String> = Vec::new();
                let deadline = tokio::time::sleep(std::time::Duration::from_secs(2));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        ev = rx.recv_async() => match ev {
                            Ok(mdns_sd::ServiceEvent::ServiceFound(_, full)) => seen.push(full),
                            Ok(_) => continue,
                            Err(_) => break,
                        },
                    }
                }
                let _ = mdns.stop_browse(service_type);
                seen.sort();
                seen.dedup();
                info!("mDNS client {} follow-up browse saw {:?}", client_id, seen);
                Ok(format!(
                    "browse_service '{service_type}' -> {} found",
                    seen.len()
                ))
            }
            other => Ok(format!("'{other}' has no non-notifying path; skipped")),
        }
    }

    /// Execute the actions the model returned for a browse event.
    ///
    /// They were discarded at both sites (`actions: _`), so a model that saw a service
    /// appear and wanted to resolve its hostname was ignored -- discovery reported
    /// nothing actionable back.
    async fn run_browse_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        mdns: &ServiceDaemon,
        protocol: &crate::client::mdns::actions::MdnsClientProtocol,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            match Self::run_mdns_op(client_id, mdns, &name, &data).await {
                Ok(detail) => info!("mDNS client {} follow-up: {}", client_id, detail),
                Err(e) => error!("mDNS client {} follow-up {} failed: {}", client_id, name, e),
            }
        }
    }

    async fn execute_mdns_action(
        client_id: ClientId,
        action: serde_json::Value,
        mdns: &ServiceDaemon,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        use crate::llm::actions::client_trait::Client;
        let protocol = Arc::new(crate::client::mdns::actions::MdnsClientProtocol::new());

        match protocol.as_ref().execute_action(action.clone()) {
            Ok(crate::llm::actions::client_trait::ClientActionResult::Custom { name, data }) => {
                match name.as_str() {
                    "browse_service" => {
                        let service_type = data["service_type"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("Missing service_type"))?;

                        info!(
                            "mDNS client {} browsing for service: {}",
                            client_id, service_type
                        );
                        let _ = status_tx.send(format!(
                            "[CLIENT] Browsing for mDNS service: {}",
                            service_type
                        ));

                        // Start browsing
                        let receiver = mdns
                            .browse(service_type)
                            .context("Failed to browse service")?;

                        // Spawn task to handle browse events
                        let llm_client_browse = llm_client.clone();
                        let app_state_browse = app_state.clone();
                        let status_tx_browse = status_tx.clone();
                        let protocol_browse = protocol.clone();
                        // The browse task needs the daemon so a follow-up the model asks
                        // for can actually run; ServiceDaemon is a cheap handle clone.
                        let mdns_browse = mdns.clone();

                        // Registered with AppState so stop_client can abort this task —
                        // dropping a JoinHandle only detaches it in Tokio.
                        let task_registrar = app_state.clone();
                        let task_handle = tokio::spawn(async move {
                            loop {
                                // `recv_timeout` is a *synchronous* blocking call, so it
                                // runs on the blocking pool rather than a runtime worker.
                                // Called inline it parks the worker for up to 10s at a
                                // time, and on a current-thread runtime that stalls
                                // everything else the client is doing - including the
                                // command channel, which is how this was found.
                                let rx = receiver.clone();
                                let recv_result = match tokio::task::spawn_blocking(move || {
                                    rx.recv_timeout(Duration::from_secs(10))
                                })
                                .await
                                {
                                    Ok(result) => result,
                                    Err(e) => {
                                        error!("mDNS browse receive task failed: {}", e);
                                        break;
                                    }
                                };

                                match recv_result {
                                    Ok(event) => {
                                        match event {
                                            ServiceEvent::ServiceFound(service_type, fullname) => {
                                                trace!(
                                                    "mDNS service found: {} ({})",
                                                    fullname,
                                                    service_type
                                                );

                                                // Call LLM with service found event
                                                if let Some(instruction) = app_state_browse
                                                    .get_instruction_for_client(client_id)
                                                    .await
                                                {
                                                    let llm_event = Event::new(
                                                        &MDNS_CLIENT_SERVICE_FOUND_EVENT,
                                                        serde_json::json!({
                                                            "service_type": service_type,
                                                            "fullname": fullname,
                                                        }),
                                                    );

                                                    let memory = app_state_browse
                                                        .get_memory_for_client(client_id)
                                                        .await
                                                        .unwrap_or_default();

                                                    match call_llm_for_client(
                                                        &llm_client_browse,
                                                        &app_state_browse,
                                                        client_id.to_string(),
                                                        &instruction,
                                                        &memory,
                                                        Some(&llm_event),
                                                        protocol_browse.as_ref(),
                                                        &status_tx_browse,
                                                    )
                                                    .await
                                                    {
                                                        Ok(ClientLlmResult {
                                                            actions,
                                                            memory_updates,
                                                        }) => {
                                                            if let Some(mem) = memory_updates {
                                                                app_state_browse
                                                                    .set_memory_for_client(
                                                                        client_id, mem,
                                                                    )
                                                                    .await;
                                                            }
                                                            Self::run_browse_follow_ups(
                                                                client_id,
                                                                actions,
                                                                &mdns_browse,
                                                                protocol_browse.as_ref(),
                                                            )
                                                            .await;
                                                        }
                                                        Err(e) => {
                                                            error!("LLM error processing service found: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            ServiceEvent::ServiceResolved(info) => {
                                                let first_addr = info
                                                    .get_addresses()
                                                    .iter()
                                                    .next()
                                                    .map(|scoped| scoped.to_string())
                                                    .unwrap_or_else(|| "0.0.0.0".to_string());

                                                info!(
                                                    "mDNS service resolved: {} at {}:{}",
                                                    info.get_fullname(),
                                                    first_addr,
                                                    info.get_port()
                                                );

                                                // Call LLM with service resolved event
                                                if let Some(instruction) = app_state_browse
                                                    .get_instruction_for_client(client_id)
                                                    .await
                                                {
                                                    let llm_event = Event::new(
                                                        &MDNS_CLIENT_SERVICE_RESOLVED_EVENT,
                                                        serde_json::json!({
                                                            "fullname": info.get_fullname(),
                                                            "hostname": info.get_hostname(),
                                                            "addresses": info.get_addresses().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                                                            "port": info.get_port(),
                                                            "properties": info.get_properties().iter().map(|p| format!("{}={}", p.key(), p.val_str())).collect::<Vec<_>>(),
                                                        }),
                                                    );

                                                    let memory = app_state_browse
                                                        .get_memory_for_client(client_id)
                                                        .await
                                                        .unwrap_or_default();

                                                    match call_llm_for_client(
                                                        &llm_client_browse,
                                                        &app_state_browse,
                                                        client_id.to_string(),
                                                        &instruction,
                                                        &memory,
                                                        Some(&llm_event),
                                                        protocol_browse.as_ref(),
                                                        &status_tx_browse,
                                                    )
                                                    .await
                                                    {
                                                        Ok(ClientLlmResult {
                                                            actions,
                                                            memory_updates,
                                                        }) => {
                                                            if let Some(mem) = memory_updates {
                                                                app_state_browse
                                                                    .set_memory_for_client(
                                                                        client_id, mem,
                                                                    )
                                                                    .await;
                                                            }
                                                            Self::run_browse_follow_ups(
                                                                client_id,
                                                                actions,
                                                                &mdns_browse,
                                                                protocol_browse.as_ref(),
                                                            )
                                                            .await;
                                                        }
                                                        Err(e) => {
                                                            error!("LLM error processing service resolved: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            ServiceEvent::ServiceRemoved(
                                                service_type,
                                                fullname,
                                            ) => {
                                                info!(
                                                    "mDNS service removed: {} ({})",
                                                    fullname, service_type
                                                );
                                            }
                                            ServiceEvent::SearchStarted(service_type) => {
                                                trace!("mDNS search started for: {}", service_type);
                                            }
                                            ServiceEvent::SearchStopped(service_type) => {
                                                trace!("mDNS search stopped for: {}", service_type);
                                                break;
                                            }
                                            _ => {
                                                // Handle any other event types
                                                trace!("mDNS unhandled event type");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // Check if it's a timeout or disconnection
                                        if format!("{:?}", e).contains("Timeout") {
                                            // Timeout is expected, check if client still exists
                                            if app_state_browse
                                                .get_client(client_id)
                                                .await
                                                .is_none()
                                            {
                                                info!("mDNS browse task stopping (client removed)");
                                                break;
                                            }
                                        } else {
                                            info!("mDNS browse channel error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                        task_registrar
                            .register_client_task(client_id, task_handle)
                            .await;

                        return Ok(Applied::Executed(format!(
                            "browse_service '{service_type}' started (the mdns-sd daemon \
                             owns the multicast socket, so no byte count is observable)"
                        )));
                    }
                    "resolve_hostname" => {
                        let hostname = data["hostname"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("Missing hostname"))?;

                        info!("mDNS client {} resolving hostname: {}", client_id, hostname);

                        // Use mdns to resolve hostname (timeout in milliseconds)
                        match mdns.resolve_hostname(hostname, Some(5000)) {
                            Ok(events) => {
                                // `resolve_hostname` returns a Receiver of resolution
                                // EVENTS, not addresses. This used to bind it as `addrs`
                                // and log `addrs.len()` -- the channel's queue depth,
                                // which is 0 -- so the client reported "Resolved X to 0
                                // addresses" and never surfaced a single address, however
                                // well the resolution went. Drain it instead; it is a
                                // flume receiver, so `recv_async` keeps this off the
                                // runtime's worker threads.
                                let mut found: Vec<String> = Vec::new();
                                while let Ok(event) = events.recv_async().await {
                                    match event {
                                        mdns_sd::HostnameResolutionEvent::AddressesFound(
                                            _,
                                            addrs,
                                        ) => {
                                            found.extend(addrs.iter().map(|a| a.to_string()));
                                            break;
                                        }
                                        mdns_sd::HostnameResolutionEvent::SearchTimeout(_)
                                        | mdns_sd::HostnameResolutionEvent::SearchStopped(_) => {
                                            break
                                        }
                                        _ => continue,
                                    }
                                }
                                found.sort();
                                info!(
                                    "Resolved {} to {} address(es): {:?}",
                                    hostname,
                                    found.len(),
                                    found
                                );
                                let _ = status_tx
                                    .send(format!("[CLIENT] Resolved {}: {:?}", hostname, found));
                                return Ok(Applied::Executed(if found.is_empty() {
                                    format!(
                                        "resolve_hostname '{hostname}': no addresses \
                                         (search timed out after 5s)"
                                    )
                                } else {
                                    format!(
                                        "resolve_hostname '{hostname}': {} -> {}",
                                        found.len(),
                                        found.join(", ")
                                    )
                                }));
                            }
                            Err(e) => {
                                warn!("Failed to resolve {}: {}", hostname, e);
                                let _ = status_tx.send(format!(
                                    "[CLIENT] Failed to resolve {}: {}",
                                    hostname, e
                                ));
                                return Err(anyhow::anyhow!(
                                    "resolve_hostname '{hostname}' failed: {e}"
                                ));
                            }
                        }
                    }
                    _ => {
                        warn!("Unknown mDNS action: {}", name);
                        return Ok(Applied::Executed(format!(
                            "custom result '{name}' is not an mDNS verb"
                        )));
                    }
                }
            }
            Ok(crate::llm::actions::client_trait::ClientActionResult::Disconnect) => {
                info!("mDNS client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send(format!("[CLIENT] mDNS client {} disconnected", client_id));
                return Ok(Applied::Disconnect);
            }
            Ok(crate::llm::actions::client_trait::ClientActionResult::WaitForMore) => {
                trace!("mDNS client {} waiting for more data", client_id);
                return Ok(Applied::Executed("wait_for_more".to_string()));
            }
            Ok(other) => Ok(Applied::Executed(format!("no wire effect: {other:?}"))),
            Err(e) => Err(e),
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// Bespoke rather than `command_support::handle_stream_client_command` because
    /// every mDNS verb yields `ClientActionResult::Custom` and there is no write half
    /// at all - the effect goes through the `ServiceDaemon` handle. The logging and
    /// reply are byte-for-byte what the generic helper does.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        mdns: ServiceDaemon,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = crate::client::mdns::actions::MdnsClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = Self::execute_mdns_action(
                client_id,
                action.clone(),
                &mdns,
                llm_client.clone(),
                app_state.clone(),
                status_tx.clone(),
            )
            .await
            .map(|applied| match applied {
                Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
                Applied::Disconnect => ClientSendOutcome::Disconnected,
            });

            // `execute_mdns_action` folds an unknown action name and a failed daemon
            // call into the same `Err`; only the former is a rejection, so classify it
            // here rather than reporting a bad daemon call as a bad action.
            let outcome = match outcome {
                Err(e) if protocol.execute_action(action.clone()).is_err() => {
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    })
                }
                other => other,
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
                    "mDNS client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a dead client (a late send then fails fast).
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}
