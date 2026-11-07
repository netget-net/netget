//! STUN client implementation for NAT traversal discovery
pub mod actions;

pub use actions::StunClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::stun::actions::{
    STUN_CLIENT_BINDING_RESPONSE_EVENT, STUN_CLIENT_CONNECTED_EVENT,
};
use crate::llm::actions::client_trait::ClientActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// STUN client for discovering external IP/port behind NAT
pub struct StunClient;

impl StunClient {
    /// Connect to a STUN server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("STUN client {} initializing for {}", client_id, remote_addr);

        // Bind local UDP socket (0.0.0.0:0 for any address/port)
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let udp_socket = tokio::net::UdpSocket::bind(local_addr)
            .await
            .context("Failed to bind UDP socket")?;

        let bound_addr = udp_socket.local_addr()?;
        info!(
            "STUN client {} bound to local address {}",
            client_id, bound_addr
        );

        // Store socket and STUN server address in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("stun_server".to_string(), serde_json::json!(remote_addr));
                client.set_protocol_field(
                    "local_addr".to_string(),
                    serde_json::json!(bound_addr.to_string()),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "STUN client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ]).
        //
        // Registered BEFORE the connected-event LLM call below: a dashboard-created client
        // defaults to a `*` -> manual routing rule, so that call can park for minutes waiting
        // for a human, and [ send ] must work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(StunClientProtocol::new());
            let event = Event::new(
                &STUN_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "local_addr": bound_addr.to_string(),
                    "stun_server": remote_addr,
                }),
            );

            let llm_clone = llm_client.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_clone,
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

                        // Execute actions
                        for action in actions {
                            if let Err(e) = Self::execute_stun_action(
                                client_id,
                                action,
                                app_state_clone.clone(),
                                llm_clone.clone(),
                                status_tx_clone.clone(),
                            )
                            .await
                            {
                                error!("Failed to execute STUN action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for STUN client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        // Command loop. This replaces the bare 5-second "has the client been removed yet?"
        // watchdog that used to live here: it still performs that check, and it is now also
        // what makes an injected action reach a running STUN client.
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            Self::command_loop(command_rx, client_id, llm_client, app_state, status_tx).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(bound_addr)
    }

    /// Execute a STUN action (internal helper)
    async fn execute_stun_action(
        client_id: ClientId,
        action: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        use crate::llm::actions::client_trait::Client;
        let protocol = Arc::new(StunClientProtocol::new());

        match protocol.as_ref().execute_action(action)? {
            crate::llm::actions::client_trait::ClientActionResult::Custom { name, data: _ } => {
                if name == "send_binding_request" {
                    Self::send_binding_request(client_id, app_state, llm_client, status_tx).await?;
                }
            }
            crate::llm::actions::client_trait::ClientActionResult::Disconnect => {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                Log::new(Some(&status_tx)).info(format!("STUN client {} disconnected", client_id));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            _ => {}
        }

        Ok(())
    }

    /// Send STUN binding request and report the result to the model.
    pub async fn send_binding_request(
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let discovered = Self::query_external_address(client_id, &app_state, &status_tx).await?;
        Self::report_binding_response(client_id, &discovered, &app_state, &llm_client, &status_tx)
            .await;
        Ok(())
    }

    /// Run one STUN binding exchange and return what it discovered.
    ///
    /// Split out from [`Self::send_binding_request`] so the injected-command path can answer
    /// the caller as soon as the exchange completes and hand the model its
    /// `stun_binding_response` event afterwards - a manual routing rule parked on that event
    /// would otherwise hold the dashboard's \[send\] open for its whole timeout.
    async fn query_external_address(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<StunDiscovery> {
        // Get STUN server address from client
        let stun_server = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("stun_server")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No STUN server found")?;

        info!(
            "STUN client {} sending binding request to {}",
            client_id, stun_server
        );

        // Resolve STUN server address (may be hostname:port).
        //
        // A literal `IP:port` is NOT handed to the resolver. `tokio::net::lookup_host`
        // calls `getaddrinfo` unconditionally, and on macOS that goes through libinfo to
        // mDNSResponder — one system-wide daemon that serialises under concurrency, and
        // which this repo has measured at **8.25 seconds** for `getaddrinfo("127.0.0.1")`
        // with ~100 processes asking at once. `stunclient`'s end-to-end timeout is 10s,
        // so a resolver stall of that size eats the whole budget and surfaces as "the
        // STUN server did not answer" against a server that was never spoken to. The
        // same trap is documented for reqwest in the root CLAUDE.md; this is the
        // `lookup_host` spelling of it.
        //
        // A hostname is still left to the resolver: resolving it is the resolver's job.
        let stun_sock_addr: SocketAddr = match stun_server.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&stun_server)
                .await
                .context(format!("Failed to resolve STUN server: {}", stun_server))?
                .next()
                .context("No addresses found for STUN server")?,
        };

        // Bind a new UDP socket for the query
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let udp_socket = tokio::net::UdpSocket::bind(local_addr)
            .await
            .context("Failed to bind UDP socket for STUN query")?;

        // Create STUN client and query external address
        let stun_client = stunclient::StunClient::new(stun_sock_addr);

        match stun_client.query_external_address_async(&udp_socket).await {
            Ok(external_addr) => {
                info!(
                    "STUN client {} discovered external address: {}",
                    client_id, external_addr
                );

                let local_addr = udp_socket.local_addr()?;

                Ok(StunDiscovery {
                    external_addr,
                    local_addr,
                    stun_server,
                })
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "STUN client {} binding request failed: {}",
                    client_id, e
                ));
                Err(e.into())
            }
        }
    }

    /// Hand a completed binding exchange to the model as a `stun_binding_response` event.
    async fn report_binding_response(
        client_id: ClientId,
        discovered: &StunDiscovery,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(StunClientProtocol::new());
        let event = Event::new(
            &STUN_CLIENT_BINDING_RESPONSE_EVENT,
            serde_json::json!({
                "external_ip": discovered.external_addr.ip().to_string(),
                "external_port": discovered.external_addr.port(),
                "external_addr": discovered.external_addr.to_string(),
                "local_addr": discovered.local_addr.to_string(),
                "stun_server": discovered.stun_server,
            }),
        );

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

                // Execute what the model asked for. These were discarded with a note
                // saying it was "to avoid recursion" -- a real hazard, but the answer is
                // to dispatch through a path that raises no event rather than to drop the
                // answer. A model that read a discovered address and wanted to re-probe
                // (to see whether the mapping is stable, which is the whole point of
                // repeated STUN binding requests) was silently ignored.
                //
                // `query_external_address` performs the exchange and raises nothing, so
                // one probe cannot drive an unbounded chain and the async type stays
                // non-recursive, which is what tokio::spawn's Send bound requires.
                use crate::llm::actions::client_trait::{Client, ClientActionResult};
                let protocol = crate::client::stun::actions::StunClientProtocol::new();
                for action in actions {
                    match protocol.execute_action(action.clone()) {
                        Ok(ClientActionResult::Custom { name, .. })
                            if name == "send_binding_request" =>
                        {
                            match Self::query_external_address(client_id, app_state, status_tx)
                                .await
                            {
                                Ok(d) => info!(
                                    "STUN client {} follow-up binding request: {}",
                                    client_id, d.external_addr
                                ),
                                Err(e) => error!(
                                    "STUN client {} follow-up binding request failed: {}",
                                    client_id, e
                                ),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => error!(
                            "STUN client {} rejected its own follow-up action: {}",
                            client_id, e
                        ),
                    }
                }
            }
            Err(e) => {
                error!("LLM error for STUN client {}: {}", client_id, e);
            }
        }
    }

    /// Drain injected commands, and keep the old client-removal watchdog on the same task.
    ///
    /// `send_binding_request` reports `Executed`, never `Sent`: the exchange runs inside
    /// `stunclient`, which owns its own UDP socket and reports no byte count, so there is no
    /// truthful number to hand back. The detail string carries the discovered external
    /// address, which is the thing the caller actually wants to see.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = StunClientProtocol::new();

        loop {
            let command = tokio::select! {
                command = command_rx.recv() => match command {
                    Some(command) => command,
                    // Channel closed: the client row (and its handle) is gone.
                    None => break,
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    // The watchdog this loop replaced: a removed client leaves nothing to
                    // command, so stop rather than sitting on a dead handle.
                    if app_state.get_client(client_id).await.is_none() {
                        info!("STUN client {} stopped", client_id);
                        break;
                    }
                    continue;
                }
            };

            let action = command.action.clone();

            // A successful exchange is reported to the model only after the caller has been
            // answered, so `discovered` carries it past the reply.
            let mut discovered: Option<StunDiscovery> = None;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Custom { name, .. }) if name == "send_binding_request" => {
                    match Self::query_external_address(client_id, &app_state, &status_tx).await {
                        Ok(result) => {
                            let detail = format!(
                                "binding exchange completed via stunclient: external address {} \
                                 (byte count not observable - stunclient owns the socket)",
                                result.external_addr
                            );
                            discovered = Some(result);
                            Ok(ClientSendOutcome::Executed { detail })
                        }
                        Err(e) => Err(e),
                    }
                }
                Ok(ClientActionResult::Custom { name, .. }) => Ok(ClientSendOutcome::Executed {
                    detail: format!("custom result '{name}' is not a STUN client verb"),
                }),
                Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more: nothing sent".to_string(),
                }),
                Ok(_) => Ok(ClientSendOutcome::Executed {
                    detail: "action produced no STUN exchange".to_string(),
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
                    "STUN client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                Log::new(Some(&status_tx)).info(format!(
                    "STUN client {} disconnected (injected action)",
                    client_id
                ));
                break;
            }

            if let Some(result) = discovered {
                Self::report_binding_response(
                    client_id,
                    &result,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// What one STUN binding exchange discovered.
struct StunDiscovery {
    external_addr: SocketAddr,
    local_addr: SocketAddr,
    stun_server: String,
}
