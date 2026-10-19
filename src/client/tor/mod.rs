//! Tor client implementation using arti
pub mod actions;

pub use actions::TorClientProtocol;

use anyhow::{Context, Result};
use arti_client::{TorClient as ArtiClient, TorClientConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace, warn};

#[cfg(unix)]
use serde::Serialize;
#[cfg(unix)]
use tor_netdir::{NetDir, Relay};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::tor::actions::{TOR_CLIENT_CONNECTED_EVENT, TOR_CLIENT_DATA_RECEIVED_EVENT};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Relay filter criteria for directory queries
#[cfg(unix)]
#[derive(Debug, Clone, Default)]
pub struct RelayFilter {
    pub flags: Option<Vec<String>>,
    pub min_bandwidth: Option<u64>,
    pub nickname_pattern: Option<String>,
    pub limit: Option<usize>,
}

#[cfg(unix)]
impl RelayFilter {
    /// Check if a relay matches this filter
    fn matches(&self, _relay: &Relay<'_>) -> bool {
        // NOTE: tor-netdir's Relay type doesn't expose flag-checking methods in the public API
        // Even with experimental-api, the internal RouterStatus fields are not accessible
        // For now, we match all relays - filtering would require deeper Arti API integration

        // TODO: When Arti exposes flag/nickname access in experimental-api, implement:
        // - Flag filtering (Guard, Exit, Fast, Stable, Running, Valid)
        // - Nickname pattern matching
        // - Bandwidth filtering

        true
    }
}

/// Simplified relay information for LLM
#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
pub struct RelayInfo {
    pub nickname: String,
    pub fingerprint: String,
    pub flags: Vec<String>,
    pub is_guard: bool,
    pub is_exit: bool,
    pub is_fast: bool,
    pub is_stable: bool,
    pub is_running: bool,
    pub is_valid: bool,
}

#[cfg(unix)]
impl RelayInfo {
    /// Create RelayInfo from a Tor relay
    fn from_relay(relay: &Relay<'_>) -> Self {
        // Get relay identity - rsa_id() is available via public trait
        let fingerprint = format!("{:?}", relay.rsa_id());

        // Use first 8 chars of fingerprint as a proxy for nickname
        // NOTE: tor-netdir's Relay type doesn't expose nickname or flags in public API
        let nickname = fingerprint.chars().take(8).collect::<String>();

        // Return minimal info - flag details not accessible via current Arti API
        // TODO: Update when Arti's experimental-api exposes RouterStatus fields
        Self {
            nickname,
            fingerprint,
            flags: vec![], // Not accessible via public API
            is_guard: false,
            is_exit: false,
            is_fast: false,
            is_stable: false,
            is_running: false,
            is_valid: false,
        }
    }
}

/// Startup parameter that opts a Tor client in to the public Tor network.
///
/// Named as a constant because it appears in four places that must agree: the parameter
/// declaration, the refusal message, this module's check, and the test that pins all of it.
pub const ALLOW_PUBLIC_TOR_NETWORK_PARAM: &str = "allow_public_tor_network";

/// Where a Tor client is allowed to bootstrap from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapTarget {
    /// A directory the caller named explicitly — normally a local `tor_relay`.
    CustomDirectory(String),
    /// The real Tor directory authorities, on the public internet. Opt-in only.
    PublicNetwork,
}

/// Decide what `connect()` may bootstrap against, and refuse rather than reach the internet.
///
/// # Why this exists
///
/// `arti_client::TorClient::create_bootstrapped()` contacts the real Tor directory authorities
/// **before it ever looks at the requested address** — measured at 14 seconds in an unguarded
/// run. So merely *opening* a Tor client made outbound connections to third parties, whatever
/// the user asked it to connect to. That is surprising for a tool that binds loopback
/// everywhere else, and it made the client impossible to exercise offline: the whole-registry
/// smoke test had to carve out a named exclusion for Tor because running it would have put a
/// smoke test on the public internet.
///
/// # Why refuse rather than make it lazy
///
/// Deferring the bootstrap until a request "genuinely needs the network" buys nothing here:
/// `connect()` is *given* the destination, so the need is immediate and the bootstrap would
/// happen a few milliseconds later anyway — with the failure now surfacing somewhere with
/// worse reporting than `connect()`'s `Err`. Deferral would hide the reach, not prevent it.
/// The property worth having is that the reach is a **decision the caller made**, and the only
/// way to express that is an explicit opt-in.
///
/// # The rule
///
/// * `directory_server` set → the caller named the directory to bootstrap from (normally a
///   local `tor_relay`). That is already an explicit choice, so it is allowed as-is.
/// * `allow_public_tor_network: true` → the caller explicitly asked for the real network.
/// * Neither → `Err`, naming the parameter. **This is the default.**
///
/// Setting both is a contradiction and is refused rather than silently resolved: which one the
/// caller meant is not inferable, and guessing is how a "local test" ends up on the public
/// internet.
pub fn bootstrap_target(
    directory_server: Option<&str>,
    allow_public_tor_network: bool,
) -> Result<BootstrapTarget> {
    match (directory_server, allow_public_tor_network) {
        (Some(dir), false) => Ok(BootstrapTarget::CustomDirectory(dir.to_string())),
        (None, true) => Ok(BootstrapTarget::PublicNetwork),
        (Some(dir), true) => Err(anyhow::anyhow!(
            "Tor client: `directory_server` ({dir}) and `{ALLOW_PUBLIC_TOR_NETWORK_PARAM}` are \
             mutually exclusive — the first bootstraps from the directory you named, the second \
             from the public Tor directory authorities. Pass exactly one."
        )),
        (None, false) => Err(anyhow::anyhow!(
            "Tor client refused to start: bootstrapping contacts the real Tor directory \
             authorities on the public internet, and does so before it looks at the address you \
             asked for — so opening this client would make outbound connections to third \
             parties regardless of the destination. NetGet does not do that by default. Either \
             pass `directory_server` (e.g. \"127.0.0.1:9001\", a local `tor_relay`) to bootstrap \
             locally, or pass `{ALLOW_PUBLIC_TOR_NETWORK_PARAM}: true` to opt in to the public \
             Tor network."
        )),
    }
}

/// The write half of a Tor circuit, once one exists.
type TorWriteHalf = Arc<Mutex<tokio::io::WriteHalf<arti_client::DataStream>>>;

/// Run one directory verb. Needs no circuit — the consensus lives in `AppState`, put there
/// when `create_bootstrapped` returned.
#[cfg(unix)]
async fn run_directory_action(
    name: &str,
    data: &serde_json::Value,
    client_id: ClientId,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    match name {
        "get_consensus_info" => match TorClient::get_consensus_info(app_state, client_id).await {
            Ok(info) => {
                let _ = status_tx.send(format!(
                    "[TOR] Consensus: {} relays, valid until {}",
                    info["relay_count"], info["valid_until"]
                ));
                trace!("Consensus info: {}", info);
            }
            Err(e) => {
                error!("Failed to get consensus info: {}", e);
                let _ = status_tx.send(format!("[TOR] Error: {}", e));
            }
        },
        "list_relays" | "search_relays" => {
            let limit = data.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let filter = RelayFilter {
                flags: data.get("flags").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
                nickname_pattern: data
                    .get("nickname")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                limit: Some(limit),
                ..Default::default()
            };
            match TorClient::query_relays(app_state, client_id, filter).await {
                Ok(relays) => {
                    let _ = status_tx.send(format!("[TOR] Found {} relays", relays.len()));
                    for (i, relay) in relays.iter().take(10).enumerate() {
                        trace!(
                            "Relay {}: {} ({})",
                            i + 1,
                            relay.nickname,
                            relay.flags.join(", ")
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to query relays: {}", e);
                    let _ = status_tx.send(format!("[TOR] Error: {}", e));
                }
            }
        }
        other => {
            warn!("Unknown custom action: {}", other);
        }
    }
}

/// Carry out what the model answered with. Returns `true` if it asked to disconnect.
///
/// `write_half` is `None` at `tor_bootstrap_complete`, which fires while `connect()` is still
/// bootstrapping and no circuit exists yet. A `send_tor_data` there is **refused loudly**
/// rather than dropped: the directory verbs are the ones that make sense at that moment, and
/// the model needs to be told which of its answers could not be carried out. Every other
/// caller has a circuit and passes `Some`.
///
/// `pub` so `tests/client/tor/` can pin the no-circuit contract directly: a live test would
/// need a real Tor bootstrap and a circuit, which this repo has no cheap loopback for.
pub async fn apply_actions(
    actions: Vec<serde_json::Value>,
    write_half: Option<&TorWriteHalf>,
    client_id: ClientId,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
) -> bool {
    apply_actions_to(actions, write_half, client_id, app_state, status_tx).await
}

/// [`apply_actions`] over any write half, so [`run_circuit`] can be driven over a plain socket.
async fn apply_actions_to<W>(
    actions: Vec<serde_json::Value>,
    write_half: Option<&Arc<Mutex<W>>>,
    client_id: ClientId,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use crate::llm::actions::client_trait::{Client, ClientActionResult};
    let protocol = crate::client::tor::actions::TorClientProtocol::new();

    for action in actions {
        match protocol.execute_action(action) {
            Ok(ClientActionResult::SendData(bytes)) => {
                let Some(write_half) = write_half else {
                    warn!(
                        "Tor client {} cannot send {} bytes: no circuit yet",
                        client_id,
                        bytes.len()
                    );
                    let _ = status_tx.send(format!(
                        "[TOR] ✖ send_tor_data ignored for client {}: the circuit is not open yet",
                        client_id
                    ));
                    continue;
                };
                match write_half.lock().await.write_all(&bytes).await {
                    Ok(()) => trace!("Tor client {} sent {} bytes", client_id, bytes.len()),
                    Err(e) => error!("Tor client {} write failed: {}", client_id, e),
                }
            }
            Ok(ClientActionResult::Disconnect) => {
                info!("Tor client {} disconnecting", client_id);
                return true;
            }
            #[cfg(unix)]
            Ok(ClientActionResult::Custom { name, data }) => {
                run_directory_action(&name, &data, client_id, app_state, status_tx).await;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Tor client {} rejected action: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[TOR] ✖ client {} rejected action: {}",
                    client_id, e
                ));
            }
        }
    }
    false
}

/// Drive one open circuit: the `tor_connected` call, then every payload the destination
/// sends, then the end of the stream — with the command channel served throughout.
///
/// The circuit is read on a registered task of its own (`client/inbound_queue.rs`), so what
/// the destination sends while the model is answering keeps its read boundaries in a bounded
/// queue instead of merging in arti's buffer: with batching on everything waiting is answered
/// as one payload, with it off one read per call.
///
/// Generic over the stream halves and `pub` because a real circuit needs a full Tor bootstrap
/// this repository has no cheap loopback for; `tests/client/tor/batching_test.rs` drives this
/// over a plain socket instead. `connect_with_llm_actions` calls it with arti's halves.
#[allow(clippy::too_many_arguments)]
pub async fn run_circuit<R, W>(
    read_half: R,
    write_half: Arc<Mutex<W>>,
    mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    remote_addr: String,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    use crate::client::inbound_queue::{Inbound, InboundQueue};

    let mut memory = String::new();

    // `tor_connected`: ask the model what to do with the circuit, then do it. The
    // answer used to be `Ok(_) => trace!("LLM called successfully")` — the round-trip
    // was paid for and every action the model chose was dropped on the floor, so a
    // client told "send an HTTP GET and analyse the response" sent nothing and then
    // waited forever for a reply to a request it never made.
    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
        let protocol = crate::client::tor::actions::TorClientProtocol::new();
        let event = Event::new(
            &TOR_CLIENT_CONNECTED_EVENT,
            serde_json::json!({ "target": remote_addr }),
        );
        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            "",
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
                    memory = mem;
                }
                if apply_actions_to(
                    actions,
                    Some(&write_half),
                    client_id,
                    &app_state,
                    &status_tx,
                )
                .await
                {
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    app_state.remove_client_handle(client_id).await;
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "Failed to call LLM for Tor client {} connection: {}",
                    client_id, e
                );
            }
        }
    }

    let mut inbound = InboundQueue::spawn(&app_state, client_id, read_half).await;

    loop {
        let first = tokio::select! {
            first = inbound.recv() => first,
            Some(cmd) = command_rx.recv() => {
                let disconnect = crate::client::command_support::handle_stream_client_command(
                    &crate::client::tor::actions::TorClientProtocol,
                    &write_half,
                    cmd,
                    client_id,
                    &app_state,
                    &status_tx,
                )
                .await;
                if disconnect {
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send(format!(
                        "[CLIENT] Tor client {} disconnected (injected action)",
                        client_id
                    ));
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    break;
                }
                continue;
            }
        };
        let (mut data, mut ended) = match first {
            Inbound::Data(data) => (data, None),
            other => (Vec::new(), Some(other)),
        };

        if !data.is_empty() {
            // With batching on, everything else already waiting joins this payload; an end
            // of stream found while sweeping is handled after it is answered.
            let batching = app_state
                .client_conversation_settings(client_id)
                .await
                .is_some_and(|(_, batching)| batching);
            if batching {
                ended = inbound.drain_into(&mut data);
            }
            trace!("Tor client {} received {} bytes", client_id, data.len());

            // A `disconnect` used to `break` the `for action in actions` loop and nothing
            // else, so the model could never actually close a Tor client: it stopped
            // executing the rest of that one answer and went straight back to reading. The
            // flag carries the decision out to this loop.
            let mut disconnect_requested = false;
            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                let protocol = crate::client::tor::actions::TorClientProtocol::new();
                let event = Event::new(
                    &TOR_CLIENT_DATA_RECEIVED_EVENT,
                    crate::client::tor::actions::inbound_event_fields(&data),
                );
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
                            memory = mem;
                        }
                        // Shared with the connected-event and bootstrap-complete paths, so
                        // the Tor action vocabulary is executed in exactly one place.
                        disconnect_requested = apply_actions_to(
                            actions,
                            Some(&write_half),
                            client_id,
                            &app_state,
                            &status_tx,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("LLM error for Tor client {}: {}", client_id, e);
                    }
                }
            }

            if disconnect_requested {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send(format!(
                    "[CLIENT] Tor client {} disconnected (model asked)",
                    client_id
                ));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }

        match ended {
            Some(Inbound::Closed) => {
                info!("Tor client {} disconnected", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send(format!("[CLIENT] Tor client {} disconnected", client_id));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
            Some(Inbound::Failed(e)) => {
                error!("Tor client {} read error: {}", client_id, e);
                app_state
                    .update_client_status(client_id, ClientStatus::Error(e))
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
            _ => {}
        }
    }

    drop(inbound);
    // The loop owns the only receiver; dropping the registered handle
    // makes later send_to_client calls fail fast instead of timing out.
    app_state.remove_client_handle(client_id).await;
}

/// Tor client that connects through the Tor network
pub struct TorClient;

impl TorClient {
    /// Connect to a destination through Tor with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!("Tor client {} initializing...", client_id);
        let _ = status_tx.send(format!("[CLIENT] Tor client {} initializing...", client_id));

        // Choose the directory to bootstrap from — and refuse to reach the public Tor network
        // unless the caller asked for it. See `bootstrap_target` for the reasoning.
        let directory_server = match startup_params {
            Some(ref params) => params.get_optional_string("directory_server")?,
            None => None,
        };
        let allow_public = match startup_params {
            Some(ref params) => params
                .get_optional_bool(ALLOW_PUBLIC_TOR_NETWORK_PARAM)?
                .unwrap_or(false),
            None => false,
        };

        let config = match bootstrap_target(directory_server.as_deref(), allow_public)? {
            BootstrapTarget::CustomDirectory(directory_server) => {
                info!(
                    "Tor client {} using custom directory server: {}",
                    client_id, directory_server
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] Tor client {} using custom directory: {}",
                    client_id, directory_server
                ));
                Self::create_custom_config(&directory_server)?
            }
            BootstrapTarget::PublicNetwork => {
                // Loud, because this is the one path that leaves the machine.
                warn!(
                    "Tor client {} is bootstrapping against the PUBLIC Tor directory \
                     authorities ({}=true): this makes outbound connections to third parties \
                     before any traffic is sent to {}",
                    client_id, ALLOW_PUBLIC_TOR_NETWORK_PARAM, remote_addr
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] ⚠ Tor client {} contacting the PUBLIC Tor directory authorities \
                     (opted in via {})",
                    client_id, ALLOW_PUBLIC_TOR_NETWORK_PARAM
                ));
                TorClientConfig::default()
            }
        };

        let tor_client = ArtiClient::create_bootstrapped(config)
            .await
            .context("Failed to bootstrap Tor client")?;

        info!("Tor client {} bootstrapped successfully", client_id);
        let _ = status_tx.send(format!("[CLIENT] Tor client {} bootstrapped", client_id));

        // Store Tor client for directory queries (requires experimental-api feature)
        #[cfg(unix)]
        app_state
            .set_tor_client(client_id, Arc::new(tor_client.clone()))
            .await;

        // Emit bootstrap complete event with consensus info
        #[cfg(unix)]
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::tor::actions::TorClientProtocol::new());

            // Try to get consensus info (may fail if bootstrap just completed)
            match Self::get_consensus_info(&app_state, client_id).await {
                Ok(info) => {
                    use crate::client::tor::actions::TOR_BOOTSTRAP_COMPLETE_EVENT;
                    let event = Event::new(
                        &TOR_BOOTSTRAP_COMPLETE_EVENT,
                        serde_json::json!({
                            "relay_count": info["relay_count"],
                            "valid_after": info["valid_after"],
                        }),
                    );

                    // The answer is carried out, not just logged. At this point there is no
                    // circuit — `connect()` has not run — so `apply_actions` gets `None` and
                    // the directory verbs (`get_consensus_info`, `list_relays`,
                    // `search_relays`) are the ones that can do anything. That is exactly
                    // what this event is for: it reports `relay_count` and `valid_after`, and
                    // its whole purpose is letting the model query the consensus it just
                    // learned about.
                    match call_llm_for_client(
                        &llm_client,
                        &app_state,
                        client_id.to_string(),
                        &instruction,
                        "",
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
                            if let Some(mem) = memory_updates {
                                app_state.set_memory_for_client(client_id, mem).await;
                            }
                            apply_actions(actions, None, client_id, &app_state, &status_tx).await;
                        }
                        Err(e) => {
                            warn!("Failed to call LLM for bootstrap event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        "Could not get consensus info at bootstrap (may not be available yet): {}",
                        e
                    );
                }
            }
        }

        // Parse target address (can be hostname:port or .onion:port)
        let target = remote_addr.clone();

        // Connect through Tor
        let stream = tor_client
            .connect(target.as_str())
            .await
            .context(format!("Failed to connect to {} through Tor", target))?;

        // Get a dummy local address since Tor connections don't have real local addresses
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));

        info!(
            "Tor client {} connected to {} through Tor network",
            client_id, remote_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Tor client {} connected to {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // The `tor_connected` LLM call happens inside the read-loop task below, not here.
        // Two reasons, both of which were bugs at this spot: it needs the write half to carry
        // out what the model answers with, and it must not precede the command channel's
        // registration — a manual `*` routing rule parks this call until a human answers, and
        // the dashboard's `[ send ]` has to reach the client for the whole park.

        // Split stream into read/write halves
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc: TorWriteHalf = Arc::new(Mutex::new(write_half));

        // Command channel: lets the dashboard inject actions into this loop
        // via AppState::send_to_client (see client/command_support.rs).
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(run_circuit(
            read_half,
            write_half_arc,
            command_rx,
            remote_addr,
            llm_client,
            app_state,
            status_tx,
            client_id,
        ));
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Create custom TorClientConfig pointing to a localhost Tor relay
    ///
    /// This allows testing with a local tor_relay server (using BEGIN_DIR for directory queries)
    /// instead of real Tor network. The directory_server parameter should be in format "127.0.0.1:9001"
    #[cfg(unix)]
    fn create_custom_config(directory_server: &str) -> Result<TorClientConfig> {
        use arti_client::config::dir::FallbackDir;

        // Parse the directory server address
        let addr: SocketAddr = directory_server.parse().context(
            "Invalid directory_server address format. Expected 'IP:port' like '127.0.0.1:9030'",
        )?;

        // WARNING: Arti FallbackDir requires an OR (relay) port, but we only have HTTP directory
        // This configuration will likely fail during bootstrap because Arti expects a working
        // Tor relay at the OR port, not just an HTTP directory server.
        //
        // For now, we configure the OR port to point to the same address as a workaround,
        // but this is a fundamental incompatibility: Arti needs a full Tor relay to bootstrap,
        // not just a directory server.

        let mut fallback = FallbackDir::builder();
        fallback
            .rsa_identity([0x42; 20].into()) // Dummy RSA identity
            .ed_identity([0x99; 32].into()) // Dummy Ed25519 identity
            .orports() // Arti only supports orports(), not dirports()
            .push(addr);

        // Build config with custom fallback
        let mut bld = TorClientConfig::builder();
        bld.tor_network().set_fallback_caches(vec![fallback]);

        // Note: We don't set custom authorities here because fallback_caches is sufficient
        // for bootstrapping. The client will use the fallback to fetch the consensus.

        let config = bld.build().context("Failed to build TorClientConfig")?;

        Ok(config)
    }

    /// Get network directory from Arti (requires experimental-api feature)
    #[cfg(unix)]
    pub async fn get_netdir(
        app_state: &Arc<crate::state::app_state::AppState>,
        client_id: crate::state::ClientId,
    ) -> Result<Arc<NetDir>> {
        let tor_client = app_state
            .get_tor_client(client_id)
            .await
            .context("Tor client not found in app state")?;

        // Access directory manager (requires experimental-api feature)
        let dirmgr = tor_client.dirmgr();

        // Get current network directory
        let netdir = dirmgr
            .netdir(tor_netdir::Timeliness::Timely)
            .context("No network directory available - client may still be bootstrapping")?;

        Ok(netdir)
    }

    /// Query relays from network directory with optional filter
    #[cfg(unix)]
    pub async fn query_relays(
        app_state: &Arc<crate::state::app_state::AppState>,
        client_id: crate::state::ClientId,
        filter: RelayFilter,
    ) -> Result<Vec<RelayInfo>> {
        let netdir = Self::get_netdir(app_state, client_id).await?;

        let limit = filter.limit.unwrap_or(100);
        let mut relays = Vec::new();

        for relay in netdir.relays() {
            if filter.matches(&relay) {
                relays.push(RelayInfo::from_relay(&relay));
                if relays.len() >= limit {
                    break;
                }
            }
        }

        Ok(relays)
    }

    /// Get consensus metadata (relay count, validity times)
    #[cfg(unix)]
    pub async fn get_consensus_info(
        app_state: &Arc<crate::state::app_state::AppState>,
        client_id: crate::state::ClientId,
    ) -> Result<serde_json::Value> {
        let netdir = Self::get_netdir(app_state, client_id).await?;

        let relay_count = netdir.relays().count();
        let lifetime = netdir.lifetime();

        Ok(serde_json::json!({
            "relay_count": relay_count,
            "valid_after": format!("{:?}", lifetime.valid_after()),
            "fresh_until": format!("{:?}", lifetime.fresh_until()),
            "valid_until": format!("{:?}", lifetime.valid_until()),
        }))
    }
}
