//! BitTorrent Tracker client implementation
pub mod actions;

pub use actions::TorrentTrackerClientProtocol;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::client::torrent_tracker::actions::{
    TRACKER_ANNOUNCE_RESPONSE_EVENT, TRACKER_SCRAPE_RESPONSE_EVENT,
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

/// BitTorrent tracker response (announce)
#[derive(Debug, Deserialize, Serialize)]
struct TrackerResponse {
    #[serde(rename = "failure reason")]
    failure_reason: Option<String>,
    #[serde(rename = "warning message")]
    warning_message: Option<String>,
    interval: Option<i64>,
    #[serde(rename = "min interval")]
    min_interval: Option<i64>,
    #[serde(rename = "tracker id")]
    tracker_id: Option<String>,
    complete: Option<i64>,
    incomplete: Option<i64>,
    peers: Option<serde_bencode::value::Value>,
}

/// BitTorrent tracker scrape response
#[derive(Debug, Deserialize, Serialize)]
struct ScrapeResponse {
    files: Option<serde_bencode::value::Value>,
}

/// How many LLM turns one announce/scrape chain may take before it is cut.
///
/// The cycle is real: an announce produces `tracker_announce_response`, whose answer may be
/// another announce. Executing the answer (which this client did not used to do) is what makes
/// the recursion possible, so it is bounded rather than avoided by staying silent.
const MAX_FOLLOWUP_DEPTH: u8 = 6;

/// Ceiling on a tracker reply before it is refused, applied while the body streams in.
///
/// A tracker answer is a small bencoded dictionary — a compact peer list of a thousand peers
/// is six kilobytes. `bytes()` would have read whatever the far end chose to send, with no
/// cap at all, so a hostile or broken tracker could hand this client gigabytes and the first
/// sign of it would be the allocator.
const MAX_TRACKER_BODY_BYTES: usize = 1024 * 1024;

/// Wall-clock bound on one announce or scrape.
///
/// `reqwest::get` applies no timeout of any kind, so a tracker that accepts the connection
/// and then says nothing parks the action — and with it whatever injected `[ send ]` is
/// waiting on its outcome — for as long as the peer cares to hold it open.
const TRACKER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{LazyLock, Mutex};

/// One `reqwest::Client` per tracker URL, built once and reused.
///
/// Three things here, all of which the root `CLAUDE.md` records as having cost real debugging
/// time:
///
/// * **Build it once.** `reqwest::get` built a fresh client per request.
/// * **Build it off the runtime.** `Client::builder().build()` sets up the rustls stack and
///   loads the platform root store, which on macOS reads the keychain through
///   Security.framework — synchronously, and serialised across processes. On an async worker
///   that parks the whole thread, so it goes through `spawn_blocking`.
/// * **Key it by URL.** `reqwest` hands even a dotted quad to `getaddrinfo`, which serialises
///   through mDNSResponder on macOS and was measured at 8.25s under load.
///   [`client_for_endpoint_with_timeout`] installs the literal-IP bypass and needs the URL to
///   decide whether to, so a single global client would not do.
///
/// The lock is **never** held across the build. A first version did exactly that — the
/// blocking keychain read happened inside `or_insert_with` while holding this `Mutex` — which
/// parked a worker *and* serialised every tracker client in the process behind it. Two
/// callers racing for the same URL may now both build, and the loser's client is dropped;
/// that is far cheaper than what it replaces.
#[cfg(not(target_arch = "wasm32"))]
static TRACKER_CLIENTS: LazyLock<Mutex<HashMap<String, reqwest::Client>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Lock, look, clone, drop. A poisoned mutex means another thread panicked mid-insert; the map
/// is still structurally sound and building a fresh client is always correct, so it is taken
/// rather than propagated.
#[cfg(not(target_arch = "wasm32"))]
fn cached_tracker_client(tracker_url: &str) -> Option<reqwest::Client> {
    match TRACKER_CLIENTS.lock() {
        Ok(cache) => cache.get(tracker_url).cloned(),
        Err(poisoned) => poisoned.into_inner().get(tracker_url).cloned(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn tracker_reqwest_client(tracker_url: &str) -> reqwest::Client {
    if let Some(client) = cached_tracker_client(tracker_url) {
        return client;
    }

    let url = tracker_url.to_string();
    let timeout = TRACKER_REQUEST_TIMEOUT;
    let built = tokio::task::spawn_blocking(move || {
        crate::llm::ollama_client::client_for_endpoint_with_timeout(&url, timeout)
    })
    .await
    // The closure cannot panic and the task is never aborted, but a default client is a
    // correct answer rather than a reason to fail the announce.
    .unwrap_or_else(|_| reqwest::Client::new());

    let mut cache = match TRACKER_CLIENTS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Whoever inserted first wins, so every later request shares one client.
    cache
        .entry(tracker_url.to_string())
        .or_insert(built)
        .clone()
}

/// The HTTP client for one tracker: the cached reqwest client natively
/// ([`tracker_reqwest_client`]); in the browser build the hyper HTTP/1.1 transport over the
/// page's virtual loopback ([`crate::client::http_fetch`]), bounded by the same
/// [`TRACKER_REQUEST_TIMEOUT`] and reading at most [`MAX_TRACKER_BODY_BYTES`].
async fn tracker_http_client(tracker_url: &str) -> FetchClient {
    #[cfg(not(target_arch = "wasm32"))]
    let client = FetchClient::from_reqwest(tracker_reqwest_client(tracker_url).await);
    #[cfg(target_arch = "wasm32")]
    let client = {
        let _ = tracker_url;
        FetchClient::transport(TRACKER_REQUEST_TIMEOUT).with_max_body(MAX_TRACKER_BODY_BYTES)
    };
    client
}

/// A tracker URL the requests can be built on. A bare `host:port` — what the dashboard's
/// `[ + BitTorrent Tracker client ]` and a model asked to "announce to 127.0.0.1:6969" produce —
/// becomes `http://host:port/announce`: HTTP trackers are plain HTTP by convention, and the
/// announce path is what BEP 3 tracker URLs name. Anything with a scheme is left as given.
/// Without this, the announce URL was `127.0.0.1:6969?info_hash=…`, which is not an absolute
/// URL and failed every request.
pub fn resolve_tracker_url(remote_addr: &str) -> String {
    let trimmed = remote_addr.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    if trimmed.contains('/') {
        format!("http://{trimmed}")
    } else {
        format!("http://{trimmed}/announce")
    }
}

/// GET `url` and return at most [`MAX_TRACKER_BODY_BYTES`] of body, refusing anything longer
/// *while it arrives* rather than after it has all been buffered.
async fn fetch_tracker_body(tracker_url: &str, url: &str) -> Result<Vec<u8>> {
    let mut response = tracker_http_client(tracker_url)
        .await
        .get(url)
        .send()
        .await?;

    // Content-Length is a hint, not a promise — it may be absent, or a lie — so it is used
    // only to refuse early, and the streaming check below is what actually holds.
    if let Some(len) = response.content_length() {
        if len > MAX_TRACKER_BODY_BYTES as u64 {
            return Err(anyhow::anyhow!(
                "tracker declared a {} byte reply, over the {} byte limit",
                len,
                MAX_TRACKER_BODY_BYTES
            ));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_TRACKER_BODY_BYTES {
            return Err(anyhow::anyhow!(
                "tracker reply exceeded the {} byte limit",
                MAX_TRACKER_BODY_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Percent-encode bytes for a query-parameter value, escaping everything but RFC 3986's
/// unreserved set.
fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// Undo percent-encoding. A stray `%` that is not followed by two hex digits is kept as a
/// literal `%`, which is what every lenient decoder does and what re-encoding then escapes.
/// Works on bytes throughout rather than slicing the `&str`: `&value[i + 1..i + 3]` would
/// panic if a `%` were followed by a multi-byte UTF-8 character, and this value comes from
/// the model. That is the byte-index-slicing defect `crate::utils::truncate` exists for.
fn percent_decode(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Normalise a model-supplied `info_hash` or `peer_id` into the percent-encoded form BEP 3
/// carries in the query string.
///
/// These are twenty raw bytes, and their value comes from the model. They used to be
/// interpolated into the URL with `format!` and nothing else, so an `&` or a `#` in one
/// inserted **extra query parameters** into the announce: a model told to announce one
/// info_hash could append its own `&event=completed`, overwrite `port`, or truncate the whole
/// query with a fragment. The parameter description told the model to send the value already
/// URL-encoded — which is not a thing to leave to the component being constrained.
///
/// Three input spellings are accepted because all three are what a model actually produces,
/// and each is reduced to the same twenty bytes before being encoded exactly once:
///
/// * 40 hex characters — the form NetGet's own tracker *server* reports an inbound
///   `info_hash`/`peer_id` in, so it is what a model echoing an event will send.
/// * already percent-encoded (`%12%34…`) — decoded and re-encoded, which normalises it and
///   strips any separator that was sitting in it unescaped.
/// * anything else — raw text, e.g. a literal peer id like `-TR2940-abcdefghijkl`.
///
/// Blind escaping would have been wrong for the second case: `%12` would become `%2512` and
/// the tracker would read the three characters `%12` rather than the byte `0x12`.
fn encode_binary_query_value(value: &str) -> String {
    let bytes = if value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec())
    } else if value.contains('%') {
        percent_decode(value)
    } else {
        value.as_bytes().to_vec()
    };
    percent_encode(&bytes)
}

/// Refuse a bencoded tracker reply whose nesting would recurse `serde_bencode` off the stack.
///
/// `serde_bencode` counts no depth, and a derived struct is no safer than a raw `Value`
/// because serde skips unknown fields through `IgnoredAny`, which lands back in
/// `deserialize_any`. A reply body of `l` bytes therefore recurses once per byte; a stack
/// overflow is `SIGSEGV`, so it aborts the whole netget process rather than failing this one
/// action. The tracker is whatever address the operator or the model pointed this client at.
fn screen_tracker_body(body: &[u8]) -> Result<()> {
    crate::utils::bencode::check_bencode_structure(body)
        .map_err(|e| anyhow::anyhow!("tracker reply refused before decoding: {}", e))
}

/// BitTorrent Tracker client
pub struct TorrentTrackerClient;

impl TorrentTrackerClient {
    /// Connect to a BitTorrent tracker with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // BitTorrent tracker is HTTP-based, so we don't maintain a persistent connection
        // We'll just track the tracker URL and make HTTP requests as needed
        let remote_addr = resolve_tracker_url(&remote_addr);
        // In the browser build the transport has no TLS: an `https://` tracker is refused
        // here, with the reason, rather than on the first announce.
        crate::client::http_fetch::check_url(&remote_addr)?;

        info!(
            "BitTorrent Tracker client {} initialized for {}",
            client_id, remote_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] BitTorrent Tracker client {} connected to {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered - and already being drained by its own task - BEFORE the
        // connected-event LLM call, which a manual `*` rule can park for minutes: the
        // operator must be able to reach the client while it waits. This is also what
        // keeps the client reachable at all, since a tracker client has no read loop.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            remote_addr.clone(),
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(
                crate::client::torrent_tracker::actions::TorrentTrackerClientProtocol::new(),
            );
            let event = Event::new(
                &TRACKER_ANNOUNCE_RESPONSE_EVENT,
                serde_json::json!({
                    "tracker_url": remote_addr,
                    "status": "connected",
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            // Execute LLM call in background
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();
            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
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

                        // Execute actions
                        for action in actions {
                            match protocol.as_ref().execute_action(action.clone()) {
                                Ok(result) => {
                                    if let Err(e) = Self::apply_action(
                                        client_id,
                                        result,
                                        Notify::Inline,
                                        0,
                                        &remote_addr,
                                        &app_state_clone,
                                        &llm_client,
                                        &status_tx_clone,
                                    )
                                    .await
                                    {
                                        error!("Failed to execute tracker action: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Tracker action execution error: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for Tracker client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        // Return a dummy local address (tracker is HTTP-based)
        Ok("0.0.0.0:0".parse()?)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: it writes
    /// `SendData` to a socket, and both tracker verbs yield `ClientActionResult::Custom`
    /// that has to become an HTTP GET against the tracker. So the action goes through
    /// [`Self::apply_action`] - the same function the connected-event path uses - and the
    /// outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        tracker_url: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::torrent_tracker::actions::TorrentTrackerClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // The HTTP GET is awaited, so the reported outcome describes a request
                // that has actually completed. Notify::Deferred delivers the tracker
                // response event from its own registered task, so a manual handler parked
                // for a human's think time cannot wedge this loop or time out the
                // dashboard's [ send ].
                Ok(result) => Self::apply_action(
                    client_id,
                    result,
                    Notify::Deferred,
                    0,
                    &tracker_url,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
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
                    "Tracker client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        info!("Tracker client {} command loop stopped", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Deliver a tracker response event to the LLM, inline or from its own registered
    /// task depending on `notify`.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        notify: Notify,
        client_id: ClientId,
        event_type: &'static crate::protocol::EventType,
        event_data: serde_json::Value,
        depth: u8,
        tracker_url: &str,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        match notify {
            Notify::Inline => {
                Self::notify_response(
                    client_id,
                    event_type,
                    event_data,
                    depth,
                    tracker_url.to_string(),
                    app_state,
                    llm_client,
                    status_tx,
                )
                .await
            }
            Notify::Deferred => {
                let state_clone = app_state.clone();
                let llm_clone = llm_client.clone();
                let status_clone = status_tx.clone();
                let tracker_url = tracker_url.to_string();
                let notify_handle = tokio::spawn(async move {
                    TorrentTrackerClient::notify_response(
                        client_id,
                        event_type,
                        event_data,
                        depth,
                        tracker_url,
                        &state_clone,
                        &llm_clone,
                        &status_clone,
                    )
                    .await;
                });
                // Registered so the notification - and the LLM call it makes - is aborted
                // when the client is stopped.
                app_state
                    .register_client_task(client_id, notify_handle)
                    .await;
            }
        }
    }

    /// Fire one tracker response event at the LLM, apply any memory update, and **carry out
    /// what it answered with**.
    ///
    /// The answer used to be destructured as `Ok(ClientLlmResult { memory_updates, .. })` —
    /// the actions dropped by the `..`. That cut every chain at one step: the model asked for
    /// an announce, the tracker's peer list came back, the model was told about it, chose what
    /// to do next, and was ignored. A tracker client could make exactly one request per
    /// instruction and then went deaf.
    ///
    /// Executing here makes the cycle real — announce → `tracker_announce_response` →
    /// announce — so it is bounded rather than cut. `depth` counts LLM turns in one chain and
    /// [`MAX_FOLLOWUP_DEPTH`] stops it; [`Self::apply_action`] returns an explicitly boxed
    /// future so the three-function cycle's opaque types can be inferred at all.
    #[allow(clippy::too_many_arguments)]
    async fn notify_response(
        client_id: ClientId,
        event_type: &'static crate::protocol::EventType,
        event_data: serde_json::Value,
        depth: u8,
        tracker_url: String,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let event = Event::new(event_type, event_data);
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
        let protocol =
            Arc::new(crate::client::torrent_tracker::actions::TorrentTrackerClientProtocol::new());

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
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                if actions.is_empty() {
                    return;
                }
                if depth >= MAX_FOLLOWUP_DEPTH {
                    warn!(
                        "Tracker client {} stopped a follow-up chain at depth {}: {} action(s) \
                         not executed",
                        client_id,
                        depth,
                        actions.len()
                    );
                    let _ = status_tx.send(format!(
                        "[CLIENT] ⚠ tracker client {} hit the follow-up depth limit ({}); \
                         {} action(s) were not executed",
                        client_id,
                        MAX_FOLLOWUP_DEPTH,
                        actions.len()
                    ));
                    return;
                }

                for action in actions {
                    match protocol.as_ref().execute_action(action) {
                        Ok(result) => {
                            match Self::apply_action(
                                client_id,
                                result,
                                Notify::Inline,
                                depth + 1,
                                &tracker_url,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await
                            {
                                Ok(Applied::Disconnect) => {
                                    app_state
                                        .update_client_status(client_id, ClientStatus::Disconnected)
                                        .await;
                                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                                    return;
                                }
                                Ok(Applied::Executed(detail)) => {
                                    trace!("Tracker client {} follow-up: {}", client_id, detail);
                                }
                                Err(e) => {
                                    error!("Tracker client {} follow-up failed: {}", client_id, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Tracker client {} rejected follow-up action: {}",
                                client_id, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("LLM error: {}", e);
            }
        }
    }

    /// Apply one already-executed action result. The single place a tracker announce or
    /// scrape is issued from, so an injected action behaves exactly like an LLM-produced
    /// one.
    #[allow(clippy::too_many_arguments)]
    /// Returns an explicitly boxed future rather than being an `async fn`, and that is load-
    /// bearing: the chain is `apply_action` -> `deliver` -> `notify_response` ->
    /// `apply_action`, and three `async fn`s in a cycle cannot have their opaque return types
    /// inferred (E0391). Boxing at the *call* site does not help -- coercing to
    /// `dyn Future` still needs the callee's opaque type. Naming the type here breaks the
    /// cycle at the definition. `+ Send` is explicit because `Notify::Deferred` awaits this
    /// inside a `tokio::spawn`.
    #[allow(clippy::too_many_arguments)]
    fn apply_action<'a>(
        client_id: ClientId,
        result: ClientActionResult,
        notify: Notify,
        depth: u8,
        tracker_url: &'a str,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
    ) -> Pin<Box<dyn Future<Output = Result<Applied>> + Send + 'a>> {
        Box::pin(async move {
            match result {
                ClientActionResult::Custom { name, data } if name == "tracker_announce" => {
                    let info_hash = data
                        .get("info_hash")
                        .and_then(|v| v.as_str())
                        .context("Missing info_hash")?;
                    let peer_id = data
                        .get("peer_id")
                        .and_then(|v| v.as_str())
                        .context("Missing peer_id")?;
                    let port = data
                        .get("port")
                        .and_then(|v| v.as_u64())
                        .context("Missing port")?;
                    let port = u16::try_from(port).context("tracker port exceeds u16")?;
                    let uploaded = data.get("uploaded").and_then(|v| v.as_u64()).unwrap_or(0);
                    let downloaded = data.get("downloaded").and_then(|v| v.as_u64()).unwrap_or(0);
                    // `left` is not a neutral counter: BEP 3 defines `left=0` as "I have the
                    // complete torrent", and trackers use it to decide who is a seeder. A
                    // model that says nothing about it should not be announcing itself as
                    // having everything, so the default is the opposite claim. An explicit 0
                    // still means seeder, which is the point.
                    let left = data
                        .get("left")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(u64::MAX);
                    let event_type = data
                        .get("event")
                        .and_then(|v| v.as_str())
                        .unwrap_or("started");

                    // Build announce URL.
                    //
                    // `info_hash`, `peer_id` and `event` come from the model and are
                    // percent-encoded rather than interpolated raw: an `&` in any of them
                    // used to insert extra query parameters into the announce, so a model
                    // told to announce one info_hash could append its own `event=completed`
                    // or overwrite `port`. The numeric fields are `u64` already and cannot
                    // carry a separator.
                    let announce_url = format!(
                        "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&event={}",
                        tracker_url,
                        encode_binary_query_value(info_hash),
                        encode_binary_query_value(peer_id),
                        port,
                        uploaded,
                        downloaded,
                        left,
                        percent_encode(event_type.as_bytes())
                    );

                    trace!(
                        "Tracker client {} announcing to: {}",
                        client_id,
                        announce_url
                    );

                    // Bounded fetch: a shared client with a timeout, a body cap applied as
                    // the bytes arrive, and a nesting screen before serde_bencode sees them.
                    let body = fetch_tracker_body(tracker_url, &announce_url).await?;
                    if let Err(e) = screen_tracker_body(&body) {
                        warn!("Tracker client {} refused announce reply: {}", client_id, e);
                        return Ok(Applied::Executed(format!(
                            "tracker_announce sent; the tracker's reply was refused: {e}"
                        )));
                    }

                    // Parse bencode response
                    match serde_bencode::from_bytes::<TrackerResponse>(&body) {
                        Ok(tracker_resp) => {
                            trace!("Tracker response: {:?}", tracker_resp);

                            Self::deliver(
                                notify,
                                client_id,
                                &TRACKER_ANNOUNCE_RESPONSE_EVENT,
                                serde_json::json!({
                                    "interval": tracker_resp.interval,
                                    "complete": tracker_resp.complete,
                                    "incomplete": tracker_resp.incomplete,
                                    "peers": format!("{:?}", tracker_resp.peers),
                                }),
                                depth,
                                tracker_url,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to parse tracker response: {}", e);
                            return Ok(Applied::Executed(format!(
                                "tracker_announce sent; the tracker's reply could not be \
                                 bdecoded: {e}"
                            )));
                        }
                    }
                    Ok(Applied::Executed("tracker_announce completed".to_string()))
                }
                ClientActionResult::Custom { name, data } if name == "tracker_scrape" => {
                    let info_hash = data
                        .get("info_hash")
                        .and_then(|v| v.as_str())
                        .context("Missing info_hash")?;

                    // Build scrape URL. Percent-encoded for the same reason as the announce
                    // above: an `&` in a model-supplied info_hash is otherwise a separator.
                    let scrape_url = format!(
                        "{}?info_hash={}",
                        tracker_url,
                        encode_binary_query_value(info_hash)
                    );

                    trace!("Tracker client {} scraping: {}", client_id, scrape_url);

                    // Same bounded fetch and nesting screen as the announce path above.
                    let body = fetch_tracker_body(tracker_url, &scrape_url).await?;
                    if let Err(e) = screen_tracker_body(&body) {
                        warn!("Tracker client {} refused scrape reply: {}", client_id, e);
                        return Ok(Applied::Executed(format!(
                            "tracker_scrape sent; the tracker's reply was refused: {e}"
                        )));
                    }

                    // Parse bencode response
                    match serde_bencode::from_bytes::<ScrapeResponse>(&body) {
                        Ok(scrape_resp) => {
                            trace!("Scrape response: {:?}", scrape_resp);

                            Self::deliver(
                                notify,
                                client_id,
                                &TRACKER_SCRAPE_RESPONSE_EVENT,
                                serde_json::json!({
                                    "files": format!("{:?}", scrape_resp.files),
                                }),
                                depth,
                                tracker_url,
                                app_state,
                                llm_client,
                                status_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to parse scrape response: {}", e);
                            return Ok(Applied::Executed(format!(
                                "tracker_scrape sent; the tracker's reply could not be \
                                 bdecoded: {e}"
                            )));
                        }
                    }
                    Ok(Applied::Executed("tracker_scrape completed".to_string()))
                }
                ClientActionResult::Disconnect => {
                    info!("Tracker client {} disconnecting", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    // Every exit path drops the handle so the dashboard stops offering
                    // [ send ] into a dead client.
                    app_state.remove_client_handle(client_id).await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    Ok(Applied::Disconnect)
                }
                other => Ok(Applied::Executed(format!(
                    "{other:?} produced no tracker request"
                ))),
            }
        })
    }
}

/// When an action's tracker response event is delivered to the LLM.
///
/// The announce/scrape GET itself is always awaited; only the notification moves. The
/// request is already inside a spawned task on the LLM-driven path, so unlike `http` there
/// is no second "spawn the request" mode here.
#[derive(Clone, Copy)]
enum Notify {
    /// Fire the event before returning. The LLM-driven path.
    Inline,
    /// Fire the event from its own registered task and return at once. The
    /// injected-command path, which must reply to the operator first.
    Deferred,
}

/// What [`TorrentTrackerClient::apply_action`] did with one action. A tracker client owns
/// no socket - each announce/scrape is a one-shot HTTP GET - so there is no honest byte
/// count to report, only "the request ran" or "the session should end".
enum Applied {
    /// The action ran; the string says what, for the injected action's outcome detail.
    Executed(String),
    /// The session should end.
    Disconnect,
}
