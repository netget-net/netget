//! RSS (Really Simple Syndication) Feed Client
//!
//! Fetches and parses RSS 2.0 XML feeds with LLM-controlled interpretation.
//! The LLM decides which feeds to fetch and how to process items.

pub mod actions;

pub use actions::RssClientProtocol;

use crate::client::llm_budget::call_llm_for_client;
use crate::client::rss::actions::{RSS_CLIENT_CONNECTED_EVENT, RSS_CLIENT_FEED_FETCHED_EVENT};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use anyhow::{Context, Result};
use rss::Channel;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// Guard against a model that keeps chaining `fetch_rss_feed` forever.
const MAX_CHAINED_FETCHES: usize = 16;

/// How often the command loop re-checks that its client still exists. RSS is a
/// fetch-on-demand client with no socket to notice a close on.
const REMOVAL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

struct ClientData {
    memory: String,
}

/// Everything the fetch machinery needs besides the URL queue.
///
/// Bundled because the injected-command loop starts a fetch chain with exactly the
/// same context the connect path uses, and passing nine arguments to three functions
/// invites them to drift apart.
struct FetchCtx {
    base_url: String,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    instruction: String,
    client_data: Arc<Mutex<ClientData>>,
    protocol: Arc<RssClientProtocol>,
}

/// What one executed action asked for.
enum Applied {
    /// Fetch this (already resolved) feed URL.
    Fetch(String),
    /// End the session.
    Disconnect,
    /// Take no action and wait.
    WaitForMore,
    /// The action ran but this client has nothing to do with the result.
    Ignored(String),
}

/// How a chain of fetches ended.
enum ChainEnd {
    /// The queue emptied (or hit the chain limit) with the client still alive.
    Drained,
    /// The chain set a terminal client status itself (fetch error, or disconnect).
    Terminated,
}

/// What the model said about a fetched feed.
enum Notified {
    /// Fetch these next.
    Queue(Vec<String>),
    /// End the session.
    Disconnect,
}

/// Turn whatever the model put in `url` into an absolute URL.
///
/// A bare path (`/news.xml`) is resolved against the address the client was opened on;
/// an absolute URL is used verbatim.
pub fn resolve_feed_url(base_url: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else if let Some(path) = url.strip_prefix('/') {
        format!("{}/{}", base_url.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", base_url.trim_end_matches('/'), url)
    }
}

/// Convert a parsed RSS channel into the structured event payload the model sees.
///
/// Deliberately structured fields, never raw XML — models cannot reliably parse XML back out.
pub fn channel_to_event_data(url: &str, channel: &Channel) -> serde_json::Value {
    let items: Vec<_> = channel
        .items()
        .iter()
        .map(|item| {
            json!({
                "title": item.title(),
                "link": item.link(),
                "description": item.description(),
                "author": item.author(),
                "pub_date": item.pub_date(),
                "guid": item.guid().map(|g| g.value()),
            })
        })
        .collect();

    json!({
        "url": url,
        "feed_title": channel.title(),
        "feed_link": channel.link(),
        "feed_description": channel.description(),
        "item_count": channel.items().len(),
        "items": items,
    })
}

/// RSS client
pub struct RssClient;

impl RssClient {
    /// Connect to an RSS feed source and set up LLM integration.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // `Client::connect` must return a concrete socket address, so resolve the host now.
        // This doubles as an early failure if the address is unusable.
        let resolved: SocketAddr = tokio::net::lookup_host(remote_addr.as_str())
            .await
            .with_context(|| format!("Failed to resolve RSS feed host: {}", remote_addr))?
            .next()
            .with_context(|| format!("No addresses for RSS feed host: {}", remote_addr))?;

        let base_url = format!("http://{}", remote_addr);

        info!(
            "RSS client {} targeting {} ({})",
            client_id, base_url, resolved
        );
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] RSS client {} ready ({})",
            client_id, base_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
        }));
        let protocol = Arc::new(RssClientProtocol::new());
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();

        let ctx = Arc::new(FetchCtx {
            base_url: base_url.clone(),
            llm_client: llm_client.clone(),
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            client_id,
            instruction: instruction.clone(),
            client_data: client_data.clone(),
            protocol: protocol.clone(),
        });

        // Injected commands (the dashboard's [ send ]). Registered BEFORE the
        // connected-event LLM call below: a dashboard-created client defaults to a
        // `*` manual rule, so that call can park for minutes waiting for a human and
        // [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_ctx = ctx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(command_rx, cmd_ctx).await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Ask the model which feed to fetch, then service its answer in a background task.
        let event = Event::new(
            &RSS_CLIENT_CONNECTED_EVENT,
            json!({ "base_url": base_url.clone() }),
        );

        let memory_snapshot = client_data.lock().await.memory.clone();
        let first = call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory_snapshot,
            Some(&event),
            protocol.as_ref() as &dyn Client,
            &status_tx,
        )
        .await;

        let mut pending: Vec<String> = Vec::new();
        match first {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    client_data.lock().await.memory = mem;
                }
                for action in actions {
                    match protocol.execute_action(action) {
                        Ok(action_result) => {
                            match Self::apply_action(action_result, &base_url) {
                                Applied::Fetch(url) => pending.push(url),
                                Applied::Disconnect => {
                                    info!(
                                        "RSS client {} disconnecting on model request",
                                        client_id
                                    );
                                    // Drop the command handle so the dashboard stops
                                    // offering [ send ]; that also ends the command loop.
                                    app_state.remove_client_handle(client_id).await;
                                    app_state
                                        .update_client_status(client_id, ClientStatus::Disconnected)
                                        .await;
                                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                                    return Ok(resolved);
                                }
                                Applied::WaitForMore => {}
                                Applied::Ignored(detail) => {
                                    debug!("RSS client {}: {}", client_id, detail)
                                }
                            }
                        }
                        Err(e) => warn!("RSS client {} rejected action: {}", client_id, e),
                    }
                }
            }
            Err(e) => {
                error!("RSS client {} LLM error on connect: {}", client_id, e);
                let _ = status_tx.send(format!("[CLIENT] RSS LLM error on connect: {}", e));
            }
        }

        if pending.is_empty() {
            debug!("RSS client {} idle: model requested no fetch", client_id);
            return Ok(resolved);
        }

        let handle = tokio::spawn(Self::fetch_loop(pending, ctx));
        app_state.register_client_task(client_id, handle).await;

        Ok(resolved)
    }

    /// Drain injected commands until the channel closes (client removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// there is no socket, and `fetch_rss_feed` yields `ClientActionResult::Custom`.
    /// So the action goes through [`Self::apply_action`] — the same function the LLM
    /// path uses — and the outcome is recorded and replied the way the generic arm
    /// does it.
    async fn command_loop(mut command_rx: mpsc::Receiver<ClientCommand>, ctx: Arc<FetchCtx>) {
        let mut removal_check = tokio::time::interval(REMOVAL_CHECK_INTERVAL);
        removal_check.tick().await; // the first tick completes immediately

        loop {
            tokio::select! {
                received = command_rx.recv() => {
                    let Some(command) = received else { break };
                    if Self::handle_command(command, &ctx).await {
                        break;
                    }
                }
                _ = removal_check.tick() => {
                    if ctx.app_state.get_client(ctx.client_id).await.is_none() {
                        info!("RSS client {} stopped", ctx.client_id);
                        break;
                    }
                }
            }
        }

        ctx.app_state.remove_client_handle(ctx.client_id).await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one injected action, record it, and reply. Returns `true` when the
    /// command loop should stop.
    async fn handle_command(command: ClientCommand, ctx: &Arc<FetchCtx>) -> bool {
        let client_id = ctx.client_id;
        let action = command.action.clone();
        let outcome = match ctx.protocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(action_result) => match Self::apply_action(action_result, &ctx.base_url) {
                Applied::Fetch(url) => match Self::fetch_feed(&url).await {
                    // Never `Sent`: reqwest owns the socket and reports no wire byte
                    // count for the GET, so a number here would be invented.
                    // `Executed` carries the parsed item count instead.
                    Ok(event_data) => {
                        let item_count = event_data
                            .get("item_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        // Hand the feed to the model from a separate registered task:
                        // a dashboard client's manual rule can park that LLM call for
                        // minutes, and the command loop must stay responsive.
                        let chain_ctx = ctx.clone();
                        let chain = tokio::spawn(async move {
                            Self::injected_chain(event_data, chain_ctx).await;
                        });
                        ctx.app_state.register_client_task(client_id, chain).await;
                        Ok(ClientSendOutcome::Executed {
                            detail: format!("fetch_rss_feed {} -> {} items", url, item_count),
                        })
                    }
                    Err(e) => Err(e),
                },
                Applied::Disconnect => Ok(ClientSendOutcome::Disconnected),
                Applied::WaitForMore => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                }),
                Applied::Ignored(detail) => Ok(ClientSendOutcome::Executed { detail }),
            },
        };

        let outcome_json = match &outcome {
            Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
            Err(e) => serde_json::json!({"error": e.to_string()}),
        };
        ctx.app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                ctx.protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![outcome_json],
            )
            .await;

        let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
        if let Err(e) = &outcome {
            Log::to(&ctx.status_tx).warn(format!(
                "RSS client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);

        if disconnect {
            ctx.app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
        }
        disconnect
    }

    /// Decide what one executed action means. Shared by the connect path, the fetch
    /// chain and the injected-command loop so URL resolution happens in one place.
    fn apply_action(action_result: ClientActionResult, base_url: &str) -> Applied {
        match action_result {
            ClientActionResult::Custom { name, data } if name == "fetch_rss_feed" => {
                match data.get("url").and_then(|v| v.as_str()) {
                    Some(url) => Applied::Fetch(resolve_feed_url(base_url, url)),
                    None => Applied::Ignored("fetch_rss_feed without a url".to_string()),
                }
            }
            ClientActionResult::Disconnect => Applied::Disconnect,
            ClientActionResult::WaitForMore => Applied::WaitForMore,
            ClientActionResult::NoAction => Applied::Ignored("no_action".to_string()),
            // Not swallowed: an action this client cannot carry out says so, rather
            // than looking identical to success.
            ClientActionResult::Custom { name, .. } => Applied::Ignored(format!(
                "custom result '{name}' is not handled by the RSS client"
            )),
            ClientActionResult::SendData(_) => {
                Applied::Ignored("send_data has no meaning for an RSS client".to_string())
            }
            ClientActionResult::Multiple(_) => {
                Applied::Ignored("multiple results are not produced by the RSS client".to_string())
            }
        }
    }

    /// The model's own fetch chain, started from the connect path: run it, and mark
    /// the client disconnected once it drains.
    async fn fetch_loop(pending: Vec<String>, ctx: Arc<FetchCtx>) {
        if let ChainEnd::Drained = Self::fetch_chain(pending, ctx.clone(), 0).await {
            ctx.app_state
                .update_client_status(ctx.client_id, ClientStatus::Disconnected)
                .await;
            let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
        }
    }

    /// An injected fetch's follow-on: hand the parsed feed to the model and service
    /// whatever it asks for next.
    ///
    /// Unlike [`Self::fetch_loop`] this does *not* mark the client disconnected when
    /// the chain drains — an injected fetch is one operation on a client the operator
    /// is still holding open.
    async fn injected_chain(event_data: serde_json::Value, ctx: Arc<FetchCtx>) {
        match Self::notify_feed_fetched(event_data, &ctx).await {
            Notified::Queue(next) if !next.is_empty() => {
                let _ = Self::fetch_chain(next, ctx, 1).await;
            }
            Notified::Queue(_) => {}
            Notified::Disconnect => {
                info!("RSS client {} disconnecting", ctx.client_id);
                ctx.app_state.remove_client_handle(ctx.client_id).await;
                ctx.app_state
                    .update_client_status(ctx.client_id, ClientStatus::Disconnected)
                    .await;
                let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
            }
        }
    }

    /// Fetch each queued feed, hand the parsed result to the model, and queue whatever it
    /// asks for next. Bounded so a looping model cannot spin forever.
    async fn fetch_chain(
        mut pending: Vec<String>,
        ctx: Arc<FetchCtx>,
        mut fetched: usize,
    ) -> ChainEnd {
        let client_id = ctx.client_id;

        while let Some(url) = pending.pop() {
            if fetched >= MAX_CHAINED_FETCHES {
                warn!(
                    "RSS client {} hit the {}-fetch chain limit",
                    client_id, MAX_CHAINED_FETCHES
                );
                break;
            }
            fetched += 1;

            let event_data = match Self::fetch_feed(&url).await {
                Ok(data) => data,
                Err(e) => {
                    error!("RSS client {} fetch of {} failed: {}", client_id, url, e);
                    let _ = ctx
                        .status_tx
                        .send(format!("[CLIENT] RSS fetch failed: {}", e));
                    ctx.app_state
                        .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                        .await;
                    let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
                    return ChainEnd::Terminated;
                }
            };

            let item_count = event_data
                .get("item_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            info!(
                "RSS client {} parsed {} ({} items)",
                client_id, url, item_count
            );
            let _ = ctx
                .status_tx
                .send(format!("[CLIENT] RSS parsed feed: {} items", item_count));

            match Self::notify_feed_fetched(event_data, &ctx).await {
                Notified::Queue(next) => pending.extend(next),
                Notified::Disconnect => {
                    info!("RSS client {} disconnecting", client_id);
                    ctx.app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
                    return ChainEnd::Terminated;
                }
            }
        }

        ChainEnd::Drained
    }

    /// Hand one parsed feed to the model and collect the URLs it wants next.
    async fn notify_feed_fetched(event_data: serde_json::Value, ctx: &Arc<FetchCtx>) -> Notified {
        let client_id = ctx.client_id;
        let event = Event::new(&RSS_CLIENT_FEED_FETCHED_EVENT, event_data);
        let memory_snapshot = ctx.client_data.lock().await.memory.clone();

        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.app_state,
            client_id.to_string(),
            &ctx.instruction,
            &memory_snapshot,
            Some(&event),
            ctx.protocol.as_ref() as &dyn Client,
            &ctx.status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    ctx.client_data.lock().await.memory = mem;
                }
                let mut next = Vec::new();
                for action in actions {
                    match ctx.protocol.execute_action(action) {
                        Ok(action_result) => {
                            match Self::apply_action(action_result, &ctx.base_url) {
                                Applied::Fetch(url) => next.push(url),
                                Applied::Disconnect => return Notified::Disconnect,
                                Applied::WaitForMore => {}
                                Applied::Ignored(detail) => {
                                    debug!("RSS client {}: {}", client_id, detail)
                                }
                            }
                        }
                        Err(e) => warn!("RSS client {} rejected action: {}", client_id, e),
                    }
                }
                Notified::Queue(next)
            }
            Err(e) => {
                error!("RSS client {} LLM error: {}", client_id, e);
                Notified::Queue(Vec::new())
            }
        }
    }

    /// Fetch one feed over HTTP and turn it into structured event data.
    pub async fn fetch_feed(url: &str) -> Result<serde_json::Value> {
        let response = reqwest::get(url)
            .await
            .with_context(|| format!("Failed to fetch RSS feed {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "RSS fetch of {} failed with status {}",
                url,
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .context("Failed to read RSS response body")?;

        let channel = Channel::read_from(body.as_bytes())
            .with_context(|| format!("Failed to parse RSS feed at {}", url))?;

        Ok(channel_to_event_data(url, &channel))
    }
}
