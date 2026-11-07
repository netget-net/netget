//! Mercurial HTTP server implementation
//!
//! Implements a subset of Mercurial's HTTP wire protocol (version 1) for serving virtual
//! repositories. The LLM controls capabilities, heads, branches and bookmarks.
//!
//! Protocol URLs:
//! - GET  /?cmd=capabilities       - Server capabilities
//! - GET  /?cmd=heads              - Repository heads
//! - GET  /?cmd=branchmap          - Branch mappings
//! - GET  /?cmd=listkeys           - List keys (bookmarks, tags, etc.)
//! - POST /?cmd=getbundle          - Changegroup retrieval (clone/pull)
//!
//! Read-only: there is no `unbundle` endpoint, so pushes are refused.
//!
//! Every command raises an [`Event`] through [`call_llm`], so script and static
//! `event_handlers` work here as they do for every other protocol.

pub mod actions;
pub mod changegroup;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::mercurial::actions::{
    MercurialProtocol, HG_BRANCHMAP_EVENT, HG_CAPABILITIES_EVENT, HG_GETBUNDLE_EVENT,
    HG_HEADS_EVENT, HG_KNOWN_EVENT, HG_LISTKEYS_EVENT, HG_LOOKUP_EVENT, REPOSITORY_RESPONSE,
};
use crate::server::mercurial::changegroup::{
    empty_changegroup, hex, parse_node, ChangegroupError, Repository,
};
use crate::state::app_state::AppState;
use crate::utils::WireFailure;
use crate::{console_error, console_info};

/// Null node ID: Mercurial's "no changeset" sentinel, and the correct `heads` answer for an
/// empty repository.
const NULL_NODE: &str = "0000000000000000000000000000000000000000";

/// Largest request body this server will buffer, in bytes.
///
/// Only `getbundle` has a body at all, and hg puts its arguments there only when they are too
/// long for a URL — kilobytes at most. An unbounded `collect()` lets one unauthenticated
/// client grow the process by whatever it cares to send, so the read is capped and an
/// oversized body is refused with 413.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// How long to wait for a peer's first byte after it connects.
///
/// Mercurial's wire protocol v1 rides on HTTP, which is client-speaks-first — the server says
/// nothing until it has a request line — so a peer that has connected and sent nothing has begun
/// no command at all, which is the state an unauthenticated flood lives in. Enforced with
/// `TcpStream::peek` *before* the socket reaches hyper, so the request line is still there for
/// hyper to parse afterwards.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between commands.
///
/// **This bounds the silence, not the transfer.** An `hg clone` is a sequence of commands —
/// `capabilities`, `heads`, `branchmap`, `listkeys`, `getbundle` — on one keep-alive connection,
/// and each answer is built into a `Full<Bytes>` before the response is returned, so hyper
/// writes an already-complete body and a slow reader is draining bytes rather than idling. The
/// watchdog reads `ConnectionActivity`, which reports a connection with a command in flight as
/// **not idle at all**, so an LLM round-trip or a `manual` rule parked for a human can never
/// close the connection it is an answer for.
///
/// Fifteen minutes is the wait between one command finishing and the next one starting. hg sets
/// no keep-alive interval of its own; a client that has taken fifteen minutes to issue its next
/// command has gone away.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// Each admitted connection may buffer a request body of up to [`MAX_REQUEST_BODY_BYTES`] and
/// build a bundle of whatever size the handler describes, so the cap is what turns that
/// per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// The wire protocol here *is* HTTP, so the protocol's own vocabulary for "come back later" is a
/// `503` with `Retry-After`, which hg reports as an HTTP error naming the status rather than as
/// an unexplained connection reset.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// Shared per-request context.
struct RequestContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<MercurialProtocol>,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
}

/// Mercurial HTTP server
pub struct MercurialServer;

impl MercurialServer {
    /// Spawn the Mercurial server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        console_info!(status_tx, "Mercurial server listening on {}", local_addr);

        let protocol = Arc::new(MercurialProtocol::new());

        // Spawn server loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Mercurial",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        crate::logging::emit::Log::to(&status_tx).info(format!(
                            "Mercurial connection {} from {}",
                            connection_id, remote_addr
                        ));

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr,
                            local_addr: local_addr_conn,
                            bytes_sent: 0,
                            bytes_received: 0,
                            packets_sent: 0,
                            packets_received: 0,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();

                        // Spawn a task to handle this connection
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early
                                // releases the slot while the peer is still here, which
                                // silently un-caps the server.
                                let _permit = permit;

                                // First-byte bound, before hyper sees the socket. hyper owns
                                // every read once `serve_connection` starts and keeps polling
                                // for frames *while a request is being answered*, so a deadline
                                // on reads would fire in the middle of an LLM round-trip.
                                // `peek` waits for data without consuming it, so the request
                                // line is still there for hyper afterwards.
                                match tokio::time::timeout(
                                    FIRST_BYTE_READ_TIMEOUT,
                                    stream.peek(&mut [0u8; 1]),
                                )
                                .await
                                {
                                    Ok(Ok(0)) | Ok(Err(_)) => {
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                    Ok(Ok(_)) => {}
                                    Err(_) => {
                                        debug!(
                                            "Mercurial peer {} sent nothing for {}s; closing \
                                             before the request line",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                }

                                let io = TokioIo::new(stream);

                                // Clone for service closure
                                let status_for_service = status_tx_clone.clone();
                                let app_state_for_service = app_state_clone.clone();

                                // Tracks whether this connection is answering anything. A
                                // command waiting on the model, or parked for a human at the
                                // dashboard, holds the count above zero, so the idle watchdog
                                // below cannot close the connection the answer belongs to
                                // however long it takes — only genuine silence counts.
                                let activity = Arc::new(
                                    crate::server::accept_bounded::ConnectionActivity::new(),
                                );
                                let activity_for_service = Arc::clone(&activity);

                                // Create a service that handles Mercurial HTTP requests with LLM
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let ctx = RequestContext {
                                        llm_client: llm_client_clone.clone(),
                                        app_state: app_state_for_service.clone(),
                                        status_tx: status_for_service.clone(),
                                        protocol: protocol_clone.clone(),
                                        connection_id,
                                        server_id,
                                        remote_addr,
                                    };
                                    let activity = Arc::clone(&activity_for_service);
                                    async move {
                                        let _busy = activity.busy();
                                        handle_mercurial_request(req, ctx).await
                                    }
                                });

                                // Serve HTTP/1 on this connection
                                let conn = http1::Builder::new().serve_connection(io, service);
                                tokio::pin!(conn);
                                tokio::select! {
                                    result = &mut conn => {
                                        if let Err(err) = result {
                                            error!(
                                                "Error serving Mercurial connection: {:?}",
                                                err
                                            );
                                        }
                                    }
                                    _ = crate::server::accept_bounded::watch_idle(
                                        Arc::clone(&activity),
                                        IDLE_BETWEEN_REQUESTS_TIMEOUT,
                                    ) => {
                                        debug!(
                                            "Mercurial connection {} idle for {}s; closing",
                                            connection_id,
                                            IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                // Mark connection as closed
                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_tx_clone)
                                    .info(format!("Mercurial connection {} closed", connection_id));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::to(&status_tx)
                            .error(format!("Failed to accept Mercurial connection: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Handle a Mercurial HTTP request
async fn handle_mercurial_request(
    req: Request<Incoming>,
    ctx: RequestContext,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();

    crate::logging::emit::Log::to(&ctx.status_tx)
        .debug(format!("Mercurial request: {} {}?{}", method, path, query));

    // Parse query parameters
    let params: HashMap<String, String> = parse_query_params(&query);
    let cmd = params.get("cmd").map(|s| s.as_str()).unwrap_or("");

    // Parse repository name from path (e.g., /repo-name or /)
    let repo = parse_repo_name(&path);

    // Track repository access
    track_repo_access(&ctx.app_state, ctx.server_id, ctx.connection_id, &repo).await;

    match cmd {
        "batch" => {
            let cmds = params.get("cmds").map(|s| s.as_str()).unwrap_or("");
            Ok(match handle_batch(&ctx, &repo, cmds).await {
                Ok(body) => text_response(&ctx, &body).await,
                Err(response) => response,
            })
        }
        cmd if BATCHABLE.contains(&cmd) => Ok(match run_command(&ctx, &repo, cmd, &params).await {
            Ok(body) => text_response(&ctx, &body).await,
            Err(response) => response,
        }),
        "getbundle" => {
            // hg sends getbundle as a GET with the arguments in the query string, or as a
            // POST when they are too long for a URL. Accept both.
            // Bounded read: `Limited` errors as soon as the cap is passed rather than after
            // buffering the whole thing, so an oversized body costs at most the cap.
            let limited = http_body_util::Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES);
            let body_len = match limited.collect().await {
                Ok(collected) => collected.to_bytes().len(),
                Err(e) => {
                    console_error!(
                        ctx.status_tx,
                        "Mercurial refusing request body ({}); limit is {} bytes",
                        e,
                        MAX_REQUEST_BODY_BYTES
                    );
                    return Ok(build_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body is too large",
                    ));
                }
            };
            if body_len > 0 {
                record_bytes_received(&ctx, body_len).await;
                trace!("Mercurial getbundle request body ({} bytes)", body_len);
            }
            Ok(handle_getbundle(&ctx, &repo, &params).await)
        }
        "unbundle" | "pushkey" => Ok(build_error_response(
            StatusCode::FORBIDDEN,
            "Push is not supported: this server serves clone/pull only",
        )),
        "" if method == Method::GET => Ok(build_text_response(
            StatusCode::OK,
            "Mercurial HTTP Server - NetGet\nSpecify ?cmd=capabilities to see server capabilities",
        )),
        other => {
            debug!("Mercurial: unimplemented command {:?}", other);
            Ok(build_error_response(
                StatusCode::NOT_FOUND,
                &format!("Unknown or unimplemented command: {}", other),
            ))
        }
    }
}

/// Parse repository name from URL path
fn parse_repo_name(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Parse query parameters from query string
fn parse_query_params(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                // Form encoding: hg's `urlencode` writes a space as `+`, and the node lists in
                // `heads`, `common` and `nodes` are space-separated.
                (Some(key), Some(value)) => Some((
                    key.to_string(),
                    urlencoding::decode(&value.replace('+', " "))
                        .ok()?
                        .to_string(),
                )),
                _ => None,
            }
        })
        .collect()
}

/// What answered a command: the command's own action, or a whole-repository description.
enum Answer {
    /// The command-specific action's data (`hg_heads`, `hg_branchmap`, ...).
    Command(Value),
    /// An `hg_repository` action, with the history already built and validated.
    Repository(Repository),
}

/// A batchable command's answer: the response body, or the complete error response.
type CommandResult = Result<String, Response<Full<Bytes>>>;

/// The commands `batch` may carry, and that are answered with a plain body.
const BATCHABLE: &[&str] = &[
    "capabilities",
    "heads",
    "branchmap",
    "listkeys",
    "known",
    "lookup",
];

/// Most commands one `batch` request may carry. hg 7.x batches the two discovery commands
/// (`heads`, `known`); each sub-command is one event, so the cap bounds model calls per request.
pub const MAX_BATCH_COMMANDS: usize = 16;

/// Answer one of the [`BATCHABLE`] commands from its arguments.
async fn run_command(
    ctx: &RequestContext,
    repo: &str,
    cmd: &str,
    args: &HashMap<String, String>,
) -> CommandResult {
    let arg = |name: &str| args.get(name).map(String::as_str).unwrap_or("");
    match cmd {
        "capabilities" => handle_capabilities(ctx, repo).await,
        "heads" => handle_heads(ctx, repo).await,
        "branchmap" => handle_branchmap(ctx, repo).await,
        "listkeys" => {
            let namespace = args
                .get("namespace")
                .map(String::as_str)
                .unwrap_or("bookmarks");
            handle_listkeys(ctx, repo, namespace).await
        }
        "known" => handle_known(ctx, repo, arg("nodes")).await,
        "lookup" => handle_lookup(ctx, repo, arg("key")).await,
        other => Err(build_error_response(
            StatusCode::NOT_FOUND,
            &format!("Unknown or unimplemented command: {}", other),
        )),
    }
}

/// `?cmd=batch&cmds=<op> <k>=<v>,...;<op> ...` - several commands in one request, answered
/// with their bodies joined by `;`, each escaped (`wireprototypes.escapebatcharg`).
///
/// hg 7.x batches whenever it has more than one batchable command to send, **whether or not
/// the server advertises `batch`** (`wireprotov1peer.peerexecutor.sendcommands`), so a clone's
/// discovery always arrives here as `heads ;known nodes=`.
async fn handle_batch(ctx: &RequestContext, repo: &str, cmds: &str) -> CommandResult {
    let mut parsed: Vec<(String, HashMap<String, String>)> = Vec::new();
    for spec in cmds.split(';') {
        let (op, rest) = spec.split_once(' ').unwrap_or((spec, ""));
        let op = op.trim();
        if op.is_empty() {
            continue;
        }
        if !BATCHABLE.contains(&op) {
            warn!("Mercurial batch decision=refused_bad_request command={op:?}");
            return Err(build_hg_error_response(
                "batch carries a command this server cannot batch",
            ));
        }
        let mut args = HashMap::new();
        for pair in rest.split(',').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            args.insert(unescape_batch_arg(k), unescape_batch_arg(v));
        }
        parsed.push((op.to_string(), args));
    }
    if parsed.is_empty() || parsed.len() > MAX_BATCH_COMMANDS {
        warn!(
            "Mercurial batch decision=refused_bad_request commands={}",
            parsed.len()
        );
        return Err(build_hg_error_response(
            "batch must carry between one and sixteen commands",
        ));
    }

    let mut answers = Vec::with_capacity(parsed.len());
    for (op, args) in &parsed {
        answers.push(escape_batch_arg(&run_command(ctx, repo, op, args).await?));
    }
    Ok(answers.join(";"))
}

/// `wireprototypes.escapebatcharg`.
fn escape_batch_arg(text: &str) -> String {
    text.replace(':', "::")
        .replace(',', ":c")
        .replace(';', ":s")
        .replace('=', ":e")
}

/// `wireprototypes.unescapebatcharg`, in one pass so `::e` reads as `:` then `e`.
fn unescape_batch_arg(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != ':' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(':'),
            Some('c') => out.push(','),
            Some('s') => out.push(';'),
            Some('e') => out.push('='),
            Some(other) => {
                out.push(':');
                out.push(other);
            }
            None => out.push(':'),
        }
    }
    out
}

/// Handle ?cmd=capabilities
async fn handle_capabilities(ctx: &RequestContext, repo: &str) -> CommandResult {
    let event = Event::new(
        &HG_CAPABILITIES_EVENT,
        serde_json::json!({
            "repository": repo,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    let capabilities = match resolve(ctx, &event, "hg_capabilities_response").await {
        Ok(Answer::Command(data)) => {
            let requested: Vec<String> = data
                .get("capabilities")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            actions::sanitize_capabilities(&requested)
        }
        Ok(Answer::Repository(_)) => actions::supported_capabilities(),
        Err(response) => return Err(response),
    };

    let body = capabilities.join("\n");
    let _ = ctx.status_tx.send(format!(
        "→ hg capabilities for '{}': {}",
        repo,
        capabilities.join(" ")
    ));
    Ok(body)
}

/// Handle ?cmd=heads
async fn handle_heads(ctx: &RequestContext, repo: &str) -> CommandResult {
    let event = Event::new(
        &HG_HEADS_EVENT,
        serde_json::json!({
            "repository": repo,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    let heads: Vec<String> = match resolve(ctx, &event, "hg_heads_response").await {
        Ok(Answer::Command(data)) => node_list(data.get("heads")),
        Ok(Answer::Repository(history)) => history.heads().iter().map(hex).collect(),
        Err(response) => return Err(response),
    };
    let heads = if heads.is_empty() {
        NULL_NODE.to_string()
    } else {
        heads.join(" ")
    };

    let _ = ctx
        .status_tx
        .send(format!("→ hg heads for '{}': {}", repo, heads));
    // The client strips the last byte before decoding (`decodelist(d[:-1])`), so the newline
    // is part of the format, not decoration.
    Ok(format!("{heads}\n"))
}

/// Handle ?cmd=branchmap
async fn handle_branchmap(ctx: &RequestContext, repo: &str) -> CommandResult {
    let event = Event::new(
        &HG_BRANCHMAP_EVENT,
        serde_json::json!({
            "repository": repo,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    // Format: one line per branch, "<url-quoted branch> <node> <node> ...".
    let mut body = String::new();
    match resolve(ctx, &event, "hg_branchmap_response").await {
        Ok(Answer::Command(data)) => {
            if let Some(branches) = data.get("branches").and_then(|v| v.as_object()) {
                for (branch, nodes) in branches {
                    let nodes = node_list(Some(nodes));
                    if nodes.is_empty() {
                        continue;
                    }
                    body.push_str(&format!(
                        "{} {}\n",
                        urlencoding::encode(branch),
                        nodes.join(" ")
                    ));
                }
            }
        }
        Ok(Answer::Repository(history)) => {
            for (branch, heads) in history.branch_heads() {
                let heads: Vec<String> = heads.iter().map(hex).collect();
                body.push_str(&format!(
                    "{} {}\n",
                    urlencoding::encode(&branch),
                    heads.join(" ")
                ));
            }
        }
        Err(response) => return Err(response),
    }

    Ok(body)
}

/// Handle ?cmd=listkeys&namespace=...
async fn handle_listkeys(ctx: &RequestContext, repo: &str, namespace: &str) -> CommandResult {
    let event = Event::new(
        &HG_LISTKEYS_EVENT,
        serde_json::json!({
            "repository": repo,
            "namespace": namespace,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    // Format: "<key>\t<value>\n" per entry.
    let mut body = String::new();
    match resolve(ctx, &event, "hg_listkeys_response").await {
        Ok(Answer::Command(data)) => {
            if let Some(keys) = data.get("keys").and_then(|v| v.as_object()) {
                for (key, value) in keys {
                    let value = match value.as_str() {
                        Some(v) => v.to_string(),
                        None => value.to_string(),
                    };
                    body.push_str(&format!("{}\t{}\n", key, value));
                }
            }
        }
        // A described history has no bookmarks, and every changeset in it is public: a
        // publishing server says exactly that.
        Ok(Answer::Repository(_)) => {
            if namespace == "phases" {
                body.push_str("publishing\tTrue\n");
            }
        }
        Err(response) => return Err(response),
    }

    Ok(body)
}

/// Handle ?cmd=known&nodes=... - one `0`/`1` per node, in the order asked.
async fn handle_known(ctx: &RequestContext, repo: &str, nodes: &str) -> CommandResult {
    let asked: Vec<&str> = nodes.split_whitespace().collect();
    if asked.is_empty() {
        // Every clone into an empty repository asks this. There is nothing to decide, so
        // nobody is asked.
        return Ok(String::new());
    }

    let event = Event::new(
        &HG_KNOWN_EVENT,
        serde_json::json!({
            "repository": repo,
            "nodes": nodes,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    let history = match resolve(ctx, &event, REPOSITORY_RESPONSE).await {
        Ok(Answer::Repository(history)) => history,
        // `resolve` checks the repository answer before the command one, and for this command
        // they are the same name, so a command answer cannot arrive; fail closed if it does.
        Ok(Answer::Command(_)) => {
            return Err(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                WireFailure::Unavailable.text(),
            ))
        }
        Err(response) => return Err(response),
    };
    let body: String = asked
        .iter()
        .map(|n| match parse_node(n) {
            Some(node) if history.contains(&node) => '1',
            _ => '0',
        })
        .collect();
    Ok(body)
}

/// Handle ?cmd=lookup&key=... - `1 <node>\n` when the symbol resolves, `0 <reason>\n` when not.
async fn handle_lookup(ctx: &RequestContext, repo: &str, key: &str) -> CommandResult {
    let event = Event::new(
        &HG_LOOKUP_EVENT,
        serde_json::json!({
            "repository": repo,
            "key": key,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    let history = match resolve(ctx, &event, REPOSITORY_RESPONSE).await {
        Ok(Answer::Repository(history)) => history,
        // `resolve` checks the repository answer before the command one, and for this command
        // they are the same name, so a command answer cannot arrive; fail closed if it does.
        Ok(Answer::Command(_)) => {
            return Err(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                WireFailure::Unavailable.text(),
            ))
        }
        Err(response) => return Err(response),
    };
    let body = match history.lookup(key) {
        Some(node) => format!("1 {}\n", hex(&node)),
        None => format!("0 unknown revision '{}'\n", key.escape_default()),
    };
    let _ = ctx.status_tx.send(format!(
        "→ hg lookup '{}' in '{}': {}",
        key,
        repo,
        body.trim_end()
    ));
    Ok(body)
}

/// Handle ?cmd=getbundle
async fn handle_getbundle(
    ctx: &RequestContext,
    repo: &str,
    params: &HashMap<String, String>,
) -> Response<Full<Bytes>> {
    let heads_arg = params.get("heads").cloned().unwrap_or_default();
    let common_arg = params.get("common").cloned().unwrap_or_default();
    let event = Event::new(
        &HG_GETBUNDLE_EVENT,
        serde_json::json!({
            "repository": repo,
            "heads": heads_arg,
            "common": common_arg,
            "client_ip": ctx.remote_addr.ip().to_string(),
        }),
    );

    let changegroup = match resolve(ctx, &event, "hg_bundle_response").await {
        Ok(Answer::Command(_)) => empty_changegroup(),
        Ok(Answer::Repository(history)) => {
            let heads = match parse_node_args(&heads_arg) {
                Some(nodes) => nodes,
                None => {
                    warn!("Mercurial getbundle decision=refused_bad_request heads={heads_arg:?}");
                    return build_hg_error_response("malformed heads argument");
                }
            };
            let common = parse_node_args(&common_arg).unwrap_or_default();
            match history.changegroup(&heads, &common) {
                Ok(cg) => cg,
                Err(ChangegroupError::UnknownHead(node)) => {
                    warn!("Mercurial getbundle decision=refused_unknown_head head={node}");
                    return build_hg_error_response("requested head is not in this repository");
                }
            }
        }
        Err(response) => return response,
    };

    // Content-Type application/mercurial-0.1 means the client zlib-decompresses a
    // compressible command's body (`httppeer.parsev1commandresponse`), and getbundle is one.
    let body = match zlib(&changegroup) {
        Ok(body) => body,
        Err(e) => {
            error!("Mercurial getbundle decision=fail_closed_compression error={e}");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                WireFailure::Unavailable.text(),
            );
        }
    };

    debug!(
        "Mercurial getbundle for '{}': changegroup of {} bytes ({} compressed)",
        repo,
        changegroup.len(),
        body.len()
    );
    let _ = ctx.status_tx.send(format!(
        "→ hg bundle for '{}': changegroup of {} bytes",
        repo,
        changegroup.len()
    ));

    record_bytes_sent(ctx, body.len()).await;
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/mercurial-0.1")
        .body(Full::new(Bytes::from(body)))
        .expect("static header values are valid")
}

/// A space-separated node list from a request argument; `None` when an entry is not a node.
fn parse_node_args(arg: &str) -> Option<Vec<changegroup::Node>> {
    arg.split_whitespace().map(parse_node).collect()
}

fn zlib(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Raise the event and pick out the protocol result this command needs.
///
/// `hg_repository` and `hg_error` are honoured for every command; anything else (no action, or
/// an action for a different command) becomes a 500 with a log line naming the event.
///
/// Four outcomes are kept distinguishable in the log by a `decision=` tag: the model
/// refused (`model_reject`), the model answered nothing usable (`fail_closed_no_action`), the
/// model described a history the server cannot build (`fail_closed_invalid_repository`), or
/// the call itself failed (`fail_closed_llm_error` / `fail_closed_overloaded`). The peer
/// is told only a category — 503 + `Retry-After` when the backend is saturated, 500
/// otherwise, an `application/hg-error` for a refused history — never the error text.
async fn resolve(
    ctx: &RequestContext,
    event: &Event,
    expected: &str,
) -> Result<Answer, Response<Full<Bytes>>> {
    let execution_result = match call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        Some(ctx.connection_id),
        event,
        ctx.protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            // The peer gets a category, the log gets the error. Nothing derived from `e`
            // reaches the socket: `WireFailure::text` is a `&'static str` by design.
            let failure = WireFailure::classify(&e);
            let decision = if failure.is_overloaded() {
                "fail_closed_overloaded"
            } else {
                "fail_closed_llm_error"
            };
            error!(
                "Mercurial {} decision={} error={:#}",
                event.id(),
                decision,
                e
            );
            let _ = ctx.status_tx.send(format!(
                "✗ Mercurial {} decision={}: {}",
                event.id(),
                decision,
                e
            ));
            // Overload is transient; 503 + Retry-After tells hg to back off rather than
            // record a permanent fault, which a bare 500 would.
            return Err(if failure.is_overloaded() {
                build_retryable_error_response(failure.text())
            } else {
                build_error_response(StatusCode::INTERNAL_SERVER_ERROR, failure.text())
            });
        }
    };

    for message in &execution_result.messages {
        console_info!(ctx.status_tx, "{}", message);
    }

    for result in execution_result.protocol_results {
        match result {
            ActionResult::Custom { name, data } if name == REPOSITORY_RESPONSE => {
                return match Repository::from_description(&data) {
                    Ok(history) => Ok(Answer::Repository(history)),
                    Err(e) => {
                        // What was wrong names a commit or a path from the description; it is
                        // for the operator. The client is told only that the history was
                        // refused.
                        warn!(
                            "Mercurial {} decision=fail_closed_invalid_repository reason={}",
                            event.id(),
                            e
                        );
                        let _ = ctx.status_tx.send(format!(
                            "✗ Mercurial {} decision=fail_closed_invalid_repository: {}",
                            event.id(),
                            e
                        ));
                        Err(build_hg_error_response(
                            "the server could not build this repository's history",
                        ))
                    }
                };
            }
            ActionResult::Custom { name, data } if name == expected => {
                return Ok(Answer::Command(data))
            }
            ActionResult::Custom { name, data } if name == "hg_error_response" => {
                let message = data
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Error");
                let code = data.get("code").and_then(|v| v.as_u64()).unwrap_or(500) as u16;
                // The model answered, and its answer was a refusal. Distinct in the log from
                // both "answered nothing" and "the call errored".
                warn!(
                    "Mercurial {} decision=model_reject code={}",
                    event.id(),
                    code
                );
                return Err(build_error_response(
                    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    message,
                ));
            }
            _ => {}
        }
    }

    // The call succeeded and the model said nothing usable — a third case, kept separate
    // from `decision=model_reject` and `decision=fail_closed_llm_error`.
    warn!(
        "Mercurial {} decision=fail_closed_no_action expected={}",
        event.id(),
        expected
    );
    let _ = ctx.status_tx.send(format!(
        "✗ Mercurial {} decision=fail_closed_no_action (expected {})",
        event.id(),
        expected
    ));
    Err(build_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        WireFailure::Unavailable.text(),
    ))
}

/// Extract a list of node IDs from an action field, accepting an array or a
/// whitespace-separated string, and dropping anything that is not a 40-character hex node.
fn node_list(value: Option<&Value>) -> Vec<String> {
    let mut nodes = Vec::new();
    match value {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(node) = item.as_str() {
                    push_node(&mut nodes, node);
                }
            }
        }
        Some(Value::String(text)) => {
            for node in text.split_whitespace() {
                push_node(&mut nodes, node);
            }
        }
        _ => {}
    }
    nodes
}

fn push_node(nodes: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim();
    if candidate.len() == 40 && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        nodes.push(candidate.to_ascii_lowercase());
    } else {
        // A model that answers "abc123..." would otherwise put an unparseable node on the
        // wire and the client would fail with an opaque error.
        warn!(
            "Mercurial: dropping {:?}, which is not a 40-character hex node ID",
            candidate
        );
    }
}

async fn text_response(ctx: &RequestContext, body: &str) -> Response<Full<Bytes>> {
    record_bytes_sent(ctx, body.len()).await;
    build_text_response(StatusCode::OK, body)
}

/// Track repository access in connection state
async fn track_repo_access(
    app_state: &Arc<AppState>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    repo_name: &str,
) {
    app_state
        .with_server_mut(server_id, |server| {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    let mut recent_repos: Vec<String> = obj
                        .get("recent_repos")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if !recent_repos.contains(&repo_name.to_string()) {
                        recent_repos.push(repo_name.to_string());
                        // Keep only last 10 repos
                        if recent_repos.len() > 10 {
                            recent_repos.remove(0);
                        }
                    }
                    obj.insert(
                        "recent_repos".to_string(),
                        serde_json::to_value(&recent_repos).unwrap_or(serde_json::json!([])),
                    );
                }
            }
        })
        .await;
}

async fn record_bytes_sent(ctx: &RequestContext, len: usize) {
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            None,
            Some(len as u64),
            None,
            Some(1),
        )
        .await;
}

async fn record_bytes_received(ctx: &RequestContext, len: usize) {
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            Some(len as u64),
            None,
            Some(1),
            None,
        )
        .await;
}

/// A Mercurial protocol error: `application/hg-error`, which `httppeer` raises as
/// `OutOfBandError`, so `hg` prints `abort: remote error:` and the message. Served with 200, as
/// hgweb serves it, because a non-2xx status is reported as a bare HTTP error before the
/// content type is ever read.
fn build_hg_error_response(message: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/hg-error")
        .body(Full::new(Bytes::from(format!("{message}\n"))))
        .expect("static header values are valid")
}

/// Build an HTTP error response
fn build_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(format!("Error: {}\n", message))))
        .expect("static header values are valid")
}

/// A retryable failure: 503 with `Retry-After`, so hg backs off instead of treating the
/// server as permanently broken. Same shape as `src/server/http_common/handler.rs`.
fn build_retryable_error_response(message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "text/plain")
        .header(hyper::header::RETRY_AFTER, "1")
        .body(Full::new(Bytes::from(format!("Error: {}\n", message))))
        .expect("static header values are valid")
}

/// Build a text response
fn build_text_response(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/mercurial-0.1")
        .body(Full::new(Bytes::from(text.to_string())))
        .expect("static header values are valid")
}
