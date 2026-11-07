//! Gopher (RFC 1436) client.
//!
//! # One connection per request, deliberately
//!
//! Gopher has no session. The client sends one selector line, the server answers and
//! **closes** — the close is the framing, because the reply carries no length and no content
//! type. So there is no persistent socket for this client to hold, and "browsing" means
//! opening a new connection per item.
//!
//! That is exactly what happens here: [`GopherClient::connect_with_llm_actions`] opens one
//! connection to prove the hole is reachable and to obtain the local address the `Client`
//! trait must return, then closes it. Every fetch afterwards — the model's, or one injected
//! from the dashboard — opens its own connection to whatever host and port the action names,
//! which is what lets a menu item point at a different server and still be followable.
//!
//! # Menu or document: the requesting item's type decides
//!
//! Nothing in a Gopher reply says which it is. The item type in the *request* is the only
//! signal, so `send_gopher_request` carries an `item_type` and this module reads the reply
//! according to it: `1` and `7` are parsed as menus, everything else as a document. There is
//! exactly one exception, and it is not a heuristic about content: a reply whose first line
//! is a **type-3 item** is reported as an error whatever was asked for, because type 3 is the
//! only error channel the protocol has and a server uses it to refuse any request.
//!
//! When the guess is wrong the reply is not thrown away. A menu request whose reply contains
//! no parseable menu line at all is reported as `gopher_document_received` with
//! `requested_item_type` still set, so the model can see the mismatch; a menu request whose
//! reply is *mostly* menu lines keeps the odd ones in `malformed_lines`. The reverse is not
//! attempted — a document may legitimately be full of tabs, so a document reply is never
//! re-read as a menu.
//!
//! # The follow-up chain
//!
//! Browsing is iterative by nature: fetch a menu, pick an item, fetch that, repeat. A
//! follow-up fetch that raised no event would give the model exactly one turn and then go
//! deaf, which is the `elasticsearch`/`http2` defect the root `CLAUDE.md` catalogues. So every
//! fetch raises its event and asks the model again, and the recursion is bounded by
//! [`MAX_FOLLOWUP_DEPTH`] rather than by silence. The recursive call is boxed (an `async fn`
//! that awaits itself has an infinitely-sized future) and the boxed type names `+ Send`
//! explicitly, because it is awaited inside a `tokio::spawn`.

pub mod actions;

pub use actions::GopherClientProtocol;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

use actions::{
    GOPHER_DOCUMENT_RECEIVED_EVENT, GOPHER_ERROR_RECEIVED_EVENT, GOPHER_FETCH_RESULT,
    GOPHER_MENU_RECEIVED_EVENT,
};

/// How many model round-trips one automatic browse may chain.
///
/// A menu whose items point back at each other is an ordinary shape in gopherspace, so the
/// chain has to be bounded by something. Silence is the wrong bound — that is the defect this
/// module exists not to have — so the bound is a depth, and hitting it is logged loudly.
pub const MAX_FOLLOWUP_DEPTH: usize = 6;

/// Largest reply this client will hold. Gopher sends no length, so without a cap any server
/// can make the client allocate until it dies.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Menu items kept from one reply. A menu longer than this is a server misbehaving.
pub const MAX_MENU_ITEMS: usize = 4096;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The default port when a remote address names no port. RFC 1436 §2.
pub const DEFAULT_GOPHER_PORT: u16 = 70;

// ---------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------

/// One parsed menu line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GopherMenuItem {
    /// RFC 1436 item type: the first character of the line.
    pub item_type: char,
    /// The text a user sees.
    pub display: String,
    /// What to send back to fetch this item.
    pub selector: String,
    /// Where to fetch it.
    pub host: String,
    /// Port to fetch it on.
    pub port: u16,
}

/// What a reply turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GopherReply {
    /// A directory listing.
    Menu {
        items: Vec<GopherMenuItem>,
        /// Lines that are not well-formed menu lines, kept verbatim rather than dropped.
        malformed_lines: Vec<String>,
    },
    /// A text document, with the terminator removed and leading dots un-doubled.
    Document { text: String },
    /// A type-3 item.
    Error { message: String },
}

/// What an RFC 1436 item type character means, for the model's benefit.
///
/// The client recognises every type the RFC and common practice define, unlike the server,
/// which deliberately emits only a closed set. A client has no choice: it must describe
/// whatever it is handed.
pub fn item_type_name(item_type: char) -> &'static str {
    match item_type {
        '0' => "text file",
        '1' => "directory (menu)",
        '2' => "CSO phone-book server",
        '3' => "error",
        '4' => "BinHex file",
        '5' => "DOS binary archive",
        '6' => "uuencoded file",
        '7' => "search server",
        '8' => "telnet session",
        '9' => "binary file",
        '+' => "redundant server",
        'T' => "tn3270 session",
        'g' => "GIF image",
        'I' => "image",
        'h' => "HTML",
        'i' => "informational text (not a link)",
        'd' => "document",
        's' => "sound",
        _ => "unrecognised item type",
    }
}

/// Split a reply into body lines: CRLF or LF, stopping at the lone `.` terminator.
///
/// Returns the lines and whether the terminator was actually seen. A server that just closes
/// without one is tolerated — the FIN is the real end of the transfer — but the difference
/// matters for the trailing blank line a final newline would otherwise leave behind.
fn body_lines(raw: &str) -> (Vec<&str>, bool) {
    let mut out: Vec<&str> = Vec::new();
    let mut terminated = false;
    for line in raw.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line == "." {
            terminated = true;
            break;
        }
        out.push(line);
    }
    if !terminated {
        // The final `\n` of the last real line yields one empty trailing element; that is
        // framing, not content. Anything before it is the author's own blank line.
        if out.last() == Some(&"") {
            out.pop();
        }
    }
    (out, terminated)
}

/// Undo the leading-dot doubling ("periodating") RFC 1436 requires of the *sender*.
///
/// The server doubles a leading period so a line of its own that begins with one cannot be
/// mistaken for the terminator; undoing it is the client's job and nothing else in the line
/// is escaped.
fn unescape_document_line(line: &str) -> &str {
    line.strip_prefix('.').unwrap_or(line)
}

/// Parse one menu line: `<type><display>\t<selector>\t<host>\t<port>`.
fn parse_menu_line(line: &str) -> Option<GopherMenuItem> {
    let mut chars = line.chars();
    let item_type = chars.next()?;
    let rest = chars.as_str();

    let fields: Vec<&str> = rest.split('\t').collect();
    if fields.len() < 4 {
        return None;
    }
    // A display string may not contain a tab (the server sanitises it), so field 0 is the
    // display and the last three named fields are selector/host/port. Anything beyond four
    // fields is a Gopher+ attribute suffix, which this client ignores.
    let port = fields[3].trim().parse::<u16>().ok()?;

    Some(GopherMenuItem {
        item_type,
        display: fields[0].to_string(),
        selector: fields[1].to_string(),
        host: fields[2].to_string(),
        port,
    })
}

/// Read a reply according to the item type that was asked for.
///
/// `requested_item_type` is the whole point: the reply itself carries no content type, so the
/// request is the only thing that says what it is. See the module docs for what happens when
/// that is wrong.
pub fn parse_gopher_reply(raw: &str, requested_item_type: char) -> GopherReply {
    let (lines, _terminated) = body_lines(raw);

    // A type-3 item can answer any request, so it is checked before anything else. The test
    // is structural (a type-3 *item*, with the tab-separated fields a menu line has), not a
    // guess about content: a document that merely begins with the digit 3 has no tab there.
    if let Some(first) = lines.iter().find(|l| !l.is_empty()) {
        if first.starts_with('3') && first.contains('\t') {
            let message = first[1..].split('\t').next().unwrap_or("").to_string();
            return GopherReply::Error { message };
        }
    }

    let wants_menu = requested_item_type == '1' || requested_item_type == '7';
    if wants_menu {
        let mut items = Vec::new();
        let mut malformed_lines = Vec::new();
        for line in &lines {
            if line.is_empty() {
                continue;
            }
            match parse_menu_line(line) {
                Some(item) if items.len() < MAX_MENU_ITEMS => items.push(item),
                Some(_) => break,
                None => malformed_lines.push((*line).to_string()),
            }
        }
        if !items.is_empty() {
            return GopherReply::Menu {
                items,
                malformed_lines,
            };
        }
        // The guess was wrong and nothing at all parsed. Report what arrived rather than an
        // empty menu, and leave `requested_item_type` on the event so the mismatch is visible.
    }

    let text = lines
        .iter()
        .map(|l| unescape_document_line(l))
        .collect::<Vec<_>>()
        .join("\n");
    GopherReply::Document { text }
}

/// Build the request line. A query makes it a type-7 search.
pub fn request_line(selector: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{selector}\t{q}\r\n"),
        None => format!("{selector}\r\n"),
    }
}

/// Split `host:port`, defaulting the port to 70.
///
/// Tolerates a bare IPv6 literal in brackets, which is the only form that can carry a port
/// unambiguously.
fn split_remote_addr(remote_addr: &str) -> (String, u16) {
    if let Some(rest) = remote_addr.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(DEFAULT_GOPHER_PORT);
            return (host.to_string(), port);
        }
    }
    match remote_addr.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            // A bare IPv6 literal has colons but no port.
            Err(_) => (remote_addr.to_string(), DEFAULT_GOPHER_PORT),
        },
        None => (remote_addr.to_string(), DEFAULT_GOPHER_PORT),
    }
}

/// Format a host and port for `TcpStream::connect`. A bare IPv6 literal needs brackets.
fn dial_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ---------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------

/// Everything one browsing session needs, so the recursive chain can be handed a single
/// `Arc` instead of a dozen arguments.
struct Session {
    protocol: Arc<GopherClientProtocol>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    /// Where a fetch goes when the action names no host/port.
    default_host: String,
    default_port: u16,
    instruction: String,
    /// Set once the session is over, so a fetch already queued does not put more bytes on
    /// the wire after the operator hung up.
    ended: Arc<AtomicBool>,
}

/// One fetch, resolved from an action.
struct FetchRequest {
    host: String,
    port: u16,
    selector: String,
    item_type: char,
    query: Option<String>,
}

/// What one fetch produced, before the model is told about it.
struct FetchOutcome {
    reply: GopherReply,
    request_bytes: usize,
    reply_bytes: usize,
    truncated: bool,
}

/// Gopher client that browses a gopher hole under LLM control.
pub struct GopherClient;

impl GopherClient {
    /// Open a Gopher client.
    ///
    /// The connection made here is a reachability probe and nothing more: Gopher expects a
    /// selector immediately and we do not know one yet, and every request needs its own
    /// connection anyway. Failing here rather than at the first fetch is what makes a
    /// mistyped address show up as a failed `open_client` instead of as a silent client that
    /// never does anything.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        let (default_host, default_port) = split_remote_addr(&remote_addr);
        let dial = dial_addr(&default_host, default_port);

        let probe = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&dial))
            .await
            .map_err(|_| anyhow!("timed out connecting to Gopher server at {dial}"))?
            .with_context(|| format!("Failed to connect to Gopher server at {dial}"))?;
        let local_addr = probe.local_addr()?;
        let remote_sock_addr = probe.peer_addr()?;
        // Nothing was sent, so the server sees a client that hung up before asking for
        // anything and logs exactly that.
        drop(probe);

        info!(
            "Gopher client {} reached {} (local: {}); every request opens its own connection",
            client_id, remote_sock_addr, local_addr
        );

        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Gopher client {} ready ({})",
            client_id, dial
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let session = Arc::new(Session {
            protocol: Arc::new(GopherClientProtocol::new()),
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            client_id,
            default_host,
            default_port,
            instruction: app_state
                .get_instruction_for_client(client_id)
                .await
                .unwrap_or_default(),
            ended: Arc::new(AtomicBool::new(false)),
        });

        // Registered before anything that can call the model. A dashboard-created client gets
        // a `*` -> manual rule, so the first event this client raises parks for as long as the
        // operator takes to answer it; without the handle in place first, `[ send ]` would be
        // greyed out for exactly that window.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_session = session.clone();
        let command_task = tokio::spawn(async move {
            Session::command_loop(command_session, command_rx).await;
        });
        app_state
            .register_client_task(client_id, command_task)
            .await;

        let browse_session = session.clone();
        let browse_task = tokio::spawn(async move {
            Session::open_browse(browse_session).await;
        });
        app_state.register_client_task(client_id, browse_task).await;

        Ok(local_addr)
    }
}

impl Session {
    /// The opening turn: ask the model what to fetch first, then run whatever it says.
    ///
    /// There is no `gopher_connected` event, because Gopher gives the client nothing to
    /// report on connect — no banner, no capabilities, no session. This is the
    /// initial-instruction call (`event: None`), which is also why it is not routed through
    /// `event_handlers`: there is no event id to match a pattern against. A deterministic
    /// first fetch is expressed by injecting the action instead.
    async fn open_browse(self: Arc<Self>) {
        if self.instruction.trim().is_empty() {
            info!(
                "Gopher client {} has no instruction; waiting for an injected request",
                self.client_id
            );
            return;
        }

        let memory = self
            .app_state
            .get_memory_for_client(self.client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            &self.llm_client,
            &self.app_state,
            self.client_id.to_string(),
            &self.instruction,
            &memory,
            None,
            self.protocol.as_ref(),
            &self.status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    self.app_state
                        .set_memory_for_client(self.client_id, mem)
                        .await;
                }
                Self::run_actions(self.clone(), actions, 0).await;
            }
            Err(e) => {
                // Stay usable: the operator can still drive this client from the dashboard.
                Log::to(&self.status_tx).warn(format!(
                    "Gopher client {} could not ask the model what to fetch: {} \
                     (a request can still be injected)",
                    self.client_id, e
                ));
            }
        }
    }

    /// Carry out the model's answer.
    ///
    /// Boxed because the chain is genuinely self-referential — an action leads to a fetch,
    /// the fetch raises an event, the event is answered with more actions — and `+ Send` is
    /// named explicitly because the whole thing is awaited inside a `tokio::spawn`.
    fn run_actions(
        session: Arc<Self>,
        actions: Vec<serde_json::Value>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            for action in actions {
                if session.ended.load(Ordering::SeqCst) {
                    debug!(
                        "Gopher client {} stopped: session ended before the next action",
                        session.client_id
                    );
                    return;
                }

                let result = match session.protocol.execute_action(action.clone()) {
                    Ok(result) => result,
                    Err(e) => {
                        Log::to(&session.status_tx).warn(format!(
                            "Gopher client {} rejected an action: {}",
                            session.client_id, e
                        ));
                        continue;
                    }
                };

                match result {
                    ClientActionResult::Custom { name, data } if name == GOPHER_FETCH_RESULT => {
                        let request = match session.resolve_fetch(&data) {
                            Ok(request) => request,
                            Err(e) => {
                                error!(
                                    "Gopher client {} could not resolve a fetch: {}",
                                    session.client_id, e
                                );
                                continue;
                            }
                        };
                        session.clone().fetch_and_notify(request, depth).await;
                    }
                    ClientActionResult::Disconnect => {
                        session.end("the model ended the browsing session").await;
                        return;
                    }
                    ClientActionResult::WaitForMore => {
                        info!(
                            "Gopher client {} is idle: the model asked to stop here",
                            session.client_id
                        );
                    }
                    ClientActionResult::NoAction => {}
                    ClientActionResult::SendData(_) | ClientActionResult::Multiple(_) => {
                        // Neither is producible by this protocol's executor.
                        debug!(
                            "Gopher client {} ignored an action result it does not produce",
                            session.client_id
                        );
                    }
                    ClientActionResult::Custom { name, .. } => {
                        debug!(
                            "Gopher client {} ignored unexpected custom result '{}'",
                            session.client_id, name
                        );
                    }
                }
            }
        })
    }

    /// Turn a `gopher_fetch` custom result into a concrete target.
    fn resolve_fetch(&self, data: &serde_json::Value) -> Result<FetchRequest> {
        let selector = data
            .get("selector")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let item_type = data
            .get("item_type")
            .and_then(|v| v.as_str())
            .and_then(|s| s.chars().next())
            .unwrap_or(actions::DEFAULT_ITEM_TYPE);
        let host = data
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|h| !h.is_empty())
            .unwrap_or(&self.default_host)
            .to_string();
        let port = data
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(self.default_port);
        let query = data
            .get("query")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(FetchRequest {
            host,
            port,
            selector,
            item_type,
            query,
        })
    }

    /// Fetch, raise the matching event, and act on the answer.
    ///
    /// The event is what keeps browsing iterative. A fetch that raised nothing would leave
    /// the model with one turn and no way to say "now open that item", which is the whole
    /// point of a menu.
    async fn fetch_and_notify(self: Arc<Self>, request: FetchRequest, depth: usize) {
        let outcome = match self.perform_fetch(&request).await {
            Ok(outcome) => outcome,
            Err(e) => {
                Log::to(&self.status_tx).warn(format!(
                    "Gopher client {} could not fetch {:?} from {}:{}: {}",
                    self.client_id, request.selector, request.host, request.port, e
                ));
                let _ = self.status_tx.send("__UPDATE_UI__".to_string());
                return;
            }
        };

        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
        self.notify(&request, outcome, depth).await;
    }

    /// One request on its own connection: write the selector line, read to EOF.
    async fn perform_fetch(&self, request: &FetchRequest) -> Result<FetchOutcome> {
        if self.ended.load(Ordering::SeqCst) {
            return Err(anyhow!("the browsing session has ended"));
        }

        let dial = dial_addr(&request.host, request.port);
        let line = request_line(&request.selector, request.query.as_deref());

        debug!(
            "Gopher client {} fetching {:?} (type '{}') from {}",
            self.client_id, request.selector, request.item_type, dial
        );

        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&dial))
            .await
            .map_err(|_| anyhow!("timed out connecting to {dial}"))?
            .with_context(|| format!("could not connect to {dial}"))?;

        let (mut read_half, mut write_half) = tokio::io::split(stream);
        write_half.write_all(line.as_bytes()).await?;
        write_half.flush().await?;
        trace!(
            "Gopher client {} sent request line: {:?}",
            self.client_id,
            line
        );

        // Read until EOF. The server closing is the only signal the transfer is complete —
        // the reply has no length — so a size cap and a deadline are the only bounds there
        // are.
        let mut body: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 8192];
        let mut truncated = false;
        loop {
            let n = tokio::time::timeout(READ_TIMEOUT, read_half.read(&mut chunk))
                .await
                .map_err(|_| anyhow!("timed out waiting for {dial} to finish its reply"))??;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() >= MAX_REPLY_BYTES {
                body.truncate(MAX_REPLY_BYTES);
                truncated = true;
                warn!(
                    "Gopher client {} truncated a reply from {} at {} bytes",
                    self.client_id, dial, MAX_REPLY_BYTES
                );
                break;
            }
        }
        let _ = write_half.shutdown().await;

        let reply_bytes = body.len();
        let raw = String::from_utf8_lossy(&body).into_owned();
        trace!("Gopher client {} reply:\n{}", self.client_id, raw);

        Ok(FetchOutcome {
            reply: parse_gopher_reply(&raw, request.item_type),
            request_bytes: line.len(),
            reply_bytes,
            truncated,
        })
    }

    /// Raise the event this reply calls for and run whatever the model answers with.
    async fn notify(self: &Arc<Self>, request: &FetchRequest, outcome: FetchOutcome, depth: usize) {
        let FetchOutcome {
            reply,
            reply_bytes,
            truncated,
            ..
        } = outcome;

        let (event, summary) = match reply {
            GopherReply::Menu {
                items,
                malformed_lines,
            } => {
                let mut data = json!({
                    "selector": request.selector,
                    "host": request.host,
                    "port": request.port,
                    "item_count": items.len(),
                    "items": items
                        .iter()
                        .map(|item| json!({
                            "item_type": item.item_type.to_string(),
                            "item_type_name": item_type_name(item.item_type),
                            "display": item.display,
                            "selector": item.selector,
                            "host": item.host,
                            "port": item.port,
                        }))
                        .collect::<Vec<_>>(),
                });
                if !malformed_lines.is_empty() {
                    data["malformed_lines"] = json!(malformed_lines);
                }
                if truncated {
                    data["truncated"] = json!(true);
                }
                let summary = format!("menu with {} item(s)", items.len());
                (Event::new(&GOPHER_MENU_RECEIVED_EVENT, data), summary)
            }
            GopherReply::Document { text } => {
                let line_count = if text.is_empty() {
                    0
                } else {
                    text.split('\n').count()
                };
                let mut data = json!({
                    "selector": request.selector,
                    "host": request.host,
                    "port": request.port,
                    "requested_item_type": request.item_type.to_string(),
                    "text": text,
                    "line_count": line_count,
                });
                if truncated {
                    data["truncated"] = json!(true);
                }
                (
                    Event::new(&GOPHER_DOCUMENT_RECEIVED_EVENT, data),
                    format!("document of {line_count} line(s)"),
                )
            }
            GopherReply::Error { message } => {
                let data = json!({
                    "selector": request.selector,
                    "host": request.host,
                    "port": request.port,
                    "message": message,
                });
                (
                    Event::new(&GOPHER_ERROR_RECEIVED_EVENT, data),
                    format!("error item: {message}"),
                )
            }
        };

        info!(
            "Gopher client {} received {} bytes for {:?}: {}",
            self.client_id, reply_bytes, request.selector, summary
        );
        let _ = self.status_tx.send(format!(
            "[CLIENT] Gopher client {} <- {} for {:?}",
            self.client_id, summary, request.selector
        ));

        if depth + 1 > MAX_FOLLOWUP_DEPTH {
            Log::to(&self.status_tx).warn(format!(
                "Gopher client {} stopped browsing after {} follow-ups (depth {})",
                self.client_id, MAX_FOLLOWUP_DEPTH, depth
            ));
            return;
        }

        if self.ended.load(Ordering::SeqCst) {
            return;
        }

        let memory = self
            .app_state
            .get_memory_for_client(self.client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            &self.llm_client,
            &self.app_state,
            self.client_id.to_string(),
            &self.instruction,
            &memory,
            Some(&event),
            self.protocol.as_ref(),
            &self.status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    self.app_state
                        .set_memory_for_client(self.client_id, mem)
                        .await;
                }
                // The answer is carried out. Dropping it here is the single most common
                // client defect in this repo, and for a browser it is fatal: the model would
                // be shown a menu and given no way to open anything on it.
                Self::run_actions(self.clone(), actions, depth + 1).await;
            }
            Err(e) => {
                Log::to(&self.status_tx).warn(format!(
                    "Gopher client {} could not act on {}: {}",
                    self.client_id,
                    event.id(),
                    e
                ));
            }
        }
    }

    /// End the session once, from whichever path got there first.
    async fn end(&self, reason: &str) {
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        info!("Gopher client {} finished: {}", self.client_id, reason);
        self.app_state
            .update_client_status(self.client_id, ClientStatus::Disconnected)
            .await;
        // Stop the dashboard offering [ send ] on a client that is done.
        self.app_state.remove_client_handle(self.client_id).await;
        let _ = self.status_tx.send(format!(
            "[CLIENT] Gopher client {} disconnected ({})",
            self.client_id, reason
        ));
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Drain injected commands until the channel closes or one of them ends the session.
    ///
    /// A separate task, not a `select!` arm, and for the same reason WHOIS uses one: this
    /// client's first model call can be parked by a manual handler for as long as the
    /// operator takes, and `[ send ]` has to work during exactly that window.
    ///
    /// `command_support::handle_stream_client_command` cannot run this vocabulary — there is
    /// no persistent write half to hand it, and the fetch verbs yield
    /// `ClientActionResult::Custom` — so the action goes through the same
    /// `perform_fetch`/`notify` pair the model's actions use.
    ///
    /// **The reply is sent as soon as the bytes have been exchanged, before the model is told
    /// about them.** Telling the model can park for minutes behind a manual handler, and
    /// `send_to_client` has a caller-supplied timeout; the caller asked whether the request
    /// went out, which is answerable immediately. The consequence is that a second injected
    /// command waits in the bounded channel until the first one's follow-up chain finishes,
    /// which is ordinary "client busy" backpressure.
    async fn command_loop(self: Arc<Self>, mut command_rx: mpsc::Receiver<ClientCommand>) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let executed = self.protocol.execute_action(action.clone());
            let mut pending: Option<(FetchRequest, FetchOutcome)> = None;
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> = match executed {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Custom { name, data }) if name == GOPHER_FETCH_RESULT => {
                    match self.resolve_fetch(&data) {
                        Err(e) => Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                        Ok(request) => match self.perform_fetch(&request).await {
                            Ok(fetched) => {
                                let bytes_sent = fetched.request_bytes;
                                pending = Some((request, fetched));
                                Ok(ClientSendOutcome::Sent { bytes_sent })
                            }
                            Err(e) => Err(e),
                        },
                    }
                }
                Ok(ClientActionResult::Disconnect) => {
                    disconnect = true;
                    Ok(ClientSendOutcome::Disconnected)
                }
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more (Gopher replies are never partial)".to_string(),
                }),
                Ok(_) => Ok(ClientSendOutcome::Executed {
                    detail: "executed".to_string(),
                }),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => json!({"error": e.to_string()}),
            };
            self.app_state
                .record_access_log(
                    AccessLogOwner::Client(self.client_id.as_u32()),
                    self.protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            if let Err(e) = &outcome {
                Log::to(&self.status_tx).warn(format!(
                    "Gopher client {} injected action failed: {}",
                    self.client_id, e
                ));
            }
            let _ = self.status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                self.end("an injected disconnect ended the browsing session")
                    .await;
                break;
            }

            // Now tell the model, and let it browse on from here. An injected fetch is a real
            // step in the session, not a side channel: the operator opening a menu should get
            // the same follow-up behaviour the model's own fetch gets.
            if let Some((request, fetched)) = pending {
                self.notify(&request, fetched, 0).await;
            }
        }
    }
}
