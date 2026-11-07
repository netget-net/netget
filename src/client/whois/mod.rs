//! WHOIS client implementation.
//!
//! **The peer here is somebody else's server, and it decides how much it says.** A WHOIS
//! reply has no length field: the server writes until it is done and then closes, so the
//! client reads until EOF. That makes "read until EOF" the protocol *and* an unbounded
//! allocation controlled entirely by the remote end — a server that streams, or simply never
//! stops, grows this process's memory for as long as it keeps sending. Both read paths are
//! therefore capped by [`MAX_RESPONSE_BYTES`] and bounded by [`RESPONSE_READ_TIMEOUT`], and
//! an over-long reply is truncated and answered rather than abandoned: the head of a WHOIS
//! record is the part with the registrar in it.

pub mod actions;

pub use actions::WhoisClientProtocol;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

/// The most of a WHOIS reply this client will hold.
///
/// Generous — a thick registry record with a legal notice attached is a few tens of KB — and
/// far below what an unbounded read costs. The remote server chooses how much it sends; this
/// is the only thing that chooses how much is kept.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// How long to wait for more of a reply before giving up on the server.
///
/// Bounds the gap between reads rather than the whole transfer, so a server that is still
/// sending keeps the connection. Without it a server that accepts, says nothing and never
/// closes parks this client forever — and the model is waiting on the response event.
const RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Strip control characters from a query before it goes on the wire.
///
/// RFC 3912 is one line, one query. A `query` containing CR or LF would put a *second* query
/// line on the wire that the model never asked for, and the client would then attribute the
/// server's reply to the first — so what reaches the response event would not describe what
/// was actually asked. `finger`'s client (`strip_controls`) and `gopher`'s (which refuses a
/// selector containing CR or LF outright) both guard this; WHOIS did not.
///
/// ESC goes with them: a query is echoed into the log and onto the operator's dashboard.
fn sanitize_query(s: &str) -> String {
    crate::utils::sanitize::strip_controls(s)
}

/// A WHOIS reply as it came off the socket.
struct Reply {
    /// Decoded lossily on purpose: registry servers still emit Latin-1, and `read_to_string`
    /// (which this replaced on one path) fails a whole transfer over a single byte.
    text: String,
    /// [`MAX_RESPONSE_BYTES`] cut the reply short.
    truncated: bool,
    /// The socket errored. Reported separately from the text, because the bytes that did
    /// arrive are still the head of the record.
    error: Option<std::io::Error>,
}

/// Read a WHOIS reply to EOF, the cap, or the timeout.
async fn read_reply<R>(reader: &mut R, client_id: ClientId) -> Reply
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut response: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut truncated = false;
    let mut error = None;

    loop {
        let read = match tokio::time::timeout(RESPONSE_READ_TIMEOUT, reader.read(&mut buf)).await {
            Err(_) => {
                warn!(
                    "WHOIS client {} saw no further data for {}s; treating the reply as \
                     complete",
                    client_id,
                    RESPONSE_READ_TIMEOUT.as_secs()
                );
                break;
            }
            Ok(read) => read,
        };

        match read {
            Ok(0) => break,
            Ok(n) => {
                let room = MAX_RESPONSE_BYTES.saturating_sub(response.len());
                if n > room {
                    response.extend_from_slice(&buf[..room]);
                    truncated = true;
                    warn!(
                        "WHOIS client {} reply exceeded {} bytes; keeping the head and \
                         stopping. A WHOIS reply has no length field, so how much arrives is \
                         the remote server's choice, not ours.",
                        client_id, MAX_RESPONSE_BYTES
                    );
                    break;
                }
                response.extend_from_slice(&buf[..n]);
            }
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }

    Reply {
        text: String::from_utf8_lossy(&response).into_owned(),
        truncated,
        error,
    }
}

use crate::client::llm_budget::call_llm_for_client;
use crate::client::whois::actions::{
    WHOIS_CLIENT_CONNECTED_EVENT, WHOIS_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// The query that actually went on the wire, whichever path put it there (the model's
/// `query_whois` or an injected one). Read once the server closes, to raise the
/// response event with the right `query`.
type SentQuery = Arc<std::sync::Mutex<Option<String>>>;

/// What [`WhoisClient::apply_action`] did with one action.
enum Applied {
    /// Bytes written (0 when the action produced no wire output).
    Sent(usize),
    /// The write side was shut down and the session should end.
    Disconnect,
}

/// WHOIS client that connects to a WHOIS server
pub struct WhoisClient;

impl WhoisClient {
    /// Connect to a WHOIS server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Connect to WHOIS server
        let stream = TcpStream::connect(&remote_addr).await.context(format!(
            "Failed to connect to WHOIS server at {}",
            remote_addr
        ))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "WHOIS client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] WHOIS client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));
        let protocol = Arc::new(WhoisClientProtocol::new());
        let sent_query: SentQuery = Arc::new(std::sync::Mutex::new(None));

        // Command channel for injected actions (the dashboard's [ query_whois ] /
        // [ disconnect ]). Registered BEFORE the connected-event LLM call, which a manual
        // `*` rule can park for minutes - the operator must be able to send the query
        // while it waits. The read below is a plain `read()` loop, but the command task is
        // separate anyway so an injected query never waits on the LLM round-trip.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            write_half_arc.clone(),
            sent_query.clone(),
            client_id,
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn task to handle LLM interaction
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            Self::session(
                read_half,
                write_half_arc,
                protocol,
                sent_query,
                remote_addr,
                llm_client,
                app_state.clone(),
                status_tx.clone(),
                client_id,
            )
            .await;
            // The session is over: drop the handle so the dashboard stops offering
            // [ send ] and the command task ends with its channel.
            app_state.remove_client_handle(client_id).await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Connected event -> (model's) query -> read until the server closes -> response event.
    #[allow(clippy::too_many_arguments)]
    async fn session<R, W>(
        mut read_half: R,
        write_half: Arc<Mutex<W>>,
        protocol: Arc<WhoisClientProtocol>,
        sent_query: SentQuery,
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        // Call LLM with connected event to get initial query
        let event = Event::new(
            &WHOIS_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_addr,
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
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
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Execute actions (should include query_whois)
                for action in actions {
                    let result = match protocol.execute_action(action) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("WHOIS client {} rejected action: {}", client_id, e);
                            continue;
                        }
                    };
                    match Self::apply_action(result, &write_half, &sent_query, client_id).await {
                        Ok(Applied::Sent(_)) => {}
                        Ok(Applied::Disconnect) => {
                            info!("WHOIS client {} disconnecting before query", client_id);
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return;
                        }
                        Err(e) => {
                            error!("WHOIS client {} failed to send query: {}", client_id, e);
                            app_state
                                .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                                .await;
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                // Stay connected: the operator can still inject the query from the
                // dashboard, and the server will close on its own otherwise.
                Log::to(&status_tx).warn(format!(
                    "WHOIS client {} LLM error: {} (still connected; a query can be \
                     injected)",
                    client_id, e
                ));
            }
        }

        if sent_query.lock().map(|q| q.is_none()).unwrap_or(true) {
            info!(
                "WHOIS client {} has no query yet; waiting for an injected one or the server closing",
                client_id
            );
        }

        // Read the full response: WHOIS servers close after sending it (RFC 3912). A
        // cancellation-safe `read()` loop rather than `read_to_string`, so the shape stays
        // compatible with a `select!` arm if one is ever needed — and capped, because how
        // much arrives is the remote server's choice (see the module note).
        let reply = read_reply(&mut read_half, client_id).await;
        if let Some(e) = reply.error {
            error!("WHOIS client {} read error: {}", client_id, e);
            app_state
                .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return;
        }
        let response = reply.text;
        let truncated = reply.truncated;
        debug!(
            "WHOIS client {} received {} bytes",
            client_id,
            response.len()
        );
        trace!("WHOIS response:\n{}", response);

        let query = sent_query.lock().ok().and_then(|q| q.clone());
        match query {
            Some(query) => {
                // Call LLM with response
                // `truncated` is on the event because a model that read half a record and
                // thought it had the whole one would answer confidently and wrongly.
                let event = Event::new(
                    &WHOIS_CLIENT_RESPONSE_RECEIVED_EVENT,
                    serde_json::json!({
                        "response": response,
                        "query": query,
                        "truncated": truncated,
                    }),
                );

                let memory = app_state
                    .get_memory_for_client(client_id)
                    .await
                    .unwrap_or_default();

                match call_llm_for_client(
                    &llm_client,
                    &app_state,
                    client_id.to_string(),
                    &instruction,
                    &memory,
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
                        // Update memory
                        if let Some(mem) = memory_updates {
                            app_state.set_memory_for_client(client_id, mem).await;
                        }

                        // Execute what the model asked for. These were discarded, so a
                        // model that read a registry response and wanted to follow the
                        // referral to the registrar -- the chase that is most of what
                        // WHOIS is used for -- was silently ignored.
                        use crate::llm::actions::client_trait::{Client, ClientActionResult};
                        for action in actions {
                            let Ok(ClientActionResult::Custom { name, data }) =
                                protocol.execute_action(action.clone())
                            else {
                                continue;
                            };
                            if name != "whois_query" {
                                continue;
                            }
                            let Some(q) = data.get("query").and_then(|v| v.as_str()) else {
                                continue;
                            };
                            match Self::run_query_once(&remote_addr, q, client_id).await {
                                Ok(resp) => info!(
                                    "WHOIS client {} follow-up query {:?} returned {} bytes",
                                    client_id,
                                    q,
                                    resp.len()
                                ),
                                Err(e) => error!(
                                    "WHOIS client {} follow-up query {:?} failed: {}",
                                    client_id, q, e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for WHOIS client {}: {}", client_id, e);
                    }
                }

                // WHOIS is one-shot, connection closes after response
                info!("WHOIS client {} query complete", client_id);
            }
            None => {
                info!(
                    "WHOIS client {} closed by the server before any query was sent",
                    client_id
                );
            }
        }

        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] WHOIS client {} disconnected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Put one executed action on the wire. Shared by the LLM path and injected commands
    /// so the encoding of `query_whois` exists exactly once.
    /// Run one WHOIS query on a **fresh** connection and return the response.
    ///
    /// Raises no event and calls no LLM.
    ///
    /// The new connection is not incidental. RFC 3912 is one query per connection: the
    /// server answers and closes, and `apply_action` says so itself ("a second one on the
    /// same connection is outside RFC 3912 and most servers ignore it"). So a follow-up
    /// the model asks for after reading a response -- the referral chase that is most of
    /// what WHOIS is for, where the registry tells you which registrar to ask next --
    /// genuinely needs its own connection.
    ///
    /// Raising no event also bounds the chain and keeps the async type non-recursive,
    /// which is what tokio::spawn's Send bound requires.
    async fn run_query_once(remote_addr: &str, query: &str, client_id: ClientId) -> Result<String> {
        use tokio::io::AsyncWriteExt;
        let mut stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("WHOIS follow-up could not reach {remote_addr}"))?;
        let query = sanitize_query(query);
        stream.write_all(format!("{query}\r\n").as_bytes()).await?;
        stream.flush().await?;

        // Was `read_to_string`, which is unbounded *and* fails the whole transfer on the
        // first non-UTF-8 byte — and a referral chase points this at registrars nobody here
        // chose, several of which still emit Latin-1. `read_reply` caps it and decodes
        // lossily; see the module note.
        let reply = read_reply(&mut stream, client_id).await;
        if let Some(e) = reply.error {
            return Err(e).with_context(|| format!("WHOIS follow-up read from {remote_addr}"));
        }
        Ok(reply.text)
    }

    async fn apply_action<W>(
        result: ClientActionResult,
        write_half: &Arc<Mutex<W>>,
        sent_query: &SentQuery,
        client_id: ClientId,
    ) -> Result<Applied>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        match result {
            ClientActionResult::Custom { name, data } if name == "whois_query" => {
                let query = sanitize_query(
                    data.get("query")
                        .and_then(|v| v.as_str())
                        .context("Missing query in action data")?,
                );
                debug!("WHOIS client {} querying: {}", client_id, query);
                let query_bytes = format!("{}\r\n", query);
                {
                    let mut writer = write_half.lock().await;
                    writer.write_all(query_bytes.as_bytes()).await?;
                    writer.flush().await?;
                }
                trace!("WHOIS client {} sent query: {}", client_id, query);
                if let Ok(mut slot) = sent_query.lock() {
                    // The first query is the one the response answers; a second one on the
                    // same connection is outside RFC 3912 and most servers ignore it.
                    slot.get_or_insert(query);
                }
                Ok(Applied::Sent(query_bytes.len()))
            }
            ClientActionResult::Disconnect => {
                debug!("WHOIS client {} disconnecting", client_id);
                // Half-close: the server reads EOF and closes, and the read loop then
                // sees 0 and runs its normal path.
                let _ = write_half.lock().await.shutdown().await;
                Ok(Applied::Disconnect)
            }
            // Unknown Custom, WaitForMore, NoAction, SendData, nested Multiple.
            _ => Ok(Applied::Sent(0)),
        }
    }

    /// Drain injected commands until the channel closes (session over, or client removed)
    /// or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because `query_whois` yields `ClientActionResult::Custom`, so the action
    /// goes through [`Self::apply_action`] - the same function the LLM path uses - and the
    /// outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop<W>(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<WhoisClientProtocol>,
        write_half: Arc<Mutex<W>>,
        sent_query: SentQuery,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use crate::llm::actions::protocol_trait::Protocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(result, &write_half, &sent_query, client_id)
                    .await
                    .map(|applied| match applied {
                        Applied::Disconnect => ClientSendOutcome::Disconnected,
                        Applied::Sent(0) => ClientSendOutcome::Executed {
                            detail: "executed (nothing to write)".to_string(),
                        },
                        Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
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
                    "WHOIS client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // Do not wait for the server to answer the half-close with its own FIN:
                // the rail must stop offering [ send ] on this client now.
                app_state.remove_client_handle(client_id).await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }
}
