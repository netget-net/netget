//! Standard I/O (stdin/stdout/stderr) server implementation.
//!
//! Platform: Unix/Linux/macOS only. NetGet itself becomes the child process behind a pipe
//! (`someprogram | netget ... | otherprogram`): it reads from its own stdin, hands each chunk to
//! the LLM as a `stdio_input_received` event, and the model decides what to emit on stdout/stderr.
//!
//! ## Coexistence (the subtlety)
//!
//! This protocol takes over the process's real stdin/stdout, so it is fundamentally incompatible
//! with two run modes and refuses to start under either:
//!
//! - **the interactive TUI** — ratatui owns the terminal; detected via `stdin` being a TTY.
//! - **`--mcp` stdio** — JSON-RPC owns stdin/stdout; detected via the process argv.
//!
//! It is intended for headless / one-shot piped use (`prog | netget --non-interactive '...' | prog`)
//! or under `--mcp-http`, where stdin is a pipe and tracing logs go to stderr. Only one stdio
//! server may run per process (an `AtomicBool` claim). See `CLAUDE.md` for the caveat that the
//! non-interactive status stream currently shares stdout.
#![cfg(unix)]

pub mod actions;

use anyhow::Result;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::llm::action_helper::call_llm_batch;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::stdio::actions::{
    StdioProtocol, STDIO_INPUT_CLOSED_EVENT, STDIO_INPUT_RECEIVED_EVENT, STDIO_STARTED_EVENT,
};
use crate::state::app_state::AppState;

/// At most one stdio server may own the process's standard streams at a time.
static STDIO_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Releases the stdio claim when the read task ends (including on abort).
struct StdioClaimGuard;

impl Drop for StdioClaimGuard {
    fn drop(&mut self) {
        STDIO_CLAIMED.store(false, Ordering::SeqCst);
    }
}

/// True when this process was launched as an MCP stdio server (`--mcp` / `--mcp-stdio`), in which
/// case JSON-RPC owns stdin/stdout and a stdio protocol server must not contend for them.
/// `--mcp-http` is a different flag and does not match.
fn running_as_mcp_stdio() -> bool {
    std::env::args().any(|a| a == "--mcp" || a == "--mcp-stdio")
}

/// How many reads from stdin may wait while the model answers an earlier one.
///
/// Each is at most one 8 KiB read, so the queue holds at most 256 KiB; past it the reader stops
/// reading and the pipe holds the upstream writer back. It equals the batch cap, so one
/// batching call can take everything that is waiting.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the stdin reader hands the dispatcher.
enum StdinInput {
    /// One read's bytes.
    Data(Vec<u8>),
    /// Upstream closed the pipe.
    Closed,
}

/// Standard I/O server.
pub struct StdioServer;

impl StdioServer {
    /// Claim the process stdio and spawn the read/dispatch loop.
    ///
    /// Returns `Err` — so `server_startup` records `ServerStatus::Error` — when the environment
    /// cannot support a stdio takeover (a TTY/TUI, `--mcp` stdio, or another stdio server already
    /// running). No half-started state is left behind on refusal.
    pub async fn spawn_with_llm_actions(
        send_first: bool,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        if std::io::stdin().is_terminal() {
            anyhow::bail!(
                "stdio server refuses to run under an interactive terminal: the TUI owns the \
                 terminal. Use it as a pipe filter (prog | netget --non-interactive '...' | prog) \
                 or under --mcp-http."
            );
        }
        if running_as_mcp_stdio() {
            anyhow::bail!(
                "stdio server cannot run under --mcp (stdio): MCP JSON-RPC already owns this \
                 process's stdin/stdout. Use --mcp-http, or run NetGet headless as a pipe filter."
            );
        }
        if STDIO_CLAIMED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            anyhow::bail!(
                "another stdio server already owns this process's stdin/stdout; only one is \
                 possible per process."
            );
        }
        // From here on we own the claim; the guard releases it on task end.
        let claim = StdioClaimGuard;

        Log::new(Some(&status_tx)).info("stdio server claimed process stdin/stdout");

        let protocol = Arc::new(StdioProtocol::new());
        let task_registrar = app_state.clone();

        // The reader runs on its own so that input arriving while the model is answering is
        // read as it arrives — each read keeping its own boundary — rather than piling up in the
        // pipe until the call returns. The bounded channel is the backpressure: once it holds
        // `READ_QUEUE_CHUNKS` chunks the reader stops reading and the pipe holds the upstream
        // writer back, which is what a slow filter does to the program feeding it.
        let (input_tx, mut input_rx) = mpsc::channel::<StdinInput>(READ_QUEUE_CHUNKS);
        let reader_status = status_tx.clone();
        let reader = app_state
            .spawn_server_task(server_id, async move {
                let mut stdin = tokio::io::stdin();
                let mut buffer = vec![0u8; 8192];
                loop {
                    let input = match stdin.read(&mut buffer).await {
                        Ok(0) => StdinInput::Closed,
                        Ok(n) => StdinInput::Data(buffer[..n].to_vec()),
                        Err(e) => {
                            Log::new(Some(&reader_status))
                                .error(format!("stdio stdin read error: {}", e));
                            break;
                        }
                    };
                    let closed = matches!(input, StdinInput::Closed);
                    if input_tx.send(input).await.is_err() || closed {
                        break;
                    }
                }
            })
            .await;

        let handle = tokio::spawn(async move {
            let _claim = claim; // released on return/abort

            if send_first {
                let event = Event::new(&STDIO_STARTED_EVENT, serde_json::json!({}));
                let _ = Self::dispatch(
                    std::slice::from_ref(&event),
                    &llm_client,
                    &app_state,
                    server_id,
                    protocol.as_ref(),
                    &status_tx,
                )
                .await;
            }

            let mut input_closed = false;
            while !input_closed {
                let first = match input_rx.recv().await {
                    Some(StdinInput::Data(data)) => data,
                    Some(StdinInput::Closed) => {
                        input_closed = true;
                        break;
                    }
                    // The reader failed and has said so; there is no EOF to report.
                    None => break,
                };

                // With batching on, every read that arrived while the model was answering the
                // previous one is answered in one call; with it off, one read per call.
                let batching = app_state
                    .server_conversation_settings(server_id)
                    .await
                    .is_some_and(|(_, batching)| batching);
                let mut chunks = vec![first];
                while batching && chunks.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match input_rx.try_recv() {
                        Ok(StdinInput::Data(data)) => chunks.push(data),
                        Ok(StdinInput::Closed) => {
                            // Answer what was read first; the EOF is its own event after it.
                            input_closed = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }

                let mut events = Vec::with_capacity(chunks.len());
                for data in &chunks {
                    let (data_str, encoding) = if data
                        .iter()
                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                    {
                        (String::from_utf8_lossy(data).to_string(), "utf8")
                    } else {
                        (hex::encode(data), "hex")
                    };

                    Log::new(Some(&status_tx)).debug(format!(
                        "stdio read {} bytes from stdin ({})",
                        data.len(),
                        encoding
                    ));

                    events.push(Event::new(
                        &STDIO_INPUT_RECEIVED_EVENT,
                        serde_json::json!({ "data": data_str, "encoding": encoding }),
                    ));
                }
                let should_close = Self::dispatch(
                    &events,
                    &llm_client,
                    &app_state,
                    server_id,
                    protocol.as_ref(),
                    &status_tx,
                )
                .await;
                if should_close {
                    info!("stdio session closed by model (close_stdio)");
                    reader.abort();
                    return;
                }
            }

            if input_closed {
                // EOF: upstream closed the pipe. Let the model emit any final output.
                Log::new(Some(&status_tx)).debug("stdio stdin reached EOF");
                let event = Event::new(&STDIO_INPUT_CLOSED_EVENT, serde_json::json!({}));
                let _ = Self::dispatch(
                    std::slice::from_ref(&event),
                    &llm_client,
                    &app_state,
                    server_id,
                    protocol.as_ref(),
                    &status_tx,
                )
                .await;
            }
            reader.abort();
        });

        task_registrar.register_server_task(server_id, handle).await;
        Ok(())
    }

    /// Run one LLM round-trip for `events` (one, or a batch that arrived during the previous
    /// call) and act on the results. Returns true if the model asked to close the stdio session.
    async fn dispatch(
        events: &[Event],
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        protocol: &StdioProtocol,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        // The newest event names the batch in the log; it is the trigger the model answers.
        let Some(event) = events.last() else {
            return false;
        };
        match call_llm_batch(llm_client, app_state, server_id, None, events, protocol).await {
            Ok(result) => {
                for msg in result.messages {
                    let _ = status_tx.send(msg);
                }
                let mut should_close = false;
                let mut wrote = false;
                for pr in result.protocol_results {
                    match pr {
                        ActionResult::Output(bytes) => {
                            wrote = true;
                            Self::write_stream(false, &bytes, status_tx).await;
                        }
                        ActionResult::Custom { name, data } if name == "stdio_stderr" => {
                            wrote = true;
                            if let Some(hex_str) = data.get("hex").and_then(|v| v.as_str()) {
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    Self::write_stream(true, &bytes, status_tx).await;
                                }
                            }
                        }
                        ActionResult::CloseConnection => should_close = true,
                        _ => {}
                    }
                }
                // The model answering nothing is a real answer for a filter (grep drops a line),
                // so it emits nothing — but it must stay distinguishable in the log from the
                // backend having failed, which is the case below.
                let decision = match (wrote, should_close) {
                    (_, true) => "model_close",
                    (true, false) => "model_answer",
                    (false, false) => "model_silent",
                };
                debug!("stdio {} decision={}", event.event_type.id, decision);
                should_close
            }
            Err(e) => {
                // The backend failed. stdout is the payload stream and stays pristine — writing a
                // diagnostic there would corrupt the data a downstream process is parsing. fd 2 is
                // where a Unix filter reports that it could not do its job, so the category goes
                // there and nothing else does: never the error, which goes to the log alone.
                let failure = crate::utils::WireFailure::classify(&e);
                let decision = if failure.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_unavailable"
                };
                Log::new(Some(status_tx)).error(format!(
                    "stdio {} decision={} error: {}",
                    event.event_type.id, decision, e
                ));
                let mut line = String::with_capacity(48);
                line.push_str(failure.prefixed_text());
                line.push('\n');
                Self::write_stream(true, line.as_bytes(), status_tx).await;
                false
            }
        }
    }

    /// Write `bytes` to stdout (`stderr = false`) or stderr (`stderr = true`), flushing.
    async fn write_stream(stderr: bool, bytes: &[u8], status_tx: &mpsc::UnboundedSender<String>) {
        let res = if stderr {
            let mut out = tokio::io::stderr();
            out.write_all(bytes).await.and(out.flush().await)
        } else {
            let mut out = tokio::io::stdout();
            out.write_all(bytes).await.and(out.flush().await)
        };
        match res {
            Ok(()) => {
                let dest = if stderr { "stderr" } else { "stdout" };
                debug!("stdio wrote {} bytes to {}", bytes.len(), dest);
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!("stdio write error: {}", e));
            }
        }
    }
}
