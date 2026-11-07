//! Generic adoption helpers for the client command channel.
//!
//! A client protocol opts into injected commands (the dashboard's \[send\]
//! button, and any future programmatic control) with a ~10-line diff to its
//! connection loop:
//!
//! ```ignore
//! let mut command_rx = command_support::register_command_channel(&app_state, client_id).await;
//! // ... inside the read loop:
//! tokio::select! {
//!     read = read_half.read(&mut buffer) => { /* existing arms unchanged */ }
//!     Some(cmd) = command_rx.recv() => {
//!         if command_support::handle_stream_client_command(
//!             &MyClientProtocol, &write_half_arc, cmd, client_id, &app_state, &status_tx,
//!         ).await { break; }
//!     }
//! }
//! ```
//!
//! `handle_stream_client_command` is fully generic for split-stream clients:
//! it executes the action through the protocol's own `execute_action` (the
//! same machinery LLM-produced actions use), writes `SendData` results to the
//! write half, and replies with a [`ClientSendOutcome`]. A protocol whose
//! vocabulary produces `Custom` results (IRC's send_privmsg, for instance)
//! writes its own arm body and uses [`reply`] directly.
//!
//! Concurrency note: the command arm runs in the same single task as the read
//! loop, so a command never races the loop's own writes. A command arriving
//! while the loop is mid-LLM-call simply waits its turn in the bounded
//! channel; user injection is deliberately independent of the protocol's
//! Idle/Processing state machine.
//!
//! Cancellation-safety note for adopters: `AsyncReadExt::read` is
//! cancellation-safe, so wrapping it in `tokio::select!` with the command arm
//! does not lose data.

use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::info;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::state::client_handles::{
    ClientCommand, ClientHandle, ClientSendOutcome, CLIENT_COMMAND_CAPACITY,
};
use crate::state::{AccessLogOwner, AppState, ClientId};

/// Create and register the command channel for a running client. Call once the
/// connection is established; move the returned receiver into the loop task.
pub async fn register_command_channel(
    state: &AppState,
    client_id: ClientId,
) -> mpsc::Receiver<ClientCommand> {
    let (command_tx, command_rx) = mpsc::channel(CLIENT_COMMAND_CAPACITY);
    state
        .register_client_handle(client_id, ClientHandle { command_tx })
        .await;
    command_rx
}

/// Reply on a command's oneshot, tolerating a caller that stopped listening.
pub fn reply(command: ClientCommand, outcome: anyhow::Result<ClientSendOutcome>) {
    let _ = command.reply_tx.send(outcome);
}

/// Generic command-arm body for split-stream clients. Executes the action,
/// maps the result to wire writes, records a client access-log entry, and
/// replies on the command's oneshot.
///
/// Returns `true` when the action requested disconnect and the loop should
/// break (the reply is sent before returning).
pub async fn handle_stream_client_command<W, P>(
    protocol: &P,
    write_half: &Arc<Mutex<W>>,
    command: ClientCommand,
    client_id: ClientId,
    state: &AppState,
    status_tx: &mpsc::UnboundedSender<String>,
) -> bool
where
    W: AsyncWrite + Unpin,
    P: Client + ?Sized,
{
    let action = command.action.clone();
    let (outcome, should_break) = execute_command_action(protocol, write_half, &action).await;

    // Record the injected action in the access log so it shows up in the
    // client's request pane exactly like LLM-produced traffic.
    let outcome_json = match &outcome {
        Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
        Err(e) => serde_json::json!({"error": e.to_string()}),
    };
    state
        .record_access_log(
            AccessLogOwner::Client(client_id.as_u32()),
            protocol.protocol_name(),
            None,
            "injected_action",
            action,
            vec![outcome_json],
        )
        .await;

    match &outcome {
        Ok(ClientSendOutcome::Sent { bytes_sent }) => {
            info!(
                "Client {} executed injected action ({} bytes sent)",
                client_id, bytes_sent
            );
        }
        Ok(ClientSendOutcome::Disconnected) => {
            info!("Client {} disconnecting on injected action", client_id);
        }
        Ok(_) => {}
        Err(e) => {
            Log::to(&status_tx).warn(format!(
                "Client {} injected action failed: {}",
                client_id, e
            ));
        }
    }
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    reply(command, outcome);
    should_break
}

/// Execute one action and fold its (possibly `Multiple`) results into a single
/// outcome. Separated from the reply/logging so it can recurse.
async fn execute_command_action<W, P>(
    protocol: &P,
    write_half: &Arc<Mutex<W>>,
    action: &serde_json::Value,
) -> (anyhow::Result<ClientSendOutcome>, bool)
where
    W: AsyncWrite + Unpin,
    P: Client + ?Sized,
{
    let result = match protocol.execute_action(action.clone()) {
        Ok(result) => result,
        Err(e) => {
            return (
                Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                false,
            )
        }
    };

    let mut bytes_sent = 0usize;
    let mut disconnect = false;
    let mut details: Vec<String> = Vec::new();

    // Flatten Multiple one level deep — that is the only nesting the enum's
    // own producers use.
    let results = match result {
        ClientActionResult::Multiple(results) => results,
        single => vec![single],
    };

    for result in results {
        match result {
            ClientActionResult::SendData(bytes) => {
                let mut guard = write_half.lock().await;
                if let Err(e) = guard.write_all(&bytes).await {
                    return (Err(anyhow::anyhow!("write failed: {e}")), false);
                }
                if let Err(e) = guard.flush().await {
                    return (Err(anyhow::anyhow!("flush failed: {e}")), false);
                }
                bytes_sent += bytes.len();
            }
            ClientActionResult::Disconnect => disconnect = true,
            ClientActionResult::WaitForMore => details.push("wait_for_more".to_string()),
            ClientActionResult::NoAction => details.push("no_action".to_string()),
            ClientActionResult::Custom { name, .. } => {
                // The generic arm cannot run protocol-specific machinery;
                // protocols with Custom vocabularies need a bespoke arm body.
                details.push(format!(
                    "custom result '{name}' not executed by generic arm"
                ));
            }
            ClientActionResult::Multiple(_) => {
                details.push("nested multiple ignored".to_string());
            }
        }
    }

    let outcome = if disconnect {
        ClientSendOutcome::Disconnected
    } else if bytes_sent > 0 {
        ClientSendOutcome::Sent { bytes_sent }
    } else {
        ClientSendOutcome::Executed {
            detail: if details.is_empty() {
                "executed".to_string()
            } else {
                details.join(", ")
            },
        }
    };
    (Ok(outcome), disconnect)
}
