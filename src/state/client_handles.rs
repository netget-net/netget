//! Command channel into a **running** client's connection loop.
//!
//! # The problem this exists to solve
//!
//! `Client::execute_action()` is only ever called from inside each client's own
//! connection loop — the task that owns the socket — and the only thing that
//! produces actions for it is the LLM answering a network event. Nothing
//! outside the loop (the dashboard's \[send\] button, a scheduled task, a
//! future LLM `send_client_action`) can put an action on the wire.
//!
//! # The shape of the fix
//!
//! Unlike [`crate::state::server_handles`], this registry is **not**
//! type-erased. What every caller wants from every client is identical —
//! "here is an action JSON, execute it against the live connection" — and the
//! `Client` trait already defines that uniform vocabulary. So the handle is a
//! plain typed command channel. Each client's loop adds a `tokio::select!` arm
//! receiving [`ClientCommand`]s (see `crate::client::command_support` for the
//! generic arm body) and executes them with the same machinery it already uses
//! for LLM-produced actions.
//!
//! The channel is **bounded** (capacity [`CLIENT_COMMAND_CAPACITY`]): commands
//! are user-initiated and low-rate, and "client busy" backpressure is the
//! correct failure mode — unlike the unbounded status channels, which carry
//! fire-and-forget log lines.
//!
//! Lifetime is tied to the client: [`AppState::remove_client`] drops the
//! handle, and a loop that exits drops its receiver, which makes any later
//! send fail fast with a clear error rather than hang. Clients that have not
//! adopted the channel simply never register — `has_client_handle` returns
//! false and the UI greys out \[send\].

use tokio::sync::{mpsc, oneshot};

/// Bounded command-channel capacity per client.
pub const CLIENT_COMMAND_CAPACITY: usize = 16;

/// Outcome of injecting one action into a running client's connection loop.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ClientSendOutcome {
    /// Action executed; bytes were written and flushed to the wire.
    Sent { bytes_sent: usize },
    /// Action sent `bytes_sent` bytes and then collected what came back for it — a DataLink
    /// `probe_tcp`. `report` is the protocol's own structured account of the replies.
    Probed {
        bytes_sent: usize,
        report: serde_json::Value,
    },
    /// Action executed but produced no wire data (NoAction / WaitForMore /
    /// a Custom result the protocol handled internally).
    Executed { detail: String },
    /// The client's protocol rejected the action (unknown type, bad params).
    Rejected { error: String },
    /// The action requested disconnect; the loop is shutting down.
    Disconnected,
}

/// One injected command: the action JSON plus a best-effort reply slot.
///
/// A dropped `reply_tx` receiver is fine — fire-and-forget callers just don't
/// listen for the outcome.
pub struct ClientCommand {
    pub action: serde_json::Value,
    pub reply_tx: oneshot::Sender<anyhow::Result<ClientSendOutcome>>,
}

/// Handle to a running client's connection loop.
#[derive(Clone)]
pub struct ClientHandle {
    pub command_tx: mpsc::Sender<ClientCommand>,
}
