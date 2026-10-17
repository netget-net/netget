//! Poll-based projection of `AppState` into owned display data for the rail.
//!
//! Mirrors the rolling TUI's `update_ui_from_state`: read everything under
//! short lock windows, clone out, render from the owned snapshot. Re-polled on
//! the `__UPDATE_UI__` sentinel, on the 1s stats tick, and immediately after
//! any UI-initiated mutation.

use std::collections::HashMap;

use crate::state::app_state::{AccessLogEntry, AppState};
use crate::state::client::{ClientConnectionAttempt, ClientStatus};
use crate::state::server::{ClosedConnectionSummary, ServerStatus};
use crate::state::{AccessLogOwner, ClientId, ServerId};

#[derive(Debug, Clone)]
pub struct ConnRow {
    pub id: u32,
    pub remote_addr: String,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub active: bool,
    /// Whether this connection accepts injected actions ("message this
    /// peer") — true only where the protocol registered a peer handle.
    pub can_message: bool,
}

#[derive(Debug, Clone)]
pub struct ServerRow {
    pub id: ServerId,
    pub protocol: String,
    pub port: u16,
    pub local_addr: Option<String>,
    pub status: ServerStatus,
    pub instruction: String,
    pub memory_len: usize,
    pub startup_params: Option<serde_json::Value>,
    pub routing: Option<crate::scripting::EventHandlerConfig>,
    pub conns: Vec<ConnRow>,
    pub recent: Vec<ClosedConnectionSummary>,
    pub requests: Vec<AccessLogEntry>,
    pub task_count: usize,
    /// Seconds since the instance was created.
    pub uptime_secs: u64,
    /// Canonical client protocol name when this server's protocol has a
    /// compiled client counterpart (drives the [+client] button).
    pub client_counterpart: Option<String>,
    /// Why this server's protocol can only answer its peers, when it declares that
    /// ([`crate::protocol::metadata::ProtocolMetadataV2::request_only`]): the reason a peer's
    /// disabled `[ send message ]` gives instead of "not implemented here yet".
    pub request_only: Option<String>,
    /// Requests a `manual` rule parked, waiting for the operator's answer.
    pub intercepts: Vec<crate::state::intercepts::InterceptView>,
    /// Earlier entries per connection the model is shown (0 = off) — the edit form's value.
    pub history_entries: u16,
    /// Whether events arriving during a call are batched — the edit form's value.
    pub batching: bool,
}

#[derive(Debug, Clone)]
pub struct ClientRow {
    pub id: ClientId,
    pub protocol: String,
    pub remote_addr: String,
    pub status: ClientStatus,
    pub instruction: String,
    pub memory_len: usize,
    pub startup_params: Option<serde_json::Value>,
    pub routing: Option<crate::scripting::EventHandlerConfig>,
    pub connection: Option<ConnRow>,
    pub history: Vec<ClientConnectionAttempt>,
    pub requests: Vec<AccessLogEntry>,
    pub task_count: usize,
    /// Seconds since the instance was created.
    pub uptime_secs: u64,
    /// Whether [send] can be used, and if not, why — "not connected" and "this
    /// protocol has no command channel yet" are different problems and must
    /// not be shown as the same one.
    pub send_state: SendState,
    /// The client protocol's own verbs, in vocabulary order — the telnet
    /// client's `send_command` / `send_text`, TCP's `send_tcp_data`. The
    /// send section renders one row per entry, and a row's index selects the
    /// action in the composer, so the order must match
    /// `ComposerModel::vocabulary` exactly (both come from it).
    pub send_actions: Vec<SendVerb>,
    /// Replies a `manual` rule parked, waiting for the operator's answer.
    pub intercepts: Vec<crate::state::intercepts::InterceptView>,
    /// Earlier entries per connection the model is shown (0 = off) — the edit form's value.
    pub history_entries: u16,
    /// Whether events arriving during a call are batched — the edit form's value.
    pub batching: bool,
}

/// One verb a client can send, as the send section lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendVerb {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// The client's loop is live and accepts injected actions.
    Ready,
    /// The client is not currently connected.
    NotConnected,
    /// Connected, but this protocol's loop has not adopted the command
    /// channel (see `client/command_support.rs`).
    ProtocolUnsupported,
}

#[derive(Debug, Clone, Default)]
pub struct RailSnapshot {
    pub servers: Vec<ServerRow>,
    pub clients: Vec<ClientRow>,
    pub pipe_count: usize,
    pub active_conversations: usize,
    pub llm_activity: Vec<crate::state::llm_activity::LlmActivity>,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_llm_calls: u64,
}

/// Requests kept per band (the full scoped log stays reachable via drill-in).
const REQUESTS_PER_BAND: usize = 100;

/// Whether an action is worth its own row in a client's send section.
///
/// The vocabulary is async ∪ sync, so it also contains verbs that only make
/// sense as *answers* to a received event, or that the action bar already
/// offers better. Those are filtered from the rows only — `[ pick a verb… ]`
/// still opens the composer on the complete list, so nothing is unreachable.
pub fn is_initiable_action(name: &str) -> bool {
    match name {
        // A response-only verb: "I am not answering yet, send me more". Sent
        // on demand it writes nothing and reports "executed".
        "wait_for_more" => false,
        // The client's own `[ disconnect ]` row does this and is strictly
        // better — it keeps the instance so `[ connect ]` can redial, where
        // the protocol action just ends the loop.
        "disconnect" => false,
        _ => true,
    }
}

pub async fn build_snapshot(state: &AppState) -> RailSnapshot {
    let servers = state.get_all_servers().await;
    let clients = state.get_all_clients().await;
    let tasks = state.get_all_tasks().await;
    let llm_activity = state.llm_activity.snapshot();
    let (total_input_tokens, total_output_tokens, total_llm_calls) = state.get_llm_stats().await;
    let pipe_count = state.list_pipes().await.len();

    // Pending manual-handler intercepts, bucketed per owner.
    let mut server_intercepts: HashMap<u32, Vec<crate::state::intercepts::InterceptView>> =
        HashMap::new();
    let mut client_intercepts: HashMap<u32, Vec<crate::state::intercepts::InterceptView>> =
        HashMap::new();
    for view in state.list_intercepts().await {
        match view.owner {
            crate::state::intercepts::InterceptOwner::Server(id) => {
                server_intercepts.entry(id.as_u32()).or_default().push(view)
            }
            crate::state::intercepts::InterceptOwner::Client(id) => {
                client_intercepts.entry(id.as_u32()).or_default().push(view)
            }
        }
    }

    // One pass over the (global, capped) access log, bucketed per owner.
    let mut server_requests: HashMap<u32, Vec<AccessLogEntry>> = HashMap::new();
    let mut client_requests: HashMap<u32, Vec<AccessLogEntry>> = HashMap::new();
    for entry in state.list_access_logs(None).await {
        match entry.owner() {
            Some(AccessLogOwner::Server(id)) => {
                let bucket = server_requests.entry(id).or_default();
                if bucket.len() < REQUESTS_PER_BAND {
                    bucket.push(entry);
                }
            }
            Some(AccessLogOwner::Client(id)) => {
                let bucket = client_requests.entry(id).or_default();
                if bucket.len() < REQUESTS_PER_BAND {
                    bucket.push(entry);
                }
            }
            None => {}
        }
    }

    let mut server_rows = Vec::with_capacity(servers.len());
    for server in servers {
        let mut conns: Vec<ConnRow> = Vec::with_capacity(server.connections.len());
        for c in server.connections.values() {
            conns.push(ConnRow {
                id: c.id.as_u32(),
                remote_addr: c.remote_addr.to_string(),
                bytes_received: c.bytes_received,
                bytes_sent: c.bytes_sent,
                active: c.status == crate::state::server::ConnectionStatus::Active,
                can_message: state.has_peer_handle(server.id, c.id.as_u32()).await,
            });
        }
        conns.sort_by_key(|c| c.id);

        let task_count = tasks
            .iter()
            .filter(|t| match t.scope {
                crate::state::task::TaskScope::Server(sid) => sid == server.id,
                crate::state::task::TaskScope::Connection(sid, _) => sid == server.id,
                _ => false,
            })
            .count();

        server_rows.push(ServerRow {
            id: server.id,
            protocol: server.protocol_name.clone(),
            port: server.port,
            local_addr: server.local_addr.map(|a| a.to_string()),
            status: server.status.clone(),
            instruction: server.instruction.clone(),
            memory_len: server.memory.len(),
            startup_params: server.startup_params.clone(),
            routing: server.event_handler_config.clone(),
            recent: server.recent_connections.iter().cloned().collect(),
            requests: server_requests
                .remove(&server.id.as_u32())
                .unwrap_or_default(),
            conns,
            task_count,
            uptime_secs: server.created_at.elapsed().as_secs(),
            client_counterpart: crate::protocol::compiled_client_protocol_for_server(
                &server.protocol_name,
            ),
            request_only: crate::protocol::server_registry::registry()
                .request_only_reason(&server.protocol_name)
                .map(str::to_string),
            intercepts: server_intercepts
                .remove(&server.id.as_u32())
                .unwrap_or_default(),
            history_entries: server.history_entries,
            batching: server.batching,
        });
    }
    server_rows.sort_by_key(|s| s.id.as_u32());

    let mut client_rows = Vec::with_capacity(clients.len());
    for client in clients {
        let connected = client.status == ClientStatus::Connected;
        let send_state = match (connected, state.has_client_handle(client.id).await) {
            (true, true) => SendState::Ready,
            (true, false) => SendState::ProtocolUnsupported,
            (false, _) => SendState::NotConnected,
        };
        let task_count = tasks
            .iter()
            .filter(|t| matches!(t.scope, crate::state::task::TaskScope::Client(cid) if cid == client.id))
            .count();
        client_rows.push(ClientRow {
            id: client.id,
            protocol: client.protocol_name.clone(),
            remote_addr: client.remote_addr.clone(),
            status: client.status.clone(),
            instruction: client.instruction.clone(),
            memory_len: client.memory.len(),
            startup_params: client.startup_params.clone(),
            routing: client.event_handler_config.clone(),
            connection: client.connection.as_ref().map(|c| ConnRow {
                id: c.id.as_u32(),
                remote_addr: c.remote_addr.clone(),
                bytes_received: c.bytes_received,
                bytes_sent: c.bytes_sent,
                active: c.status == ClientStatus::Connected,
                can_message: false,
            }),
            history: client.connection_history.iter().cloned().collect(),
            requests: client_requests
                .remove(&client.id.as_u32())
                .unwrap_or_default(),
            task_count,
            uptime_secs: client.created_at.elapsed().as_secs(),
            send_state,
            send_actions: crate::tui::modal::composer::ComposerModel::vocabulary(
                &client.protocol_name,
                state,
            )
            .into_iter()
            .filter(|action| is_initiable_action(&action.name))
            .map(|action| SendVerb {
                name: action.name,
                description: action.description,
            })
            .collect(),
            intercepts: client_intercepts
                .remove(&client.id.as_u32())
                .unwrap_or_default(),
            history_entries: client.history_entries,
            batching: client.batching,
        });
    }
    client_rows.sort_by_key(|c| c.id.as_u32());

    RailSnapshot {
        servers: server_rows,
        clients: client_rows,
        pipe_count,
        active_conversations: llm_activity.len(),
        llm_activity,
        total_input_tokens,
        total_output_tokens,
        total_llm_calls,
    }
}
