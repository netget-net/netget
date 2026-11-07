//! Cassandra client implementation using ScyllaDB Rust driver
pub mod actions;

pub use actions::CassandraClientProtocol;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

use crate::client::cassandra::actions::{
    CASSANDRA_CLIENT_CONNECTED_EVENT, CASSANDRA_CLIENT_RESULT_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{ClientId, ClientStatus};
use serde_json::json;

use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::frame::Compression;

/// What one executed action did to the Cassandra session.
enum Applied {
    /// A CQL statement ran; the rows are what the model is told about.
    Query {
        query: String,
        rows: Vec<serde_json::Value>,
        row_count: usize,
    },
    /// The session should end.
    Disconnect,
    /// The action executed but touched the session in no way.
    Nothing(&'static str),
}

/// How many query → result → query hops one action may set off.
///
/// `report_result` asks the model what to do with a result set, and the answer may be another
/// query, whose result is reported in turn. The recursion was boxed but **not bounded**: a
/// model that answers every result with another query looped for as long as the LLM budget
/// lasted, hammering the server with no way to stop short of the client being removed. Boxing
/// only makes the type finite; the cap is what makes the chain finite.
const MAX_FOLLOWUP_DEPTH: u8 = 6;

/// Map a CQL consistency-level name onto the driver's enum.
///
/// Names are the ones the native protocol and every driver use. Anything else returns `None`
/// so the caller can refuse: silently running at the session default would serve a weaker
/// guarantee than the model asked for.
fn parse_consistency(name: &str) -> Option<scylla::frame::types::Consistency> {
    use scylla::frame::types::Consistency;
    match name.trim().to_ascii_uppercase().as_str() {
        "ANY" => Some(Consistency::Any),
        "ONE" => Some(Consistency::One),
        "TWO" => Some(Consistency::Two),
        "THREE" => Some(Consistency::Three),
        "QUORUM" => Some(Consistency::Quorum),
        "ALL" => Some(Consistency::All),
        "LOCAL_QUORUM" => Some(Consistency::LocalQuorum),
        "EACH_QUORUM" => Some(Consistency::EachQuorum),
        "SERIAL" => Some(Consistency::Serial),
        "LOCAL_SERIAL" => Some(Consistency::LocalSerial),
        "LOCAL_ONE" => Some(Consistency::LocalOne),
        _ => None,
    }
}

/// Cassandra client that connects to a Cassandra/ScyllaDB server
pub struct CassandraClient;

impl CassandraClient {
    /// Connect to a Cassandra server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse startup parameters
        let keyspace = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("keyspace"))
            .transpose()?
            .flatten();

        let username = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("username"))
            .transpose()?
            .flatten();

        let password = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("password"))
            .transpose()?
            .flatten();

        info!(
            "Cassandra client {} connecting to {}",
            client_id, remote_addr
        );

        // Build session
        let mut builder = SessionBuilder::new()
            .known_node(&remote_addr)
            .compression(Some(Compression::Lz4));

        // Add authentication if provided
        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.user(&user, &pass);
        }

        // Set keyspace if provided
        if let Some(ks) = &keyspace {
            builder = builder.use_keyspace(ks, false);
        }

        // Connect to Cassandra
        let session = builder
            .build()
            .await
            .context(format!("Failed to connect to Cassandra at {}", remote_addr))?;

        // `Session` is `Sync` and every query method takes `&self`, so a bare `Arc` is enough
        // to share it between the LLM path and the injected-command loop — no mutex needed.
        let session_arc = Arc::new(session);
        let protocol = Arc::new(CassandraClientProtocol::new());

        // Parse address to get SocketAddr
        let socket_addr: SocketAddr = remote_addr
            .parse()
            .context(format!("Invalid address format: {}", remote_addr))?;

        info!(
            "Cassandra client {} connected to {}",
            client_id, socket_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] Cassandra client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call, which this protocol *awaits inline*
        // — so under a manual `*` rule the call below parks and client creation parks with
        // it. The command loop is a separate task precisely so [ send ] still works then.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            session_arc.clone(),
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &CASSANDRA_CLIENT_CONNECTED_EVENT,
                json!({
                    "remote_addr": remote_addr,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            // Initial LLM call after connection
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

                    // Execute initial actions
                    Self::execute_actions(
                        actions,
                        protocol.clone(),
                        session_arc.clone(),
                        client_id,
                        llm_client.clone(),
                        app_state.clone(),
                        status_tx.clone(),
                        0,
                    )
                    .await;
                }
                Err(e) => {
                    error!(
                        "Initial LLM call error for Cassandra client {}: {}",
                        client_id, e
                    );
                }
            }
        }

        Ok(socket_addr)
    }

    /// Drain injected commands until the channel closes (the client was removed or stopped)
    /// or an injected `disconnect` ends the session.
    ///
    /// This task is also what keeps the session alive: before it existed the only `Arc<Session>`
    /// belonged to the connect-time LLM path and was dropped when `connect_with_llm_actions`
    /// returned.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<CassandraClientProtocol>,
        session: Arc<Session>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let mut follow_up: Option<(Vec<serde_json::Value>, usize)> = None;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => match Self::apply_action(result, &session, client_id).await {
                    Err(e) => Err(e),
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Ok(Applied::Nothing(what)) => Ok(ClientSendOutcome::Executed {
                        detail: what.to_string(),
                    }),
                    Ok(Applied::Query {
                        query,
                        rows,
                        row_count,
                    }) => {
                        let detail = format!(
                            "CQL executed by the scylla driver ({} rows); \
                             no byte count — the driver owns the socket: {}",
                            row_count,
                            crate::utils::truncate::truncate_for_log(&query, 80)
                        );
                        follow_up = Some((rows, row_count));
                        Ok(ClientSendOutcome::Executed { detail })
                    }
                },
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
                    "Cassandra client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::mark_disconnected(client_id, &app_state, &status_tx).await;
                break;
            }

            // The model sees an injected query's result exactly as it sees one it asked for —
            // after the reply, so the dashboard is not held for an LLM round-trip.
            if let Some((rows, row_count)) = follow_up {
                Self::report_result(
                    rows,
                    row_count,
                    &protocol,
                    &session,
                    client_id,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    0,
                )
                .await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute a list of actions returned by the LLM.
    ///
    /// `depth` is how many follow-up hops led here; 0 for the connected event and for an
    /// injected command. See [`MAX_FOLLOWUP_DEPTH`].
    #[allow(clippy::too_many_arguments)]
    async fn execute_actions(
        actions: Vec<serde_json::Value>,
        protocol: Arc<CassandraClientProtocol>,
        session: Arc<Session>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        depth: u8,
    ) {
        for action in actions {
            let result = match protocol.execute_action(action) {
                Ok(result) => result,
                Err(e) => {
                    error!("Cassandra client {} action error: {}", client_id, e);
                    continue;
                }
            };

            match Self::apply_action(result, &session, client_id).await {
                Ok(Applied::Query {
                    rows,
                    row_count,
                    query,
                }) => {
                    if depth >= MAX_FOLLOWUP_DEPTH {
                        let log = Log::to(&status_tx);
                        log.warn(format!(
                            "Cassandra client {} hit the follow-up depth limit ({}); the last \
                             query ran and returned {} row(s) but its rows were not reported, \
                             so the model will not answer it",
                            client_id, MAX_FOLLOWUP_DEPTH, row_count
                        ));
                        log.debug(format!(
                            "Cassandra client {} follow-up chain stopped at depth {} after \
                             '{}'",
                            client_id, depth, query
                        ));
                    } else {
                        Self::report_result(
                            rows,
                            row_count,
                            &protocol,
                            &session,
                            client_id,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            depth,
                        )
                        .await;
                    }
                }
                Ok(Applied::Disconnect) => {
                    info!("Cassandra client {} disconnecting", client_id);
                    Self::mark_disconnected(client_id, &app_state, &status_tx).await;
                    break;
                }
                Ok(Applied::Nothing(what)) => {
                    debug!(
                        "Cassandra client {} action had no effect: {}",
                        client_id, what
                    );
                }
                Err(e) => {
                    error!("Cassandra client {} query error: {}", client_id, e);
                    let _ = status_tx.send(format!("[CLIENT] Cassandra query error: {}", e));
                }
            }
        }
    }

    /// Run one executed action against the session. Shared by the LLM path and injected
    /// commands so the CQL execution path exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        session: &Arc<Session>,
        client_id: ClientId,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "cql_query" => {
                let query_str = data
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' in cql_query action data")?
                    .to_string();

                // `consistency` is advertised to the model as a parameter of
                // `execute_cql_query`, so it has to reach the wire. It used to be read, logged
                // and dropped under a comment claiming scylla exposes no per-statement
                // override; `scylla::statement::unprepared::Statement::set_consistency` is
                // exactly that, and `query_unpaged` takes `impl Into<Statement>`. A model
                // asking for QUORUM was silently served at the session default, which for
                // scylla is LOCAL_QUORUM — a different durability guarantee than the one
                // requested, reported in the log as though it had been honoured.
                let mut statement =
                    scylla::statement::unprepared::Statement::new(query_str.clone());
                let requested = data.get("consistency").and_then(|v| v.as_str());
                if let Some(name) = requested {
                    // An unrecognised level is refused rather than quietly downgraded: running
                    // at a weaker consistency than asked for is the failure this fixes.
                    let level = parse_consistency(name).ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown consistency level '{name}'; use one of ANY, ONE, TWO, \
                             THREE, QUORUM, ALL, LOCAL_QUORUM, EACH_QUORUM, SERIAL, \
                             LOCAL_SERIAL, LOCAL_ONE"
                        )
                    })?;
                    statement.set_consistency(level);
                }
                debug!(
                    "Cassandra client {} executing query (consistency {}): {}",
                    client_id,
                    requested.unwrap_or("session default"),
                    query_str
                );

                let query_result = session
                    .query_unpaged(statement, &[])
                    .await
                    .context("CQL query failed")?;

                // Converted inline rather than in a helper so the driver's `QueryResult`
                // type never has to be named (its module path moves between scylla releases).
                let (rows, row_count) = {
                    use scylla::value::Row;
                    match query_result.into_rows_result() {
                        Ok(rows_result) => match rows_result.rows::<Row>() {
                            Ok(rows_iter) => {
                                let collected: Vec<_> =
                                    rows_iter.collect::<Result<Vec<_>, _>>().unwrap_or_default();
                                let count = collected.len();
                                let data: Vec<serde_json::Value> = collected
                                    .into_iter()
                                    .map(|row| {
                                        let columns: Vec<String> = (0..row.columns.len())
                                            .map(|i| format!("{:?}", row.columns[i]))
                                            .collect();
                                        json!({ "columns": columns })
                                    })
                                    .collect();
                                (data, count)
                            }
                            Err(e) => {
                                debug!(
                                    "Cassandra client {} result deserialization error: {}",
                                    client_id, e
                                );
                                (
                                    vec![json!({
                                        "message": "Query succeeded but result parsing not supported for this schema",
                                        "error": format!("{}", e),
                                    })],
                                    0,
                                )
                            }
                        },
                        Err(e) => {
                            // Not a rows result (e.g. INSERT / UPDATE / DELETE succeeded)
                            debug!(
                                "Cassandra client {} query succeeded (non-SELECT): {}",
                                client_id, e
                            );
                            (Vec::new(), 0)
                        }
                    }
                };
                trace!("Cassandra client {} received {} rows", client_id, row_count);

                Ok(Applied::Query {
                    query: query_str,
                    rows,
                    row_count,
                })
            }
            ClientActionResult::Custom { name, .. } => {
                debug!(
                    "Cassandra client {} ignoring custom result '{}'",
                    client_id, name
                );
                Ok(Applied::Nothing("custom result not handled by this client"))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more")),
            ClientActionResult::NoAction => Ok(Applied::Nothing("no_action")),
            ClientActionResult::SendData(_) => Ok(Applied::Nothing(
                "send_data is not meaningful for a scylla session",
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Nothing(
                "multiple results not handled by this client",
            )),
        }
    }

    /// Raise `cassandra_result_received` and run whatever the model answers.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn report_result(
        rows_data: Vec<serde_json::Value>,
        row_count: usize,
        protocol: &Arc<CassandraClientProtocol>,
        session: &Arc<Session>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: u8,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let event = Event::new(
            &CASSANDRA_CLIENT_RESULT_RECEIVED_EVENT,
            json!({
                "rows": rows_data,
                "row_count": row_count,
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

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
                actions: next_actions,
                memory_updates,
            }) => {
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Execute next actions. Boxed because an `async fn` that awaits itself has
                // an infinitely-sized future; bounded by `MAX_FOLLOWUP_DEPTH` because boxing
                // alone leaves the *chain* unbounded, which is the part that mattered.
                Box::pin(Self::execute_actions(
                    next_actions,
                    protocol.clone(),
                    session.clone(),
                    client_id,
                    llm_client.clone(),
                    app_state.clone(),
                    status_tx.clone(),
                    depth + 1,
                ))
                .await;
            }
            Err(e) => {
                error!("LLM error for Cassandra client {}: {}", client_id, e);
            }
        }
    }

    async fn mark_disconnected(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Cassandra client {} disconnected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}
