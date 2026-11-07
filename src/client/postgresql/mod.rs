//! PostgreSQL client implementation
pub mod actions;

pub use actions::PostgresqlClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::postgresql::actions::{
    POSTGRESQL_CLIENT_CONNECTED_EVENT, POSTGRESQL_CLIENT_QUERY_RESULT_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{ClientId, ClientStatus};

/// What one executed action did to the PostgreSQL connection.
enum Applied {
    /// A query ran; the rows are the JSON result set reported back to the model.
    Query {
        query: String,
        rows: Vec<serde_json::Value>,
    },
    /// The session should end.
    Disconnect,
    /// The action executed but touched the connection in no way.
    Nothing(&'static str),
}

/// How many action -> query -> result -> action turns one client will take before stopping.
///
/// The chain is genuinely self-referential, so it needs a bound rather than silence: a model
/// that answers every result with another query would otherwise run forever. Four covers
/// connect → create → insert → select → react to the rows, and a runaway costs five LLM calls
/// rather than an unbounded number. The MySQL client uses the same bound.
const MAX_FOLLOWUP_DEPTH: usize = 4;

/// PostgreSQL client that connects to a PostgreSQL server
pub struct PostgresqlClient;

impl PostgresqlClient {
    /// Connect to a PostgreSQL server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract connection parameters from startup_params if provided
        let (database, user, password) = if let Some(params) = &startup_params {
            let database = params
                .get_optional_string("database")?
                .unwrap_or_else(|| "postgres".to_string());
            let user = params
                .get_optional_string("user")?
                .unwrap_or_else(|| "postgres".to_string());
            let password = params
                .get_optional_string("password")?
                .unwrap_or_else(|| "".to_string());
            (database, user, password)
        } else {
            (
                "postgres".to_string(),
                "postgres".to_string(),
                "".to_string(),
            )
        };

        // Build connection string. `remote_addr` is NetGet's "host:port"; a libpq keyword
        // string has no such form — `host=127.0.0.1:5433` is read as a *hostname* containing
        // a colon and resolution fails, so the port has to be split out into its own keyword.
        let (host, port) = match remote_addr.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => (remote_addr.clone(), 5432),
            },
            None => (remote_addr.clone(), 5432),
        };
        let conn_str = if password.is_empty() {
            format!(
                "host={} port={} user={} dbname={}",
                host, port, user, database
            )
        } else {
            format!(
                "host={} port={} user={} password={} dbname={}",
                host, port, user, password, database
            )
        };

        info!(
            "PostgreSQL client {} connecting to {} (user={}, database={})",
            client_id, remote_addr, user, database
        );

        // Connect to PostgreSQL server
        let (client, connection) = tokio_postgres::connect(&conn_str, tokio_postgres::NoTls)
            .await
            .context(format!(
                "Failed to connect to PostgreSQL at {}",
                remote_addr
            ))?;

        // Get the local address from the connection's underlying socket
        // Note: tokio-postgres doesn't expose local_addr directly, so we parse from remote_addr
        let local_addr: SocketAddr = format!("{}:0", host)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());

        info!(
            "PostgreSQL client {} connected to {}",
            client_id, remote_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] PostgreSQL client {} connected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Spawn connection task
        let status_tx_clone = status_tx.clone();
        let connection_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("PostgreSQL client {} connection error: {}", client_id, e);
                let _ = status_tx_clone.send(format!(
                    "[CLIENT] PostgreSQL client {} connection error: {}",
                    client_id, e
                ));
            }
        });
        app_state
            .register_client_task(client_id, connection_handle)
            .await;

        // The driver's `Client` is shared: the connected-event LLM task and the injected
        // command loop both issue queries through it. Holding it in the command loop is
        // also what keeps the session alive for a client with no instruction.
        let client_arc = Arc::new(client);
        let protocol = Arc::new(PostgresqlClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes — the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            client_arc.clone(),
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Send connected event to LLM
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &POSTGRESQL_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                    "database": database,
                    "user": user,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            let protocol_clone = protocol.clone();
            let client_arc_clone = client_arc.clone();
            let llm_client_clone = llm_client.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            let task_registrar = app_state.clone();
            let handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client_clone,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    protocol_clone.as_ref(),
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
                            if let Err(e) = Self::execute_llm_action(
                                client_id,
                                action,
                                &protocol_clone,
                                &client_arc_clone,
                                &app_state_clone,
                                &llm_client_clone,
                                &status_tx_clone,
                                0,
                            )
                            .await
                            {
                                error!("Error executing PostgreSQL action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for PostgreSQL client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar.register_client_task(client_id, handle).await;
        }

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (the client was removed or stopped)
    /// or an injected `disconnect` ends the session.
    ///
    /// `tokio_postgres` owns the socket, so `execute_query` yields
    /// `ClientActionResult::Custom` and the generic split-stream arm cannot serve it; the
    /// effect goes through [`Self::apply_action`], the same function the LLM path uses.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<PostgresqlClientProtocol>,
        pg_client: Arc<tokio_postgres::Client>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let mut follow_up: Option<(String, Vec<serde_json::Value>)> = None;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => match Self::apply_action(result, &pg_client, client_id).await {
                    Err(e) => Err(e),
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Ok(Applied::Nothing(what)) => Ok(ClientSendOutcome::Executed {
                        detail: what.to_string(),
                    }),
                    Ok(Applied::Query { query, rows }) => {
                        let detail = format!(
                            "query executed by tokio_postgres ({} rows); \
                             no byte count — the driver owns the socket: {}",
                            rows.len(),
                            crate::utils::truncate::truncate_for_log(&query, 80)
                        );
                        follow_up = Some((query, rows));
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
                    "PostgreSQL client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::mark_disconnected(client_id, &app_state, &status_tx).await;
                break;
            }

            // The model sees the result of a user-injected query exactly as it sees one it
            // asked for — after the reply, so the dashboard is not held for an LLM round-trip.
            if let Some((query, rows)) = follow_up {
                Self::report_query_result(
                    client_id,
                    &query,
                    rows,
                    &pg_client,
                    &protocol,
                    &app_state,
                    &llm_client,
                    &status_tx,
                    0,
                )
                .await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one action produced by the model and, if it ran a query, report the rows back.
    ///
    /// Returns an explicitly boxed `+ Send` future rather than being an `async fn`: this and
    /// [`Self::report_query_result`] call each other (a query's rows go to the model, whose
    /// answer may be another query), and naming the type is what lets the compiler prove
    /// `Send` for the cycle — required because the chain runs inside a `tokio::spawn`. The
    /// cycle is bounded by [`MAX_FOLLOWUP_DEPTH`].
    #[allow(clippy::too_many_arguments)]
    fn execute_llm_action<'a>(
        client_id: ClientId,
        action: serde_json::Value,
        protocol: &'a Arc<PostgresqlClientProtocol>,
        pg_client: &'a Arc<tokio_postgres::Client>,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match Self::apply_action(protocol.execute_action(action)?, pg_client, client_id).await {
                Ok(Applied::Query { query, rows }) => {
                    Self::report_query_result(
                        client_id, &query, rows, pg_client, protocol, app_state, llm_client,
                        status_tx, depth,
                    )
                    .await;
                }
                Ok(Applied::Disconnect) => {
                    info!("PostgreSQL client {} disconnecting", client_id);
                    Self::mark_disconnected(client_id, app_state, status_tx).await;
                }
                Ok(Applied::Nothing(what)) => {
                    trace!(
                        "PostgreSQL client {} action had no effect: {}",
                        client_id,
                        what
                    );
                }
                Err(e) => {
                    error!("PostgreSQL client {} query error: {}", client_id, e);
                    let _ = status_tx.send(format!(
                        "[CLIENT] PostgreSQL client {} query error: {}",
                        client_id, e
                    ));
                }
            }
            Ok(())
        })
    }

    /// Run one executed action against the connection. Shared by the LLM path and injected
    /// commands so the query path exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        pg_client: &Arc<tokio_postgres::Client>,
        client_id: ClientId,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "pg_query" => {
                let query = data
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' in pg_query action data")?
                    .to_string();

                trace!("PostgreSQL client {} executing: {}", client_id, query);

                // `query` takes `&self`: tokio_postgres pipelines requests over its own
                // connection task, so the client is shared by `Arc` and no lock is held
                // across the round-trip to the server.
                let rows = pg_client
                    .query(query.as_str(), &[])
                    .await
                    .context("Failed to execute query")?;

                let result = rows
                    .iter()
                    .map(|row| {
                        let mut obj = serde_json::Map::new();
                        for (idx, col) in row.columns().iter().enumerate() {
                            obj.insert(col.name().to_string(), pg_cell_to_json(row, idx));
                        }
                        serde_json::Value::Object(obj)
                    })
                    .collect::<Vec<_>>();

                info!(
                    "PostgreSQL client {} query returned {} rows",
                    client_id,
                    result.len()
                );

                Ok(Applied::Query {
                    query,
                    rows: result,
                })
            }
            ClientActionResult::Custom { name, .. } => {
                trace!(
                    "PostgreSQL client {} ignoring custom result '{}'",
                    client_id,
                    name
                );
                Ok(Applied::Nothing("custom result not handled by this client"))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more")),
            ClientActionResult::NoAction => Ok(Applied::Nothing("no_action")),
            ClientActionResult::SendData(_) => Ok(Applied::Nothing(
                "send_data is not meaningful for a tokio_postgres connection",
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Nothing(
                "multiple results not handled by this client",
            )),
        }
    }

    /// Raise `postgresql_query_result` with a query's rows and run whatever the model answers.
    ///
    /// The answer is **executed** through [`Self::execute_llm_action`], so a follow-up query's
    /// own rows come back to the model in turn: connect → `CREATE TABLE` → `INSERT` → `SELECT`
    /// → react to the rows is a chain of four results, each decided by the model after it has
    /// seen the previous one. The chain stops at [`MAX_FOLLOWUP_DEPTH`]; past it the model's
    /// actions are dropped with a warning rather than looping.
    #[allow(clippy::too_many_arguments)]
    async fn report_query_result(
        client_id: ClientId,
        query: &str,
        rows: Vec<serde_json::Value>,
        pg_client: &Arc<tokio_postgres::Client>,
        protocol: &Arc<PostgresqlClientProtocol>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let event = Event::new(
            &POSTGRESQL_CLIENT_QUERY_RESULT_EVENT,
            serde_json::json!({
                "query": query,
                "rows": rows,
                "row_count": rows.len(),
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        // `match`, not `if let Ok(..)`: a client that goes quiet because its model failed
        // should say so.
        let (actions, memory_updates) = match call_llm_for_client(
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
            }) => (actions, memory_updates),
            Err(e) => {
                error!(
                    "LLM error for PostgreSQL client {} on a query result: {}",
                    client_id, e
                );
                return;
            }
        };
        if let Some(mem) = memory_updates {
            app_state.set_memory_for_client(client_id, mem).await;
        }
        if actions.is_empty() {
            return;
        }
        if depth >= MAX_FOLLOWUP_DEPTH {
            warn!(
                "PostgreSQL client {} reached the follow-up depth bound ({}); dropping {} \
                 action(s) rather than looping",
                client_id,
                MAX_FOLLOWUP_DEPTH,
                actions.len()
            );
            return;
        }
        for action in actions {
            if let Err(e) = Self::execute_llm_action(
                client_id,
                action,
                protocol,
                pg_client,
                app_state,
                llm_client,
                status_tx,
                depth + 1,
            )
            .await
            {
                error!(
                    "PostgreSQL client {} rejected its own follow-up action: {}",
                    client_id, e
                );
            }
        }
    }

    /// Mark the client disconnected **and** stop offering to send on it.
    ///
    /// Dropping the command handle closes the channel, which ends `command_loop`; without it
    /// an LLM-requested `disconnect` left the client drawn as `Disconnected` while the loop
    /// still ran and the dashboard still offered `[ send ]`. Only the *injected* disconnect
    /// path ended the loop, because it breaks out of it directly.
    ///
    /// `tokio_postgres::Client` closes when the last handle drops, and it is an `Arc` shared
    /// with `command_loop`, so ending that loop is what releases it.
    async fn mark_disconnected(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        app_state.remove_client_handle(client_id).await;
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] PostgreSQL client {} disconnected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Read one cell as JSON without ever panicking.
///
/// This used to be `let value: Option<String> = row.get(idx)`. `tokio_postgres::Row::get`
/// **panics** when the column's type has no `FromSql` impl for the requested Rust type, and
/// `Option<String>` only accepts the text-ish types — so a single `int4`, `bool` or `float8`
/// column panicked the whole query.
///
/// That panic happened inside a `tokio::spawn`, which swallows it: nothing was logged, the
/// client stayed `Connected`, no `postgresql_query_result` event was raised, and the model
/// simply never heard back. It is the exact failure shape the root CLAUDE.md records for
/// `block_on` in usb-msc and SMB — the task dies quietly and the peer waits forever.
///
/// `try_get` is the non-panicking form. Types are tried in declared order and the final
/// fallback is JSON null, so an unknown OID costs one null cell rather than the query.
fn pg_cell_to_json(row: &tokio_postgres::Row, idx: usize) -> serde_json::Value {
    use tokio_postgres::types::Type;

    macro_rules! try_as {
        ($t:ty) => {
            if let Ok(v) = row.try_get::<_, Option<$t>>(idx) {
                return serde_json::json!(v);
            }
        };
    }

    match *row.columns()[idx].type_() {
        Type::BOOL => try_as!(bool),
        Type::INT2 => try_as!(i16),
        Type::INT4 => try_as!(i32),
        Type::INT8 => try_as!(i64),
        Type::FLOAT4 => try_as!(f32),
        Type::FLOAT8 => try_as!(f64),
        _ => {}
    }
    // Text and everything text-shaped, then give up rather than panic.
    try_as!(String);
    serde_json::Value::Null
}
