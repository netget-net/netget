//! MySQL client implementation
pub mod actions;

pub use actions::MysqlClientProtocol;

use anyhow::{Context, Result};
use mysql_async::{prelude::*, Conn, OptsBuilder, Row};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::mysql::actions::{
    MYSQL_CLIENT_CONNECTED_EVENT, MYSQL_CLIENT_RESULT_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{ClientId, ClientStatus};

/// What one executed action did to the MySQL connection.
///
/// Returned by [`MysqlClient::apply_action`], which is the single place a `mysql_query`
/// reaches the server — the connected-event LLM path and injected dashboard commands both
/// go through it.
enum Applied {
    /// A query ran; what the server said about it is reported back to the model.
    Query(QueryOutcome),
    /// The session should end.
    Disconnect,
    /// The action executed but touched the connection in no way.
    Nothing(&'static str),
}

/// What the server returned for one query.
///
/// `affected_rows` and `last_insert_id` come from the server's OK packet, read off the
/// connection before its guard is released, not derived from the result set: an `INSERT`
/// returns no rows and affects one, and a `SELECT` returns rows and affects none.
struct QueryOutcome {
    query: String,
    rows: Vec<serde_json::Value>,
    affected_rows: u64,
    last_insert_id: Option<u64>,
}

/// How many action -> query -> result -> action turns one client will take before stopping.
///
/// The chain is genuinely self-referential, so it needs a bound rather than silence: a model
/// that answers every result with another query would otherwise run forever. Four is enough
/// for the flows this client is for (connect, query, react to the rows, one more query) and
/// small enough that a runaway costs four LLM calls rather than an unbounded number.
const MAX_FOLLOWUP_DEPTH: usize = 4;

/// MySQL client that connects to a MySQL server
pub struct MysqlClient;

impl MysqlClient {
    /// Connect to a MySQL server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // `get_optional_string`, not `get_string`. All three parameters are declared
        // `required: false`, but `get_string` **errors when the key is absent** ("Required
        // string parameter '{}' is missing or not a string"), and `.transpose()?` propagates
        // that. So the `unwrap_or_else` defaults only ever applied when `startup_params` was
        // `None` *entirely*: pass any subset and connecting failed.
        //
        // The dashboard makes that the normal case, not a corner one - `ServerForm`/
        // `ClientForm` omit blank fields and return `None` only when nothing at all was
        // filled in - so filling in just `database` on the MySQL create form failed with
        // "Required string parameter 'username' is missing". The PostgreSQL client already
        // used the optional accessor.
        let username = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("username"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "root".to_string());
        let password = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("password"))
            .transpose()?
            .flatten()
            .unwrap_or_default();
        let database: Option<String> = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("database"))
            .transpose()?
            .flatten();

        // Parse remote_addr to get host and port
        let (host, port) = if let Some((h, p)) = remote_addr.split_once(':') {
            (h.to_string(), p.parse::<u16>().context("Invalid port")?)
        } else {
            (remote_addr.clone(), 3306)
        };

        // Build MySQL connection options.
        //
        // `max_allowed_packet` / `wait_timeout` / `prefer_socket` are pinned deliberately.
        // Left unset, `Conn::new` asks the server for `@@max_allowed_packet`,
        // `@@wait_timeout` and `@@socket` and feeds each answer to `from_value`, which
        // **panics** rather than erroring when the value is not the type it expects. The
        // server at the other end of a NetGet client is frequently one whose replies a model
        // composed, so that panic is reachable from an ordinary LLM answer. Supplying the
        // values here means the settings query is never issued. `prefer_socket(false)` is
        // right on its own terms too: the user gave us a TCP address to use.
        let mut opts_builder = OptsBuilder::default()
            .ip_or_hostname(&host)
            .tcp_port(port)
            .user(Some(&username))
            .pass(Some(&password))
            .max_allowed_packet(Some(16 * 1024 * 1024))
            .wait_timeout(Some(28800))
            .prefer_socket(false);

        if let Some(db) = database.as_ref() {
            opts_builder = opts_builder.db_name(Some(db.as_str()));
        }

        // Connect to MySQL server
        let conn = Conn::new(opts_builder)
            .await
            .context(format!("Failed to connect to MySQL at {}", remote_addr))?;

        info!("MySQL client {} connected to {}", client_id, remote_addr);

        // For SocketAddr, we'll create a fake one since mysql_async doesn't expose the actual socket
        // We'll parse the remote_addr to create a SocketAddr
        let socket_addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .context("Failed to parse socket address")?;

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] MySQL client {} connected to {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap connection in Arc<Mutex> for shared access. The command loop below holds a
        // clone, which is also what keeps the connection alive: before it existed, a client
        // with no instruction dropped its only `Conn` the moment this function returned.
        let conn_arc = Arc::new(Mutex::new(conn));
        let protocol = Arc::new(MysqlClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes — the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            conn_arc.clone(),
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &MYSQL_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            let protocol_clone = protocol.clone();
            let conn_clone = conn_arc.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            let task_registrar = app_state.clone();
            let handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
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
                                &conn_clone,
                                &app_state_clone,
                                &llm_client,
                                &status_tx_clone,
                                0,
                            )
                            .await
                            {
                                error!("Error executing MySQL action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for MySQL client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar.register_client_task(client_id, handle).await;
        }

        Ok(socket_addr)
    }

    /// Drain injected commands until the channel closes (the client was removed or stopped)
    /// or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// there is no socket NetGet owns — `mysql_async` does — so `execute_query` yields
    /// `ClientActionResult::Custom` and the effect goes through the shared
    /// [`Self::apply_action`], the same function the LLM path uses.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<MysqlClientProtocol>,
        conn: Arc<Mutex<Conn>>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let mut follow_up: Option<QueryOutcome> = None;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => {
                    match Self::apply_action(result, &conn, client_id, &app_state, &status_tx).await
                    {
                        Err(e) => Err(e),
                        Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                        Ok(Applied::Nothing(what)) => Ok(ClientSendOutcome::Executed {
                            detail: what.to_string(),
                        }),
                        Ok(Applied::Query(outcome)) => {
                            let detail = format!(
                                "query executed by mysql_async ({} rows, {} affected); \
                                 no byte count — the driver owns the socket: {}",
                                outcome.rows.len(),
                                outcome.affected_rows,
                                crate::utils::truncate::truncate_for_log(&outcome.query, 80)
                            );
                            follow_up = Some(outcome);
                            Ok(ClientSendOutcome::Executed { detail })
                        }
                    }
                }
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
                    "MySQL client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::mark_disconnected(client_id, &app_state, &status_tx).await;
                break;
            }

            // The model must see the result of a user-injected query exactly as it sees the
            // result of one it asked for. Done *after* the reply so the dashboard is not
            // blocked for the length of an LLM round-trip.
            if let Some(outcome) = follow_up {
                Self::report_query_result(
                    client_id,
                    outcome,
                    &protocol,
                    &conn,
                    &app_state,
                    &llm_client,
                    &status_tx,
                    0,
                )
                .await;
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a client whose loop is gone.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute an action from the LLM
    /// Execute one action from the model and, if it was a query, feed the rows back.
    ///
    /// Returns an explicitly boxed `+ Send` future rather than being an `async fn`. That is
    /// not style: this and `report_query_result` call each other, and with two `async fn`s the
    /// compiler has to prove `Send` for each in terms of the other and gives up
    /// ("future cannot be sent between threads safely ... cannot satisfy `impl Future: Send`").
    /// Naming the type here breaks the cycle, and `+ Send` is required anyway because this is
    /// awaited inside a `tokio::spawn`.
    #[allow(clippy::too_many_arguments)]
    fn execute_llm_action<'a>(
        client_id: ClientId,
        action: serde_json::Value,
        protocol: &'a Arc<MysqlClientProtocol>,
        conn: &'a Arc<Mutex<Conn>>,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match Self::apply_action(
                protocol.execute_action(action)?,
                conn,
                client_id,
                app_state,
                status_tx,
            )
            .await?
            {
                Applied::Query(outcome) => {
                    Self::report_query_result(
                        client_id, outcome, protocol, conn, app_state, llm_client, status_tx, depth,
                    )
                    .await;
                }
                Applied::Disconnect => {
                    info!("MySQL client {} disconnecting", client_id);
                    Self::mark_disconnected(client_id, app_state, status_tx).await;
                }
                Applied::Nothing(what) => {
                    trace!("MySQL client {} action had no effect: {}", client_id, what);
                }
            }
            Ok(())
        })
    }

    /// Put one executed action on the connection. Shared by the connected-event LLM path and
    /// injected commands so the query path exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        conn: &Arc<Mutex<Conn>>,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "mysql_query" => {
                let query_str = data
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' in mysql_query action data")?
                    .to_string();

                trace!("MySQL client {} executing query: {}", client_id, query_str);

                // The OK packet's counters live on the connection and are overwritten by the
                // next query, so they are read under the same guard as the query itself.
                let result: Result<(Vec<Row>, u64, Option<u64>)> = {
                    let mut conn_guard = conn.lock().await;
                    match conn_guard.query(&query_str).await {
                        Ok(rows) => Ok((
                            rows,
                            conn_guard.affected_rows(),
                            conn_guard.last_insert_id(),
                        )),
                        Err(e) => Err(anyhow::Error::from(e).context("Failed to execute query")),
                    }
                };

                match result {
                    Ok((rows, affected_rows, last_insert_id)) => {
                        let json_rows = rows_to_json(&rows);
                        info!(
                            "MySQL client {} query returned {} rows, {} affected",
                            client_id,
                            json_rows.len(),
                            affected_rows
                        );
                        Ok(Applied::Query(QueryOutcome {
                            query: query_str,
                            rows: json_rows,
                            affected_rows,
                            last_insert_id: last_insert_id.filter(|id| *id != 0),
                        }))
                    }
                    Err(e) => {
                        error!("MySQL client {} query error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        Err(e)
                    }
                }
            }
            ClientActionResult::Custom { name, .. } => {
                trace!(
                    "MySQL client {} ignoring custom result '{}'",
                    client_id,
                    name
                );
                Ok(Applied::Nothing("custom result not handled by this client"))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more")),
            ClientActionResult::NoAction => Ok(Applied::Nothing("no_action")),
            ClientActionResult::SendData(_) => Ok(Applied::Nothing(
                "send_data is not meaningful for a mysql_async connection",
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Nothing(
                "multiple results not handled by this client",
            )),
        }
    }

    /// Raise `mysql_result_received` with a query's rows and run whatever the model answers.
    ///
    /// The answer is **executed**, not merely decoded. It used to be decoded and dropped: the
    /// loop called `protocol.execute_action(..)`, which is pure - it returns a
    /// `ClientActionResult::Custom { name: "mysql_query", .. }` and nothing put it on the
    /// connection - and then matched everything but `Disconnect` into a `trace!`. So a model
    /// answering `mysql_result_received` with `execute_query` (which this client advertises in
    /// both its async and sync sets) issued no query and sent no bytes, on the LLM path and on
    /// the dashboard's `[ send ]` path alike. A comment above it explained that "more complex
    /// flows can be handled by the LLM in the instruction", which is the
    /// explaining-why-the-answer-is-not-needed idiom the root CLAUDE.md names as this exact
    /// bug.
    ///
    /// Closing the loop makes it self-referential - `execute_llm_action` runs a query, which
    /// reports its result here, which may run another. `execute_llm_action` therefore returns
    /// an explicitly boxed `+ Send` future (see its own comment) and the chain is bounded by
    /// `MAX_FOLLOWUP_DEPTH`.
    #[allow(clippy::too_many_arguments)]
    async fn report_query_result(
        client_id: ClientId,
        outcome: QueryOutcome,
        protocol: &Arc<MysqlClientProtocol>,
        conn: &Arc<Mutex<Conn>>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let mut data = serde_json::json!({
            "query": outcome.query,
            "result": outcome.rows,
            "row_count": outcome.rows.len(),
            "affected_rows": outcome.affected_rows,
        });
        if let Some(id) = outcome.last_insert_id {
            data["last_insert_id"] = serde_json::json!(id);
        }
        let event = Event::new(&MYSQL_CLIENT_RESULT_RECEIVED_EVENT, data);

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
                actions,
                memory_updates,
            }) => {
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                if actions.is_empty() {
                    return;
                }
                if depth >= MAX_FOLLOWUP_DEPTH {
                    warn!(
                        "MySQL client {} reached the follow-up depth bound ({}); dropping {} \
                         action(s) rather than looping. A model answering every result with \
                         another query would otherwise never stop.",
                        client_id,
                        MAX_FOLLOWUP_DEPTH,
                        actions.len()
                    );
                    return;
                }

                for new_action in actions {
                    if let Err(e) = Self::execute_llm_action(
                        client_id,
                        new_action,
                        protocol,
                        conn,
                        app_state,
                        llm_client,
                        status_tx,
                        depth + 1,
                    )
                    .await
                    {
                        error!(
                            "MySQL client {} failed to execute a follow-up action: {}",
                            client_id, e
                        );
                    }
                }
            }
            Err(e) => {
                error!("LLM error for MySQL client {}: {}", client_id, e);
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
    /// `mysql_async`'s `Conn` is closed by dropping it, and it is held behind an
    /// `Arc<Mutex<..>>` shared with `command_loop`, so ending that loop is what releases the
    /// last handle and with it the TCP session.
    async fn mark_disconnected(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        app_state.remove_client_handle(client_id).await;
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] MySQL client {} disconnected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Convert a MySQL result set into the JSON rows reported to the model.
fn rows_to_json(rows: &[Row]) -> Vec<serde_json::Value> {
    rows.iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (idx, col) in row.columns_ref().iter().enumerate() {
                let value = match row.as_ref(idx) {
                    Some(mysql_async::Value::NULL) => serde_json::Value::Null,
                    Some(mysql_async::Value::Bytes(b)) => {
                        serde_json::Value::String(String::from_utf8_lossy(b).to_string())
                    }
                    Some(mysql_async::Value::Int(i)) => serde_json::Value::Number((*i).into()),
                    Some(mysql_async::Value::UInt(u)) => serde_json::Value::Number((*u).into()),
                    Some(mysql_async::Value::Float(f)) => serde_json::Number::from_f64(*f as f64)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null),
                    Some(mysql_async::Value::Double(d)) => serde_json::Number::from_f64(*d)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null),
                    Some(mysql_async::Value::Date(y, m, d, h, min, s, us)) => {
                        serde_json::Value::String(format!(
                            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                            y, m, d, h, min, s, us
                        ))
                    }
                    Some(mysql_async::Value::Time(is_neg, d, h, m, s, us)) => {
                        let sign = if *is_neg { "-" } else { "" };
                        serde_json::Value::String(format!(
                            "{}{} {:02}:{:02}:{:02}.{:06}",
                            sign, d, h, m, s, us
                        ))
                    }
                    None => serde_json::Value::Null,
                };
                obj.insert(col.name_str().to_string(), value);
            }
            serde_json::Value::Object(obj)
        })
        .collect()
}
