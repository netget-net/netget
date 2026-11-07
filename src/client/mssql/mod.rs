//! MSSQL client implementation using tiberius
pub mod actions;

pub use actions::MssqlClientProtocol;

use crate::client::llm_budget::call_llm_for_client;
use crate::client::mssql::actions::{
    MSSQL_CLIENT_CONNECTED_EVENT, MSSQL_CLIENT_ERROR_EVENT, MSSQL_CLIENT_QUERY_RESULT_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use anyhow::{Context, Result};
use futures::StreamExt;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tiberius::{AuthMethod, Client as TiberiusClient, Config, QueryItem, Row};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{debug, error, info, trace, warn};

/// The live tiberius connection. Named because it appears in five signatures.
type MssqlConn = TiberiusClient<tokio_util::compat::Compat<TcpStream>>;

/// What one executed MSSQL action did, before any follow-up LLM call.
///
/// Splitting "run it" from "tell the model about it" is what lets the connected-event path
/// and an injected dashboard command share the query path without the command loop having
/// to block on a handler that may be parked for a human.
enum MssqlApplied {
    /// A query ran. `result` is the collected rows, or the server's error as text.
    Query {
        query: String,
        result: std::result::Result<QueryResult, String>,
    },
    /// The action asked to end the session.
    Disconnect,
    /// The action ran but touched the connection in no way worth reporting.
    Nothing(String),
}

/// MSSQL client that connects to an MSSQL/SQL Server
pub struct MssqlClient;

impl MssqlClient {
    /// Connect to an MSSQL server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse connection string (format: "host:port" or "host:port;database=db;user=user;password=pass")
        let (host_port, config_params) = if remote_addr.contains(';') {
            let parts: Vec<&str> = remote_addr.splitn(2, ';').collect();
            (parts[0].to_string(), Some(parts[1].to_string()))
        } else {
            (remote_addr.clone(), None)
        };

        // Parse host and port
        let (host, port) = if host_port.contains(':') {
            let parts: Vec<&str> = host_port.split(':').collect();
            (
                parts[0].to_string(),
                parts
                    .get(1)
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(1433),
            )
        } else {
            (host_port, 1433)
        };

        // Build tiberius config
        let mut config = Config::new();
        config.host(&host);
        config.port(port);
        config.trust_cert(); // For testing - accept self-signed certs
                             // tiberius defaults to `EncryptionLevel::Required` whenever a TLS backend is
                             // compiled in, and NetGet pulls tiberius with `native-tls`. NetGet's own MSSQL
                             // server answers PRELOGIN with ENCRYPT_NOT_SUP, so with the default the client
                             // negotiated `EncryptionLevel::On` and then tried a TLS handshake the server cannot
                             // do - the two halves of this codebase could not talk to each other at all.
        config.encryption(tiberius::EncryptionLevel::NotSupported);

        // Parse optional connection parameters
        if let Some(params_str) = config_params {
            for param in params_str.split(';') {
                let kv: Vec<&str> = param.split('=').collect();
                if kv.len() == 2 {
                    match kv[0].to_lowercase().as_str() {
                        "database" => config.database(kv[1]),
                        "user" => config.authentication(AuthMethod::sql_server(kv[1], "")),
                        _ => {}
                    };
                }
            }
        }

        // Always use no authentication for now (works with our test server)
        // In production, parse credentials from connection string
        config.authentication(AuthMethod::None);

        // Connect to MSSQL server
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .context(format!("Failed to connect to MSSQL at {}:{}", host, port))?;

        let local_addr = tcp.local_addr()?;
        let remote_sock_addr = tcp.peer_addr()?;

        info!(
            "MSSQL client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Create tiberius client
        let client = TiberiusClient::connect(config, tcp.compat_write())
            .await
            .context("Failed to create tiberius client")?;

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] MSSQL client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let client_arc = Arc::new(Mutex::new(client));
        let client_for_connected = client_arc.clone();

        // The dashboard's `[ send ]` channel, registered BEFORE the connected-event LLM call
        // below. A dashboard-created client defaults to a `*` -> manual rule, so that call can
        // park for minutes waiting for a human; registering after it would leave the rail
        // reading "no command channel" for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_task = tokio::spawn(Self::command_loop(
            client_arc.clone(),
            command_rx,
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        // Call LLM with mssql_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &MSSQL_CLIENT_CONNECTED_EVENT,
                json!({
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(), // No memory yet for initial connection
                Some(&event),
                &MssqlClientProtocol::new(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Execute actions from LLM response. Depth 0: this is the first step of a
                    // chain the model may extend by answering each query result with another
                    // query.
                    for action in result.actions {
                        if let Err(e) = Self::execute_action_internal(
                            client_for_connected.clone(),
                            action,
                            client_id,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            0,
                        )
                        .await
                        {
                            error!("Failed to execute action after connect: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on mssql_connected event: {}", e);
                }
            }
        }

        // MSSQL (via tiberius) is query-driven, not event-driven: there is no read loop,
        // because nothing arrives that this client did not ask for. `command_loop` above is
        // what holds the connection open and what makes queries reachable from outside an
        // LLM round trip.
        info!("MSSQL client {} ready for queries", client_id);

        Ok(local_addr)
    }

    /// How many queries deep this client keeps following the model's answers.
    ///
    /// The cycle is real and it is the point of the client: a query is run, its result is
    /// reported to the model as an event, and the model may answer that event with another
    /// query. Nothing in that loop terminates on its own, so a model that answers every
    /// `mssql_query_result` with another `mssql_query` recursed for as long as the process
    /// lived, growing the heap by one boxed future per step and holding a `register_client_task`
    /// handle for each. The bound is the fix the root CLAUDE.md prescribes for this shape, and
    /// 4 is what the etcd client uses for the identical cycle.
    const MAX_FOLLOWUP_DEPTH: u8 = 4;

    /// Execute an action: run it against the connection, then tell the model what happened.
    ///
    /// Boxed rather than a plain `async fn` because the recursion is real - `follow_up` calls
    /// back into this function - and a self-awaiting `async fn` has an infinitely-sized future.
    /// `depth` is how many queries have already run in this chain.
    #[allow(clippy::too_many_arguments)]
    fn execute_action_internal<'a>(
        client: Arc<Mutex<MssqlConn>>,
        action: serde_json::Value,
        client_id: ClientId,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let applied = Self::apply_action(&client, action, client_id).await?;
            Self::follow_up(
                applied, client, client_id, llm_client, app_state, status_tx, depth,
            )
            .await;
            Ok(())
        })
    }

    /// Run one action against the live tiberius connection and report what it did.
    ///
    /// Shared by the connected-event path and by injected dashboard commands, so the query
    /// path — and the `execute_action` validation in front of it — exists exactly once. It
    /// deliberately makes no LLM call: [`Self::follow_up`] does that, and the command loop
    /// spawns it rather than awaiting it.
    async fn apply_action(
        client: &Arc<Mutex<MssqlConn>>,
        action: serde_json::Value,
        client_id: ClientId,
    ) -> Result<MssqlApplied> {
        let protocol = MssqlClientProtocol::new();
        match protocol.execute_action(action)? {
            ClientActionResult::Custom { name, data } if name == "mssql_query" => {
                let query = data
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("mssql_query carried no 'query' string")?
                    .to_string();
                debug!("MSSQL client {} executing query: {}", client_id, query);

                // The mutex is held for the query only; it is never held across an LLM call.
                let outcome = {
                    let mut client_guard = client.lock().await;
                    Self::execute_and_collect_query(&mut client_guard, &query).await
                };
                Ok(MssqlApplied::Query {
                    query,
                    result: outcome.map_err(|e| e.to_string()),
                })
            }
            ClientActionResult::Disconnect => Ok(MssqlApplied::Disconnect),
            ClientActionResult::WaitForMore => {
                trace!("MSSQL client {} waiting for more data", client_id);
                Ok(MssqlApplied::Nothing("wait_for_more".to_string()))
            }
            other => Ok(MssqlApplied::Nothing(format!(
                "unsupported action result {other:?}"
            ))),
        }
    }

    /// Raise the event an applied action produced and execute whatever the handler answers.
    ///
    /// `depth` is how many queries have already run in this chain; see
    /// [`Self::MAX_FOLLOWUP_DEPTH`].
    #[allow(clippy::too_many_arguments)]
    async fn follow_up(
        applied: MssqlApplied,
        client: Arc<Mutex<MssqlConn>>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: u8,
    ) {
        let protocol = Arc::new(MssqlClientProtocol::new());

        let event = match applied {
            MssqlApplied::Disconnect => {
                info!("MSSQL client {} disconnecting", client_id);
                // Stop offering [ send ] on a session that is going away.
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return;
            }
            MssqlApplied::Nothing(detail) => {
                trace!(
                    "MSSQL client {} action produced nothing: {}",
                    client_id,
                    detail
                );
                return;
            }
            MssqlApplied::Query {
                result: Ok(result), ..
            } => {
                debug!(
                    "MSSQL client {} received {} columns, {} rows",
                    client_id,
                    result.columns.len(),
                    result.rows.len()
                );
                Event::new(
                    &MSSQL_CLIENT_QUERY_RESULT_EVENT,
                    json!({
                        "columns": result.columns,
                        "rows": result.rows,
                        "rows_affected": result.rows_affected,
                    }),
                )
            }
            MssqlApplied::Query {
                result: Err(e),
                query,
            } => {
                error!("MSSQL query error on '{}': {}", query, e);
                Event::new(
                    &MSSQL_CLIENT_ERROR_EVENT,
                    json!({
                        "error_number": 50000,
                        "message": e,
                    }),
                )
            }
        };

        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
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
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                // Say what is being dropped and why, rather than letting the chain stop
                // silently - a model whose plan needed a fifth step should be able to see
                // from the log that it was cut off, not that its action was ignored.
                if depth + 1 >= Self::MAX_FOLLOWUP_DEPTH {
                    if !actions.is_empty() {
                        warn!(
                            "MSSQL client {} reached the follow-up depth limit of {}; dropping \
                             {} further action(s)",
                            client_id,
                            Self::MAX_FOLLOWUP_DEPTH,
                            actions.len()
                        );
                    }
                    return;
                }

                for follow_action in actions {
                    if let Err(e) = Self::execute_action_internal(
                        client.clone(),
                        follow_action,
                        client_id,
                        llm_client,
                        app_state,
                        status_tx,
                        depth + 1,
                    )
                    .await
                    {
                        error!("Failed to execute follow-up action: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("LLM error for MSSQL client {}: {}", client_id, e);
            }
        }
    }

    /// Drain injected commands (the dashboard's `[ send ]`) until the channel closes or an
    /// injected `disconnect` ends the session.
    ///
    /// This task is also what keeps the tiberius connection alive: before it existed the
    /// only `Arc` to the connection was a local in `connect_with_llm_actions`, so the socket
    /// was dropped the moment that function returned.
    ///
    /// Outcome semantics: tiberius owns the TDS framing, so there is no byte count this loop
    /// can honestly claim. A query that ran reports `Executed` naming the row/column counts;
    /// a query the server refused is an `Err`, never a quieter `Sent`.
    async fn command_loop(
        client: Arc<Mutex<MssqlConn>>,
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = MssqlClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let mut applied_for_follow_up = None;
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> =
                match Self::apply_action(&client, action.clone(), client_id).await {
                    // `apply_action` only errors when the protocol rejected the action.
                    Err(e) => Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                    Ok(MssqlApplied::Disconnect) => {
                        disconnect = true;
                        Ok(ClientSendOutcome::Disconnected)
                    }
                    Ok(MssqlApplied::Nothing(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(MssqlApplied::Query {
                        query,
                        result: Err(e),
                    }) => Err(anyhow::anyhow!("query '{query}' failed: {e}")),
                    Ok(MssqlApplied::Query {
                        query,
                        result: Ok(result),
                    }) => {
                        let detail = format!(
                            "execute_query '{}': {} row(s), {} column(s)",
                            query,
                            result.rows.len(),
                            result.columns.len()
                        );
                        applied_for_follow_up = Some(MssqlApplied::Query {
                            query,
                            result: Ok(result),
                        });
                        Ok(ClientSendOutcome::Executed { detail })
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

            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "MSSQL client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }

            // The query-result event goes to the model in its own task: a handler parked for
            // a human must not block the next injected command.
            if let Some(applied) = applied_for_follow_up {
                let client = client.clone();
                let llm_client = llm_client.clone();
                let state = app_state.clone();
                let tx = status_tx.clone();
                let handle = tokio::spawn(async move {
                    // An injected command is the operator starting a fresh chain, so it
                    // begins at depth 0 rather than inheriting anything.
                    Self::follow_up(applied, client, client_id, &llm_client, &state, &tx, 0).await;
                });
                app_state.register_client_task(client_id, handle).await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute query and collect results
    async fn execute_and_collect_query(
        client: &mut TiberiusClient<tokio_util::compat::Compat<TcpStream>>,
        query: &str,
    ) -> Result<QueryResult> {
        let mut stream = client.query(query, &[]).await?;

        let mut columns = Vec::new();
        let mut rows = Vec::new();
        let rows_affected: u64;

        // Collect column metadata
        if let Some(cols) = stream.columns().await? {
            for col in cols {
                columns.push(json!({
                    "name": col.name(),
                    "type": format!("{:?}", col.column_type()),
                }));
            }
        }

        // Collect rows
        while let Some(item) = stream.next().await {
            match item {
                Ok(QueryItem::Row(row)) => {
                    let row_values = Self::row_to_json(&row)?;
                    rows.push(row_values);
                }
                Ok(QueryItem::Metadata(_)) => {
                    // Metadata already processed above
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // For SELECT queries, rows_affected is typically the row count
        rows_affected = rows.len() as u64;

        Ok(QueryResult {
            columns,
            rows,
            rows_affected,
        })
    }

    /// Collect query results into JSON format (legacy - not used)
    #[allow(dead_code)]
    async fn collect_query_results(mut stream: tiberius::QueryStream<'_>) -> Result<QueryResult> {
        let mut columns = Vec::new();
        let mut rows = Vec::new();

        // Collect column metadata
        if let Some(cols) = stream.columns().await? {
            for col in cols {
                columns.push(json!({
                    "name": col.name(),
                    "type": format!("{:?}", col.column_type()),
                }));
            }
        }

        // Collect rows
        while let Some(item) = stream.next().await {
            match item {
                Ok(QueryItem::Row(row)) => {
                    let row_values = Self::row_to_json(&row)?;
                    rows.push(row_values);
                }
                Ok(QueryItem::Metadata(_)) => {
                    // Metadata already processed above
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // For SELECT queries, rows_affected is typically 0 or the row count
        // For INSERT/UPDATE/DELETE, tiberius would return this in metadata
        // For simplicity, we'll use the row count as a proxy
        let rows_affected = rows.len() as u64;

        Ok(QueryResult {
            columns,
            rows,
            rows_affected,
        })
    }

    /// Convert a tiberius Row to JSON array
    fn row_to_json(row: &Row) -> Result<serde_json::Value> {
        let mut values = Vec::new();

        for i in 0..row.len() {
            let value = if let Ok(Some(s)) = row.try_get::<&str, _>(i) {
                json!(s)
            } else if let Ok(Some(n)) = row.try_get::<i32, _>(i) {
                json!(n)
            } else if let Ok(Some(n)) = row.try_get::<i64, _>(i) {
                json!(n)
            } else if let Ok(Some(b)) = row.try_get::<bool, _>(i) {
                json!(b)
            } else if let Ok(Some(f)) = row.try_get::<f32, _>(i) {
                json!(f)
            } else if let Ok(Some(f)) = row.try_get::<f64, _>(i) {
                json!(f)
            } else {
                // NULL or unsupported type
                json!(null)
            };

            values.push(value);
        }

        Ok(json!(values))
    }
}

/// Query result structure
struct QueryResult {
    columns: Vec<serde_json::Value>,
    rows: Vec<serde_json::Value>,
    rows_affected: u64,
}
