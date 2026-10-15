//! Snowflake client: NetGet speaks Snowflake's connector REST protocol and the model decides
//! what SQL to run. See `AGENTS.md` beside this file.
//!
//! Rust owns the HTTP and JSON envelope, the `Authorization: Snowflake Token="…"` header, the
//! session and master tokens (renewal included), polling a query still in progress, decoding
//! the result (JSON rowsets and Arrow streams, typed by `rowtype`) and every bound. The model
//! sees typed rows and the server's error codes, never the envelope.
//!
//! Two tasks per client, both registered so `stop_client` ends them:
//!
//! * the **session** owns the tokens. It logs in before `connect` returns, then runs one action
//!   at a time — the model's, or one injected from the dashboard or MCP — and turns the
//!   response into an event.
//! * the **turns** task asks the model about each event and hands its actions back to the
//!   session. Each event carries the number of model turns that led to it; past
//!   [`MAX_FOLLOWUP_DEPTH`] the model is not asked again.
//!
//! **The target is mandatory.** The client talks to `endpoint_url` exactly as given, or to its
//! `remote_addr`; without one it refuses to start. It never derives
//! `<account>.snowflakecomputing.com` from the account name, and it never follows a URL to
//! another origin — a result's `chunks` (presigned cloud-storage URLs) are counted, not
//! fetched, and a `getResultUrl` must be on the target.
//!
//! Fail closed: a refused login fails `connect` and the model is never asked anything; an LLM
//! failure sends nothing; a response that cannot be read becomes a `snowflake_error` naming
//! why, never an invented result.
pub mod actions;
pub mod arrow;
pub mod result;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::SnowflakeClientProtocol;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// How long a login, or a statement with its polling, may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REQUEST_TIMEOUT_SECS: u64 = 3600;
/// The largest response body read. A JSON or Arrow first result set is bounded by Snowflake at
/// a few MiB before it moves to chunks.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_ROWS: usize = 100;
pub const MAX_ROWS_LIMIT: usize = 1000;
/// The longest statement sent.
pub const MAX_SQL_BYTES: usize = 1024 * 1024;
/// How many times a query still in progress is polled.
pub const MAX_POLLS: usize = 1000;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Events waiting for the model.
const TURNS: usize = 64;
/// The application id sent at login.
pub const CLIENT_APP_ID: &str = "NetGet";

const CODE_SESSION_EXPIRED: &str = "390112";
const CODE_QUERY_IN_PROGRESS: &str = "333333";
const CODE_QUERY_IN_PROGRESS_ASYNC: &str = "333334";

fn user_agent() -> String {
    format!("NetGet/{}", env!("CARGO_PKG_VERSION"))
}

/// The base URL this client talks to: `endpoint_url` as given, else `remote_addr` (a bare
/// `host:port` meaning `http://host:port`). There is no third option.
pub fn resolve_endpoint(remote_addr: &str, endpoint_url: Option<&str>) -> Result<String> {
    let given = match endpoint_url.map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => url.to_string(),
        None => {
            let raw = remote_addr.trim();
            ensure!(
                !raw.is_empty(),
                "the Snowflake client needs a target: a remote_addr (host:port) or an \
                 endpoint_url. Refusing to start without one; it never derives \
                 <account>.snowflakecomputing.com from the account name"
            );
            if raw.contains("://") {
                raw.to_string()
            } else {
                format!("http://{raw}")
            }
        }
    };
    let parsed = url::Url::parse(&given).with_context(|| format!("{given:?} is not a URL"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "{given:?} is not an http(s) URL with a host"
    );
    ensure!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "{given:?}: the endpoint is a base URL, without a query or fragment"
    );
    Ok(given.trim_end_matches('/').to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn http_client(base: &str, timeout: Duration) -> Result<FetchClient> {
    let builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent());
    let client = crate::llm::ollama_client::configured_for_endpoint(builder, base)
        .build()
        .context("building the HTTP client")?;
    Ok(FetchClient::from_reqwest(client).with_max_body(MAX_RESPONSE_BYTES))
}

#[cfg(target_arch = "wasm32")]
fn http_client(_base: &str, timeout: Duration) -> Result<FetchClient> {
    Ok(FetchClient::transport(timeout)
        .with_max_body(MAX_RESPONSE_BYTES)
        .with_user_agent(&user_agent()))
}

/// What a login needs.
#[derive(Debug, Clone, Default)]
pub struct Login {
    pub username: String,
    pub password: String,
    pub account: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub warehouse: Option<String>,
    pub role: Option<String>,
}

/// One logged-in session.
pub struct Session {
    http: FetchClient,
    pub base: String,
    token: String,
    master_token: Option<String>,
    timeout: Duration,
    sequence: u64,
    pub bytes_out: usize,
    /// What the login response said about the session, for the connected event.
    pub info: Value,
}

/// What one action produced: the event to raise.
pub type Done = (&'static EventType, Value);

fn code_of(resp: &Value) -> Option<String> {
    match resp.get("code") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn text_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Session {
    async fn post(
        &mut self,
        path: &str,
        body: &Value,
        token: Option<&str>,
    ) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.base);
        let payload = serde_json::to_vec(body)?;
        self.bytes_out += payload.len();
        let mut req = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/snowflake")
            .body(payload);
        if let Some(token) = token {
            req = req.header("Authorization", format!("Snowflake Token=\"{token}\""));
        }
        read(req.send().await.with_context(|| format!("POST {path}"))?).await
    }

    async fn get(&mut self, url: &str) -> Result<(u16, Value)> {
        let req = self
            .http
            .get(url)
            .header("Accept", "application/snowflake")
            .header(
                "Authorization",
                format!("Snowflake Token=\"{}\"", self.token),
            );
        read(req.send().await.with_context(|| format!("GET {url}"))?).await
    }

    /// Log in. Any refusal is an error: the caller fails `connect`.
    pub async fn login(base: String, login: &Login, timeout: Duration) -> Result<Session> {
        ensure!(!login.username.is_empty(), "the username is empty");
        let mut session = Session {
            http: http_client(&base, timeout)?,
            base,
            token: String::new(),
            master_token: None,
            timeout,
            sequence: 0,
            bytes_out: 0,
            info: Value::Null,
        };
        let query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("request_id", &request_id());
            for (key, value) in [
                ("databaseName", &login.database),
                ("schemaName", &login.schema),
                ("warehouse", &login.warehouse),
                ("roleName", &login.role),
            ] {
                if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
                    query.append_pair(key, v);
                }
            }
            query.append_pair("request_guid", &request_id());
            query.finish()
        };
        let mut data = json!({
            "CLIENT_APP_ID": CLIENT_APP_ID,
            "CLIENT_APP_VERSION": env!("CARGO_PKG_VERSION"),
            "LOGIN_NAME": login.username,
            "PASSWORD": login.password,
            "CLIENT_ENVIRONMENT": {"APPLICATION": CLIENT_APP_ID, "OS": std::env::consts::OS},
            "SESSION_PARAMETERS": {},
        });
        if let Some(account) = login.account.as_deref().filter(|a| !a.is_empty()) {
            data["ACCOUNT_NAME"] = json!(account);
        }
        let path = format!("/session/v1/login-request?{query}");
        let (status, resp) =
            tokio::time::timeout(timeout, session.post(&path, &json!({ "data": data }), None))
                .await
                .map_err(|_| anyhow!("no login response within {}s", timeout.as_secs()))??;
        if resp.get("success").and_then(Value::as_bool) != Some(true) {
            bail!(
                "login refused (HTTP {status}): code {} {} decision=refused",
                code_of(&resp).unwrap_or_else(|| "none".into()),
                crate::utils::sanitize::line_field(
                    &text_of(resp.get("message")).unwrap_or_default()
                )
            );
        }
        let d = resp.get("data").context("a login success with no data")?;
        session.token = d
            .get("token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .context("a login success with no session token")?
            .to_string();
        session.master_token = d
            .get("masterToken")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        let si = d.get("sessionInfo").cloned().unwrap_or(Value::Null);
        session.info = json!({
            "database": text_of(si.get("databaseName")),
            "schema": text_of(si.get("schemaName")),
            "warehouse": text_of(si.get("warehouseName")),
            "role": text_of(si.get("roleName")),
            "server_version": text_of(d.get("serverVersion")),
            "session_id": text_of(d.get("sessionId")),
        });
        Ok(session)
    }

    /// `POST /session/token-request` with the master token, replacing the session token.
    async fn renew(&mut self) -> Result<()> {
        let master = self
            .master_token
            .clone()
            .context("the server gave no master token to renew the session with")?;
        let path = format!("/session/token-request?requestId={}", request_id());
        let body = json!({"oldSessionToken": self.token, "requestType": "RENEW"});
        let (_, resp) = self.post(&path, &body, Some(&master)).await?;
        let d = resp.get("data").cloned().unwrap_or(Value::Null);
        match d.get("sessionToken").and_then(Value::as_str) {
            Some(t)
                if resp.get("success").and_then(Value::as_bool) == Some(true) && !t.is_empty() =>
            {
                self.token = t.to_string();
                if let Some(m) = d.get("masterToken").and_then(Value::as_str) {
                    self.master_token = Some(m.to_string());
                }
                Ok(())
            }
            _ => bail!(
                "the server refused to renew the session: code {} {}",
                code_of(&resp).unwrap_or_else(|| "none".into()),
                text_of(resp.get("message")).unwrap_or_default()
            ),
        }
    }

    /// `POST /session?delete=true`.
    pub async fn logout(&mut self) -> Result<()> {
        let token = self.token.clone();
        let (status, resp) = tokio::time::timeout(
            self.timeout,
            self.post("/session?delete=true", &json!({}), Some(&token)),
        )
        .await
        .map_err(|_| anyhow!("no logout response within {}s", self.timeout.as_secs()))??;
        ensure!(
            resp.get("success").and_then(Value::as_bool) == Some(true),
            "logout refused (HTTP {status}): code {}",
            code_of(&resp).unwrap_or_else(|| "none".into())
        );
        Ok(())
    }

    /// Run one statement. `Ok` carries the event to raise, a refusal included.
    pub async fn execute(&mut self, sql: &str, max_rows: usize) -> Done {
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, self.execute_inner(sql, max_rows)).await {
            Ok(Ok(done)) => done,
            Ok(Err(e)) => error_event(sql, None, format!("{e:#}"), None),
            Err(_) => error_event(
                sql,
                None,
                format!("no answer within {}s", timeout.as_secs()),
                None,
            ),
        }
    }

    async fn execute_inner(&mut self, sql: &str, max_rows: usize) -> Result<Done> {
        let mut renewed = false;
        let (mut status, mut resp) = loop {
            self.sequence += 1;
            let submitted = crate::utils::clock::SystemTime::now()
                .duration_since(crate::utils::clock::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let body = json!({
                "sqlText": sql,
                "asyncExec": false,
                "sequenceId": self.sequence,
                "querySubmissionTime": submitted,
                "isInternal": false,
                "describeOnly": false,
            });
            let path = format!(
                "/queries/v1/query-request?requestId={}&request_guid={}",
                request_id(),
                request_id()
            );
            let token = self.token.clone();
            let (status, resp) = self.post(&path, &body, Some(&token)).await?;
            if code_of(&resp).as_deref() == Some(CODE_SESSION_EXPIRED) && !renewed {
                renewed = true;
                if let Err(e) = self.renew().await {
                    return Ok(error_event(
                        sql,
                        Some(&resp),
                        format!("the session expired and could not be renewed: {e:#}"),
                        Some(status),
                    ));
                }
                continue;
            }
            break (status, resp);
        };

        let mut polls = 0;
        while matches!(
            code_of(&resp).as_deref(),
            Some(CODE_QUERY_IN_PROGRESS | CODE_QUERY_IN_PROGRESS_ASYNC)
        ) {
            polls += 1;
            ensure!(
                polls <= MAX_POLLS,
                "the query was still in progress after {MAX_POLLS} polls"
            );
            let result_url = resp
                .pointer("/data/getResultUrl")
                .and_then(Value::as_str)
                .context("a query in progress with no getResultUrl")?;
            // Only ever on the target: a result URL naming another origin is refused.
            let url = crate::client::http_fetch::resolve_same_origin(&self.base, result_url)?;
            tokio::time::sleep(POLL_INTERVAL).await;
            (status, resp) = self.get(&url).await?;
        }

        if resp.get("success").and_then(Value::as_bool) == Some(true) {
            let data = resp.get("data").cloned().unwrap_or(Value::Null);
            return Ok(match result::decode(&data, max_rows) {
                Ok(mut out) => {
                    out["sql"] = json!(sql);
                    (&actions::QUERY_RESULT_EVENT, out)
                }
                Err(e) => error_event(
                    sql,
                    Some(&resp),
                    format!("the result could not be read: {e:#}"),
                    Some(status),
                ),
            });
        }
        let message = text_of(resp.get("message"))
            .unwrap_or_else(|| format!("the server answered HTTP {status} without success"));
        Ok(error_event(sql, Some(&resp), message, Some(status)))
    }
}

fn error_event(sql: &str, resp: Option<&Value>, message: String, status: Option<u16>) -> Done {
    let mut data = json!({"operation": "run_sql", "sql": sql, "message": message});
    if let Some(resp) = resp {
        if let Some(code) = code_of(resp) {
            data["code"] = json!(code);
        }
        if let Some(state) = text_of(resp.pointer("/data/sqlState").or(resp.get("sqlState"))) {
            data["sql_state"] = json!(state);
        }
        if let Some(id) = text_of(resp.pointer("/data/queryId")) {
            data["query_id"] = json!(id);
        }
    }
    if let Some(status) = status {
        data["http_status"] = json!(status);
    }
    (&actions::ERROR_EVENT, data)
}

/// A response body as JSON, whatever the HTTP status: Snowflake reports failures in the body,
/// and some servers send them with a 4xx or 5xx as well.
async fn read(resp: crate::client::http_fetch::FetchResponse) -> Result<(u16, Value)> {
    let status = resp.status().as_u16();
    let body = resp.bytes().await.context("reading the response")?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "the response is {} bytes; at most {MAX_RESPONSE_BYTES} are read",
        body.len()
    );
    let value: Value = serde_json::from_slice(&body).map_err(|e| {
        anyhow!(
            "the server answered HTTP {status} with a body that is not JSON ({e}): {}",
            crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_for_log(
                &String::from_utf8_lossy(&body),
                200
            ))
        )
    })?;
    ensure!(
        value.is_object(),
        "the server answered HTTP {status} with JSON that is not an object"
    );
    Ok((status, value))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let string = |key: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten())
    };
    let base = resolve_endpoint(&ctx.remote_addr, string("endpoint_url")?.as_deref())?;
    crate::client::http_fetch::check_url(&base)?;
    let login = Login {
        username: string("username")?
            .filter(|u| !u.is_empty())
            .context("the Snowflake client needs the username startup parameter")?,
        password: string("password")?
            .context("the Snowflake client needs the password startup parameter")?,
        account: string("account")?,
        database: string("database")?,
        schema: string("schema")?,
        warehouse: string("warehouse")?,
        role: string("role")?,
    };
    let timeout_secs = params
        .map(|p| p.get_optional_u64("request_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(REQUEST_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_REQUEST_TIMEOUT_SECS).contains(&timeout_secs),
        "request_timeout_secs is 1..={MAX_REQUEST_TIMEOUT_SECS}"
    );
    let log = Log::new(Some(&ctx.status_tx));
    let mut session =
        match Session::login(base.clone(), &login, Duration::from_secs(timeout_secs)).await {
            Ok(s) => s,
            Err(e) => {
                log.warn(format!(
                    "Snowflake client {}: login to {base} failed: {e:#} decision=fail_closed_login",
                    ctx.client_id
                ));
                return Err(e);
            }
        };
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    log.info(format!(
        "Snowflake client {} logged in to {base} as {}",
        ctx.client_id, login.username
    ));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());

    // Registered before the connected turn can run, so the operator can reach the client
    // while that turn is parked on a manual rule.
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(TURNS);
    let mut connected = json!({
        "endpoint": base,
        "user": login.username,
        "account": login.account,
    });
    if let (Some(out), Some(info)) = (connected.as_object_mut(), session.info.as_object()) {
        for (k, v) in info {
            out.insert(k.clone(), v.clone());
        }
    }
    let _ = event_tx.try_send((Event::new(&actions::CONNECTED_EVENT, connected), 0));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = run_session(&mut session, &session_ctx, external, internal, event_tx).await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!(
                    "Snowflake client {} ended: {e:#} decision=connection_failed",
                    session_ctx.client_id
                ));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    // HTTP holds no one socket for the session; there is no local address to report.
    Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

/// Execute actions one at a time until the client logs out or is stopped.
async fn run_session(
    session: &mut Session,
    ctx: &ConnectContext,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) -> Result<()> {
    let protocol = SnowflakeClientProtocol;
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => {
                    ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "Snowflake",
                        None, "injected_action", c.action.clone(), vec![]).await;
                    (c.action.clone(), 0, Some(c))
                }
                None => return Ok(()),
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return Ok(()),
            },
        };
        let (name, data) = match protocol.execute_action(action) {
            Ok(ClientActionResult::Custom { name, data }) => (name, data),
            Ok(_) => {
                reply(
                    command,
                    ClientSendOutcome::Executed {
                        detail: "nothing to send".into(),
                    },
                );
                continue;
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "Snowflake client {}: action refused: {e:#}",
                    ctx.client_id
                ));
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        if name == "logout" {
            match session.logout().await {
                Ok(()) => Log::new(Some(&ctx.status_tx)).info(format!(
                    "Snowflake client {} logged out of {}",
                    ctx.client_id, session.base
                )),
                Err(e) => Log::new(Some(&ctx.status_tx))
                    .warn(format!("Snowflake client {}: logout: {e:#}", ctx.client_id)),
            }
            reply(command, ClientSendOutcome::Disconnected);
            return Ok(());
        }
        let sql = data.get("sql").and_then(Value::as_str).unwrap_or_default();
        let max_rows = data
            .get("max_rows")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_MAX_ROWS as u64)
            .min(MAX_ROWS_LIMIT as u64) as usize;
        let before = session.bytes_out;
        let (event_type, payload) = session.execute(sql, max_rows).await;
        reply(
            command,
            ClientSendOutcome::Sent {
                bytes_sent: session.bytes_out - before,
            },
        );
        tracing::info!(
            "Snowflake client {} {name} -> {} (depth {depth})",
            ctx.client_id,
            event_type.id
        );
        if events
            .try_send((Event::new(event_type, payload), depth))
            .is_err()
        {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "Snowflake client {}: {} events are waiting for the model; this one is dropped \
                 decision=turn_queue_full",
                ctx.client_id, TURNS
            ));
        }
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}

/// Ask the model about each event, in order, and hand its actions to the session.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = SnowflakeClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "Snowflake client {} not asking the model about {}: {depth} turns deep \
                 decision=followup_depth",
                ctx.client_id,
                event.id()
            ));
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                tracing::info!(
                    "Snowflake client {} {} decision={} actions={}",
                    ctx.client_id,
                    event.id(),
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            // Fail closed: nothing is sent on the model's behalf when it cannot be asked.
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                "Snowflake client {} {}: {e:#} decision=fail_closed_llm_error",
                ctx.client_id,
                event.id()
            )),
        }
    }
}
