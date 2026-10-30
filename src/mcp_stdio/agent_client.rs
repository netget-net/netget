//! Supported JSON-lines adapter for agent hosts. rmcp owns HTTP/SSE sessions and
//! reconnecting streams; this loop re-establishes a session if the server restarts.

use anyhow::{Context, Result};
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{serve_client, RoleClient};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::time::Duration;

type Client = RunningService<RoleClient, ()>;
// Polls wake immediately for work. A short server-side wait plus a bounded RPC
// also recovers a response stream lost during a server/session restart.
const WAIT_SECONDS: u64 = 5;
const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct AgentToolError(String);

// Tokio's stdin uses an uncancellable blocking task; its runtime can then hang
// on Ctrl+C waiting for another keystroke. A detached OS reader thread lets the
// process exit promptly, while a bounded channel and bounded read cap buffering.
fn input_lines() -> tokio::sync::mpsc::Receiver<std::io::Result<String>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut line = String::new();
            match Read::take(&mut input, MAX_ANSWER_BYTES as u64 + 1).read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line.len() > MAX_ANSWER_BYTES => {
                    let _ = sender.blocking_send(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "agent answer exceeds 16 MiB",
                    )));
                    break;
                }
                Ok(_) => {
                    if sender.blocking_send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    receiver
}

async fn call(client: &Client, name: &'static str, arguments: Value) -> Result<Value> {
    let timeout = Duration::from_secs(
        match arguments.get("wait_seconds").and_then(Value::as_u64) {
            Some(wait) => wait.min(120) + 5,
            None => 10,
        },
    );
    let mut params = CallToolRequestParams::new(name);
    params.arguments = arguments.as_object().cloned();
    let result = tokio::time::timeout(timeout, client.call_tool(params))
        .await
        .context("agent MCP call timed out")?
        .context("agent MCP connection lost")?;
    if result.is_error == Some(true) {
        let message = result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<String>();
        return Err(AgentToolError(message).into());
    }
    result.structured_content.ok_or_else(|| {
        AgentToolError("server lacks structured agent tools; update NetGet".into()).into()
    })
}

fn emit(request: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &json!({"type":"request", "request":request}))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// Run until stdin closes or Ctrl+C. The host must actively read requests and
/// author answers; this command cannot wake a host whose agent turn has ended.
pub async fn run(endpoint: &str, token: Option<String>) -> Result<()> {
    let url = url::Url::parse(endpoint).context("invalid MCP URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "MCP URL must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "put the MCP token in NETGET_MCP_TOKEN, not in the URL"
    );
    let mut builder = reqwest_mcp::Client::builder().connect_timeout(Duration::from_secs(10));
    if crate::llm::ollama_client::is_loopback_endpoint(endpoint) {
        builder = builder.no_proxy();
    }
    let http = builder.build()?;
    let mut config = StreamableHttpClientTransportConfig::with_uri(endpoint.to_string());
    config.retry_config = std::sync::Arc::new(
        rmcp::transport::common::client_side_sse::ExponentialBackoff {
            max_times: Some(3),
            base_duration: Duration::from_millis(250),
        },
    );
    if let Some(token) = token {
        config = config.auth_header(token);
    }
    let mut input = input_lines();
    // Retain an unacknowledged answer across session failures. A claim token
    // prevents accidentally answering a new request after a server restart.
    let mut unacknowledged: Option<Value> = None;
    let mut delay = 1;
    'connect: loop {
        eprintln!("agent: connecting");
        let transport = StreamableHttpClientTransport::with_client(http.clone(), config.clone());
        let connected = tokio::select! {
            result = serve_client((), transport) => result,
            _ = tokio::signal::ctrl_c() => return Ok(()),
            line = input.recv() => {
                if line.is_none() { return Ok(()); }
                eprintln!("agent: wait for a request before sending an answer");
                continue;
            }
        };
        let client = match connected {
            Ok(client) => {
                delay = 1;
                client
            }
            Err(_) => {
                eprintln!("agent: disconnected; reconnecting in {delay}s");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    line = input.recv() => { if line.is_none() { return Ok(()); } }
                }
                delay = (delay * 2).min(10);
                continue;
            }
        };
        if let Some(answer) = &unacknowledged {
            // Replaying an answer is safe: it is removed atomically on first
            // acceptance, and the token binds it to this process and claim.
            let recovery = call(
                &client,
                "get_llm_request",
                json!({"request_id":answer["request_id"]}),
            )
            .await;
            match recovery {
                Ok(request) if request["claim_token"] == answer["claim_token"] => {
                    match call(&client, "answer_llm_request", answer.clone()).await {
                        Ok(_) => unacknowledged = None,
                        Err(error) if error.downcast_ref::<AgentToolError>().is_none() => {
                            eprintln!("agent: disconnected while recovering answer; retrying");
                            let _ = client.cancel().await;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue 'connect;
                        }
                        Err(_) => {
                            eprintln!("agent: previous claim expired or changed");
                            unacknowledged = None;
                        }
                    }
                }
                Err(error) if error.downcast_ref::<AgentToolError>().is_none() => {
                    eprintln!("agent: disconnected while checking answer; retrying");
                    let _ = client.cancel().await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue 'connect;
                }
                _ => {
                    eprintln!(
                        "agent: previous request was answered, cancelled, expired, or reassigned"
                    );
                    unacknowledged = None;
                }
            }
        }
        loop {
            let request = {
                eprintln!("agent: waiting");
                let fetched = tokio::select! {
                    result = call(&client,"get_next_llm_request",json!({"wait_seconds":WAIT_SECONDS,"lease_seconds":60})) => result,
                    _ = tokio::signal::ctrl_c() => { let _ = client.cancel().await; return Ok(()); }
                    line = input.recv() => {
                        if line.is_none() { let _ = client.cancel().await; return Ok(()); }
                        eprintln!("agent: wait for a request before sending an answer");
                        continue;
                    }
                };
                match fetched {
                    Ok(value) if value.get("request_id").is_some() => value,
                    Ok(_) => continue,
                    Err(error) if error.downcast_ref::<AgentToolError>().is_some() => {
                        return Err(error)
                    }
                    Err(_) => {
                        eprintln!("agent: disconnected; reconnecting");
                        break;
                    }
                }
            };
            emit(&request)?;
            eprintln!("agent: answering request {}", request["request_id"]);
            let remaining = request["deadline_unix_ms"]
                .as_u64()
                .map(|deadline| {
                    let now = crate::utils::clock::SystemTime::now()
                        .duration_since(crate::utils::clock::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    Duration::from_millis(deadline.saturating_sub(now))
                })
                .unwrap_or(Duration::from_secs(300));
            let answer_deadline =
                tokio::time::Instant::now() + remaining.min(Duration::from_secs(299));
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(20),
                Duration::from_secs(20),
            );
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let answer = loop {
                let line = tokio::select! {
                    _ = heartbeat.tick() => {
                        let renewed = tokio::select! {
                            result = call(&client,"renew_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"],"lease_seconds":60})) => result,
                            _ = tokio::signal::ctrl_c() => {
                                let _ = tokio::time::timeout(Duration::from_secs(3),call(&client,"release_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"]}))).await;
                                let _ = client.cancel().await; return Ok(());
                            }
                        };
                        if renewed.is_err() { eprintln!("agent: request claim lost; discard its unfinished answer"); break None; }
                        continue;
                    }
                    line = input.recv() => line,
                    _ = tokio::signal::ctrl_c() => {
                        let _ = tokio::time::timeout(Duration::from_secs(3),call(&client,"release_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"]}))).await;
                        let _ = client.cancel().await; return Ok(());
                    }
                    _ = tokio::time::sleep_until(answer_deadline) => { eprintln!("agent: request deadline reached"); break None; }
                };
                let Some(line) = line else {
                    let _ = call(&client,"release_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"]})).await;
                    let _ = client.cancel().await;
                    return Ok(());
                };
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        let _ = call(&client,"release_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"]})).await;
                        return Err(error).context("invalid or oversized agent answer line");
                    }
                };
                let answer: Value = match serde_json::from_str(&line) {
                    Ok(value) => value,
                    Err(_) => {
                        eprintln!("agent: expected a JSON object with request_id and actions");
                        continue;
                    }
                };
                if answer["request_id"] != request["request_id"]
                    || answer["claim_token"] != request["claim_token"]
                    || !answer["actions"].is_array()
                {
                    eprintln!(
                        "agent: answer must echo request {} and its claim_token, and contain an actions array",
                        request["request_id"]
                    );
                    continue;
                }
                break Some(answer);
            };
            let Some(answer) = answer else {
                continue;
            };
            unacknowledged = Some(answer.clone());
            eprintln!("agent: answer submitted; waiting");
            let answered = tokio::select! {
                result = call(&client,"answer_llm_request",answer) => result,
                _ = tokio::signal::ctrl_c() => { let _ = client.cancel().await; return Ok(()); }
            };
            match answered {
                Ok(_) => {
                    unacknowledged = None;
                }
                Err(error) if error.downcast_ref::<AgentToolError>().is_some() => {
                    eprintln!("agent: answer was refused ({error}); waiting for a current request");
                    unacknowledged = None;
                }
                Err(_) => {
                    eprintln!("agent: answer acknowledgement lost; reconnecting");
                    break;
                }
            }
        }
        let _ = client.cancel().await;
        tokio::select! { _ = tokio::time::sleep(Duration::from_secs(1)) => {}, _ = tokio::signal::ctrl_c() => return Ok(()) }
    }
}
