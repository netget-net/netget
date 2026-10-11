pub mod actions;
pub mod query;
pub mod transport;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::protocol::{ConnectContext, Event};
use crate::server::influxdb::codec::{self, WriteBatch};
use crate::state::{
    client_handles::{ClientCommand, ClientSendOutcome},
    AccessLogOwner, ClientStatus,
};
use crate::{console_error, console_info};
pub use actions::InfluxDbClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{collections::VecDeque, future::Future, pin::Pin};
pub const MAX_QUEUED_EVENTS: usize = 32;
pub const MAX_HANDLER_ACTIONS: usize = 32;
pub const MAX_FOLLOWUP_DEPTH: usize = 8;
type Handler = Pin<Box<dyn Future<Output = Result<crate::llm::ClientLlmResult>> + Send>>;
/// One HTTP exchange, a write or a query, ending in the event that reports it.
type Exchange = Pin<Box<dyn Future<Output = Result<Event>> + Send>>;
struct Inflight {
    exchange: Exchange,
    command: Option<ClientCommand>,
    depth: usize,
}
fn handler(ctx: ConnectContext, event: Event) -> Handler {
    Box::pin(async move {
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let configured = ctx
            .state
            .get_client_event_handler_config(ctx.client_id)
            .await
            .is_some_and(|c| c.find_handler(event.id()).is_some());
        if instruction.is_empty() && !configured {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "InfluxDB",
                    None,
                    event.id(),
                    event.data.clone(),
                    vec![],
                )
                .await;
            return Ok(crate::llm::ClientLlmResult {
                actions: vec![],
                memory_updates: None,
            });
        }
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        crate::client::llm_budget::call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &InfluxDbClientProtocol::new(),
            &ctx.status_tx,
        )
        .await
    })
}
pub struct InfluxDbClient;
impl InfluxDbClient {
    pub async fn connect(ctx: ConnectContext) -> Result<std::net::SocketAddr> {
        let origin = transport::Origin::parse(&ctx.remote_addr)?;
        let token = ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string("auth_token"))
            .transpose()?
            .flatten();
        if let Some(token) = &token {
            codec::validate_token(token)?;
        }
        let mut commands =
            crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id)
                .await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Connected)
            .await;
        let registrar = ctx.state.clone();
        let id = ctx.client_id;
        console_info!(
            ctx.status_tx,
            "InfluxDB HTTP session ready for {}",
            origin.authority
        );
        let task = tokio::spawn(async move {
            let protocol = InfluxDbClientProtocol::new();
            let mut current = Some((
                handler(
                    ctx.clone(),
                    Event::new(
                        &actions::INFLUX_CONNECTED_EVENT,
                        json!({"remote_addr":format!("http://{}",origin.authority)}),
                    ),
                ),
                0,
            ));
            let mut events = VecDeque::new();
            let mut actions = VecDeque::new();
            let mut pending: Option<Inflight> = None;
            'session: loop {
                if current.is_none() {
                    if let Some((event, depth)) = events.pop_front() {
                        current = Some((handler(ctx.clone(), event), depth));
                    }
                }
                if pending.is_none() {
                    if let Some((action, depth)) = actions.pop_front() {
                        match prepare(&protocol, action, depth, &origin, &token) {
                            Ok(Prepared::Exchange(exchange)) => {
                                pending = Some(Inflight {
                                    exchange,
                                    command: None,
                                    depth,
                                })
                            }
                            Ok(Prepared::Disconnect) => break,
                            Err(error) => console_error!(
                                ctx.status_tx,
                                "InfluxDB handler action rejected: {}",
                                error
                            ),
                        }
                        continue;
                    }
                }
                tokio::select! {
                    result = async { pending.as_mut().unwrap().exchange.as_mut().await }, if pending.is_some() => {
                        let p = pending.take().unwrap();
                        match result {
                            Ok(event) => {
                                if let Some(command) = p.command {
                                    finish(&ctx, command, Ok(ClientSendOutcome::Executed {
                                        detail: format!("InfluxDB HTTP {}", event.data["status"]),
                                    })).await;
                                }
                                if events.len() == MAX_QUEUED_EVENTS {
                                    console_error!(ctx.status_tx, "InfluxDB response-event queue limit");
                                    break;
                                }
                                events.push_back((event, p.depth));
                            }
                            Err(error) => {
                                if let Some(command) = p.command {
                                    finish(&ctx, command, Err(anyhow::anyhow!("InfluxDB HTTP exchange failed"))).await;
                                }
                                console_error!(ctx.status_tx, "InfluxDB HTTP exchange failed: {}", error);
                                break;
                            }
                        }
                    }
                    result = async { current.as_mut().unwrap().0.as_mut().await }, if current.is_some() => {
                        let (_, depth) = current.take().unwrap();
                        match result {
                            Ok(result) => {
                                if let Some(memory) = result.memory_updates {
                                    ctx.state.set_memory_for_client(id, memory).await;
                                }
                                if result.actions.len() > MAX_HANDLER_ACTIONS
                                    || actions.len() + result.actions.len() > MAX_HANDLER_ACTIONS {
                                    console_error!(ctx.status_tx, "InfluxDB handler action count limit");
                                    break;
                                }
                                actions.extend(result.actions.into_iter().map(|a| (a, depth + 1)));
                            }
                            Err(error) => console_error!(ctx.status_tx, "InfluxDB handler failed: {}", error),
                        }
                    }
                    command = commands.recv() => {
                        let Some(command) = command else { break; };
                        let prepared = prepare(&protocol, command.action.clone(), 0, &origin, &token);
                        match prepared {
                            Ok(Prepared::Disconnect) => {
                                finish(&ctx, command, Ok(ClientSendOutcome::Disconnected)).await;
                                break 'session;
                            }
                            Ok(Prepared::Exchange(exchange)) if pending.is_none() => {
                                pending = Some(Inflight { exchange, command: Some(command), depth: 0 });
                            }
                            Ok(Prepared::Exchange(_)) => finish(&ctx, command, Ok(ClientSendOutcome::Rejected {
                                error: "One request is already in flight".into(),
                            })).await,
                            Err(error) => finish(&ctx, command, Ok(ClientSendOutcome::Rejected {
                                error: error.to_string(),
                            })).await,
                        }
                    }
                }
                let _ = ctx.status_tx.send("__UPDATE_UI__".into());
            }
            if let Some(p) = pending.take() {
                if let Some(command) = p.command {
                    finish(
                        &ctx,
                        command,
                        Err(anyhow::anyhow!("InfluxDB request cancelled")),
                    )
                    .await;
                }
            }
            ctx.state.remove_client_handle(id).await;
            ctx.state
                .update_client_status(id, ClientStatus::Disconnected)
                .await;
            let _ = ctx.status_tx.send("__UPDATE_UI__".into());
        });
        registrar.register_client_task(id, task).await;
        Ok("0.0.0.0:0".parse().unwrap())
    }
}
enum Prepared {
    Disconnect,
    Exchange(Exchange),
}
fn prepare(
    protocol: &InfluxDbClientProtocol,
    action: Value,
    depth: usize,
    origin: &transport::Origin,
    token: &Option<String>,
) -> Result<Prepared> {
    match protocol.execute_action(action)? {
        ClientActionResult::Disconnect => Ok(Prepared::Disconnect),
        ClientActionResult::Custom { name, data } if name == "write_influx_points" => {
            anyhow::ensure!(depth <= MAX_FOLLOWUP_DEPTH, "write follow-up depth limit");
            let batch: WriteBatch = serde_json::from_value(data).context("invalid typed write")?;
            let body = codec::encode_batch(&batch)?;
            let exchange = transport::write(origin.clone(), token.clone(), batch, body);
            Ok(Prepared::Exchange(Box::pin(async move {
                let response = exchange.await?;
                Ok(Event::new(
                    &actions::INFLUX_RESPONSE_EVENT,
                    serde_json::to_value(response)?,
                ))
            })))
        }
        ClientActionResult::Custom { name, data } if name == actions::QUERY_RESULT => {
            anyhow::ensure!(depth <= MAX_FOLLOWUP_DEPTH, "query follow-up depth limit");
            let spec: query::QuerySpec = serde_json::from_value(data).context("invalid query")?;
            spec.validate()?;
            let exchange = query::query(origin.clone(), token.clone(), spec);
            Ok(Prepared::Exchange(Box::pin(async move {
                let response = exchange.await?;
                Ok(Event::new(
                    &actions::INFLUX_QUERY_RESPONSE_EVENT,
                    serde_json::to_value(response)?,
                ))
            })))
        }
        _ => anyhow::bail!("unsupported InfluxDB action result"),
    }
}
async fn finish(ctx: &ConnectContext, command: ClientCommand, result: Result<ClientSendOutcome>) {
    let outcome = match &result {
        Ok(outcome) => serde_json::to_value(outcome).unwrap_or(Value::Null),
        Err(error) => json!({"error":error.to_string()}),
    };
    ctx.state
        .record_access_log(
            AccessLogOwner::Client(ctx.client_id.as_u32()),
            "InfluxDB",
            None,
            "injected_action",
            command.action.clone(),
            vec![outcome],
        )
        .await;
    crate::client::command_support::reply(command, result);
}
