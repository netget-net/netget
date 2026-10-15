//! The client's cluster mode: the [`Router`] does the routing, this runs the conversation.
//!
//! A cluster has no single stream to read replies from, so this mode is request/response: one
//! work queue holds the model's commands and the dashboard's injected ones, a driver task runs
//! each to completion through the router, raises `redis_response_received` (with the node, the
//! slot and every redirection followed) and queues whatever the model answers. The model's
//! follow-ups run before anything injected later, in the order it gave them.
use super::cluster::{Routed, Router};
use super::{wire_for, Wire};
use crate::client::llm_budget::call_llm_for_client;
use crate::client::redis::actions::{
    RedisClientProtocol, REDIS_CLIENT_CONNECTED_EVENT, REDIS_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use anyhow::Result;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// One unit of work for the driver.
enum Work {
    Command(Vec<Vec<u8>>),
    Disconnect,
}

/// Turn one executed action into work, refusing what cluster mode cannot do.
fn work_for(
    result: crate::llm::actions::client_trait::ClientActionResult,
    client_id: ClientId,
) -> Result<Vec<Work>> {
    Ok(match wire_for(result, client_id)? {
        Wire::Disconnect => vec![Work::Disconnect],
        Wire::Nothing => vec![],
        Wire::Publish(args) => vec![Work::Command(args)],
        Wire::UnsubscribeAll => anyhow::bail!("pub/sub is not available in cluster mode"),
        Wire::Commands(commands) => {
            for args in &commands {
                let name = args
                    .first()
                    .map(|n| String::from_utf8_lossy(n).to_ascii_uppercase())
                    .unwrap_or_default();
                anyhow::ensure!(
                    !matches!(
                        name.as_str(),
                        "SUBSCRIBE"
                            | "PSUBSCRIBE"
                            | "SSUBSCRIBE"
                            | "UNSUBSCRIBE"
                            | "PUNSUBSCRIBE"
                            | "SUNSUBSCRIBE"
                            | "MONITOR"
                    ),
                    "{name} is not available in cluster mode: commands run one at a time to \
                     completion, and a subscription never completes"
                );
            }
            commands.into_iter().map(Work::Command).collect()
        }
    })
}

fn event_for(routed: &Routed) -> Event {
    let mut data = routed.reply.event_data();
    data["node"] = serde_json::Value::String(routed.node.clone());
    if let Some(slot) = routed.slot {
        data["slot"] = serde_json::Value::from(slot);
    }
    data["redirects"] = serde_json::json!(routed.redirects);
    if routed.exhausted {
        data["redirects_exhausted"] = serde_json::Value::Bool(true);
    }
    Event::new(&REDIS_CLIENT_RESPONSE_RECEIVED_EVENT, data)
}

/// Ask the model about one event and queue what it answers.
#[allow(clippy::too_many_arguments)]
async fn ask(
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    protocol: &RedisClientProtocol,
    client_id: ClientId,
    event: &Event,
    queue: &mut VecDeque<Work>,
) {
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
        Some(event),
        protocol,
        status_tx,
    )
    .await
    {
        Ok(result) => {
            if let Some(mem) = result.memory_updates {
                app_state.set_memory_for_client(client_id, mem).await;
            }
            for action in result.actions {
                match protocol
                    .execute_action(action)
                    .and_then(|r| work_for(r, client_id))
                {
                    Ok(work) => queue.extend(work),
                    Err(e) => {
                        error!(
                            "Redis cluster client {} could not execute action: {}",
                            client_id, e
                        );
                        let _ = status_tx.send(format!(
                            "[ERROR] Redis client {} action failed: {}",
                            client_id, e
                        ));
                    }
                }
            }
        }
        Err(e) => error!("LLM error for Redis cluster client {}: {}", client_id, e),
    }
}

/// Connect in cluster mode: read the slot map, tell the model, then run the work queue.
pub async fn connect(
    remote_addr: String,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) -> Result<SocketAddr> {
    let mut router = Router::connect(&remote_addr).await?;
    let local_addr = router
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("the seed connection closed"))?;
    let nodes = router.nodes();
    info!(
        "Redis cluster client {} connected via {}: {} master(s)",
        client_id,
        remote_addr,
        nodes.len()
    );
    app_state
        .update_client_status(client_id, ClientStatus::Connected)
        .await;
    let _ = status_tx.send(format!(
        "[CLIENT] Redis cluster client {} connected ({} masters)",
        client_id,
        nodes.len()
    ));
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    let protocol = Arc::new(RedisClientProtocol::new());

    // Injected commands join the same queue as the model's; the dashboard is answered once
    // the command is queued.
    let (work_tx, mut work_rx) = mpsc::unbounded_channel::<Work>();
    let mut command_rx =
        crate::client::command_support::register_command_channel(&app_state, client_id).await;
    let cmd_protocol = protocol.clone();
    let cmd_state = app_state.clone();
    let cmd_task = tokio::spawn(async move {
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match cmd_protocol
                .execute_action(action.clone())
                .and_then(|r| work_for(r, client_id))
            {
                Err(e) => ClientSendOutcome::Rejected {
                    error: e.to_string(),
                },
                Ok(work) => {
                    let mut bytes = 0;
                    let mut disconnect = false;
                    for item in work {
                        if let Work::Command(args) = &item {
                            bytes += super::resp::encode_command(args).len();
                        } else {
                            disconnect = true;
                        }
                        let _ = work_tx.send(item);
                    }
                    if disconnect {
                        ClientSendOutcome::Disconnected
                    } else {
                        ClientSendOutcome::Sent { bytes_sent: bytes }
                    }
                }
            };
            cmd_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    "Redis",
                    None,
                    "injected_action",
                    action,
                    vec![serde_json::to_value(&outcome).unwrap_or_default()],
                )
                .await;
            crate::client::command_support::reply(command, Ok(outcome));
        }
    });
    app_state.register_client_task(client_id, cmd_task).await;

    let mut queue: VecDeque<Work> = VecDeque::new();
    let connected = Event::new(
        &REDIS_CLIENT_CONNECTED_EVENT,
        serde_json::json!({
            "remote_addr": remote_addr,
            "cluster_nodes": nodes,
        }),
    );
    ask(
        &llm_client,
        &app_state,
        &status_tx,
        &protocol,
        client_id,
        &connected,
        &mut queue,
    )
    .await;

    let task_state = app_state.clone();
    let driver = tokio::spawn(async move {
        loop {
            let work = match queue.pop_front() {
                Some(work) => work,
                None => match work_rx.recv().await {
                    Some(work) => work,
                    None => break,
                },
            };
            let args = match work {
                Work::Disconnect => {
                    info!("Redis cluster client {} disconnecting", client_id);
                    break;
                }
                Work::Command(args) => args,
            };
            let routed = match router.execute(&args).await {
                Ok(routed) => routed,
                Err(e) => {
                    // A node that failed mid-exchange: the framing on that connection is gone
                    // and the command's fate is unknown, so the client stops rather than guess.
                    error!("Redis cluster client {} failed: {:#}", client_id, e);
                    task_state
                        .update_client_status(client_id, ClientStatus::Error(format!("{e:#}")))
                        .await;
                    task_state.remove_client_handle(client_id).await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    return;
                }
            };
            if !routed.redirects.is_empty() {
                info!(
                    "Redis cluster client {}: followed {} to {}",
                    client_id,
                    routed.redirects.join(", "),
                    routed.node
                );
            }
            if routed.exhausted {
                warn!(
                    "Redis cluster client {} decision=redirects_exhausted: {}",
                    client_id, routed.reply.response
                );
            }
            let event = event_for(&routed);
            ask(
                &llm_client,
                &task_state,
                &status_tx,
                &protocol,
                client_id,
                &event,
                &mut queue,
            )
            .await;
        }
        task_state.remove_client_handle(client_id).await;
        task_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Redis cluster client {} disconnected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    });
    app_state.register_client_task(client_id, driver).await;

    Ok(local_addr)
}
