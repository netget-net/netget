//! Modbus/TCP client: NetGet is the master, the model decides what to read and write.
//!
//! Three tasks per connection, all registered with the client:
//!
//! * **transport** owns the socket. It frames requests with the shared codec, puts one
//!   transaction on the wire at a time, checks the response against it by transaction id, and
//!   reports a request left unanswered past [`RESPONSE_TIMEOUT`]. It never waits on the model.
//! * **turns** asks the model about each response, in order, and hands its actions back to the
//!   transport. The chain request → response → model → request passes through that queue, so it
//!   needs no recursion.
//! * **commands** runs injected actions (`[ send ]`, MCP `send_to_client`) down the same path.

pub mod actions;

pub use actions::ModbusClientProtocol;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::modbus::actions::{
    request_from_action, MODBUS_CONNECTED_EVENT, MODBUS_ERROR_EVENT, MODBUS_EXCEPTION_EVENT,
    MODBUS_READ_RESPONSE_EVENT, MODBUS_WRITE_RESPONSE_EVENT, REQUEST_RESULT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::modbus::codec::{
    encode_adu, encode_request, exception_name, parse_response, try_parse_adu, ModbusRequest,
    ModbusResponse,
};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// How long a request may go unanswered before the model is told it timed out.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Requests accepted and not yet answered — the one on the wire plus those queued behind it.
/// The next one is refused.
pub const MAX_QUEUED: usize = 32;

const TURN_QUEUE_CAPACITY: usize = 256;
const OUTBOUND_CAPACITY: usize = 64;

enum Outbound {
    Request {
        unit_id: u8,
        request: ModbusRequest,
        ack: oneshot::Sender<Result<Accepted, String>>,
    },
    Disconnect {
        ack: oneshot::Sender<()>,
    },
}

/// What the transport did with a request it accepted.
enum Accepted {
    /// Written now: this many octets.
    Written(usize),
    /// Queued behind this many requests; written when they are answered.
    Queued(usize),
}

/// The one request on the wire.
struct InFlight {
    tid: u16,
    unit_id: u8,
    request: ModbusRequest,
    deadline: Instant,
}

enum Applied {
    Sent(usize),
    Queued(usize),
    Nothing,
    Disconnect,
}

pub struct ModbusClient;

impl ModbusClient {
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        unit_id: u8,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "Modbus client needs a remote_addr (host:port); refusing to connect without one"
            ));
        }
        let stream = TcpStream::connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to Modbus device at {remote_addr}"))?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        info!("Modbus client {client_id} connected to {peer} (unit {unit_id})");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] Modbus client {client_id} connected"));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(ModbusClientProtocol::new());
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(OUTBOUND_CAPACITY);
        let (turn_tx, turn_rx) = mpsc::channel::<Event>(TURN_QUEUE_CAPACITY);

        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        app_state
            .spawn_client_task(
                client_id,
                command_loop(
                    command_rx,
                    protocol.clone(),
                    outbound_tx.clone(),
                    unit_id,
                    client_id,
                    app_state.clone(),
                    status_tx.clone(),
                ),
            )
            .await;

        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                run_turns(
                    turn_rx,
                    outbound_tx,
                    protocol,
                    unit_id,
                    llm_client,
                    app_state.clone(),
                    status_tx.clone(),
                    client_id,
                ),
            )
            .await;

        let _ = turn_tx.try_send(Event::new(
            &MODBUS_CONNECTED_EVENT,
            json!({"remote_addr": peer.to_string(), "unit_id": unit_id}),
        ));
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    stream,
                    outbound_rx,
                    turn_tx,
                    app_state.clone(),
                    status_tx,
                    client_id,
                    turn_abort,
                ),
            )
            .await;
        Ok(local_addr)
    }
}

/// The values a request carried (writes) or that its response carried (reads), as JSON.
fn values_json(request: &ModbusRequest) -> Value {
    match request {
        ModbusRequest::WriteSingleCoil { value, .. } => json!([value]),
        ModbusRequest::WriteSingleRegister { value, .. } => json!([value]),
        ModbusRequest::WriteMultipleCoils { values, .. } => json!(values),
        ModbusRequest::WriteMultipleRegisters { values, .. } => json!(values),
        _ => json!([]),
    }
}

/// The event one matched response becomes.
fn event_for(pending: &InFlight, response_unit: u8, pdu: &[u8]) -> Event {
    let request = &pending.request;
    let base = |mut data: Value| {
        data["function"] = json!(request.function_name());
        data["address"] = json!(request.start_address());
        data
    };
    if response_unit != pending.unit_id {
        return Event::new(
            &MODBUS_ERROR_EVENT,
            base(json!({
                "kind": "unit_mismatch",
                "message": format!(
                    "the request went to unit {} and the reply came from unit {response_unit}",
                    pending.unit_id
                ),
            })),
        );
    }
    match parse_response(pdu, request) {
        Ok(ModbusResponse::Bits(bits)) => Event::new(
            &MODBUS_READ_RESPONSE_EVENT,
            base(json!({
                "unit_id": pending.unit_id,
                "quantity": request.quantity(),
                "values": bits,
            })),
        ),
        Ok(ModbusResponse::Registers(regs)) => Event::new(
            &MODBUS_READ_RESPONSE_EVENT,
            base(json!({
                "unit_id": pending.unit_id,
                "quantity": request.quantity(),
                "values": regs,
            })),
        ),
        Ok(ModbusResponse::WriteAck) => Event::new(
            &MODBUS_WRITE_RESPONSE_EVENT,
            base(json!({
                "unit_id": pending.unit_id,
                "quantity": request.quantity(),
                "values": values_json(request),
            })),
        ),
        Ok(ModbusResponse::Exception { code }) => Event::new(
            &MODBUS_EXCEPTION_EVENT,
            base(json!({
                "unit_id": pending.unit_id,
                "code": code,
                "name": exception_name(code),
            })),
        ),
        Err(message) => Event::new(
            &MODBUS_ERROR_EVENT,
            base(json!({"kind": "bad_response", "message": message})),
        ),
    }
}

fn enqueue(turn_tx: &mpsc::Sender<Event>, event: Event, client_id: ClientId) {
    if turn_tx.try_send(event).is_err() {
        warn!(
            "Modbus client {client_id} dropped a response: the model is {TURN_QUEUE_CAPACITY} \
             events behind decision=turn_queue_full"
        );
    }
}

/// A request accepted by the transport and not yet written.
struct Queued {
    unit_id: u8,
    request: ModbusRequest,
    pdu: Vec<u8>,
}

/// Write the next queued request if nothing is on the wire. Returns the octets written, or
/// `None` when nothing was written.
async fn pump<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    queue: &mut VecDeque<Queued>,
    in_flight: &mut Option<InFlight>,
    next_tid: &mut u16,
    client_id: ClientId,
) -> std::io::Result<Option<usize>> {
    if in_flight.is_some() {
        return Ok(None);
    }
    let Some(next) = queue.pop_front() else {
        return Ok(None);
    };
    let tid = *next_tid;
    *next_tid = next_tid.wrapping_add(1);
    let frame = encode_adu(tid, next.unit_id, &next.pdu)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    debug!(
        "Modbus client {client_id} sent {} tid {tid} unit {}",
        next.request.function_name(),
        next.unit_id
    );
    *in_flight = Some(InFlight {
        tid,
        unit_id: next.unit_id,
        request: next.request,
        deadline: Instant::now() + RESPONSE_TIMEOUT,
    });
    Ok(Some(frame.len()))
}

/// Own the socket for the life of the connection.
///
/// **One transaction on the wire at a time.** The Modbus/TCP implementation guide lets a master
/// pipeline, but a device may accept one outstanding transaction, and pymodbus 3.15 silently
/// drops the second of two ADUs that arrive in one segment. A master that pipelines therefore
/// loses requests against real devices, with no error at either end. Requests queue here, and
/// the next is written when the previous one is answered or times out.
async fn run_transport(
    stream: TcpStream,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    turn_tx: mpsc::Sender<Event>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    turn_abort: tokio::task::AbortHandle,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut queue: VecDeque<Queued> = VecDeque::new();
    let mut in_flight: Option<InFlight> = None;
    let mut next_tid: u16 = 1;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let status = loop {
        let deadline = in_flight.as_ref().map(|f| f.deadline);
        tokio::select! {
            read = reader.read(&mut chunk) => {
                let n = match read {
                    Ok(0) => {
                        info!("Modbus client {client_id} closed by the device");
                        break ClientStatus::Disconnected;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        error!("Modbus client {client_id} read error: {e}");
                        break ClientStatus::Error(e.to_string());
                    }
                };
                buf.extend_from_slice(&chunk[..n]);
                // Every ADU is at most MAX_ADU_LEN octets and `try_parse_adu` refuses a longer
                // declared length, so the buffer never holds more than one incomplete frame
                // plus one read.
                let mut fatal = None;
                loop {
                    match try_parse_adu(&buf) {
                        Ok(None) => break,
                        Ok(Some((adu, used))) => {
                            buf.drain(..used);
                            match in_flight.take() {
                                Some(f) if f.tid == adu.transaction_id => {
                                    let event = event_for(&f, adu.unit_id, &adu.pdu);
                                    enqueue(&turn_tx, event, client_id);
                                }
                                other => {
                                    in_flight = other;
                                    warn!(
                                        "Modbus client {client_id} got a response for \
                                         transaction {} that is not in flight \
                                         decision=unmatched_response",
                                        adu.transaction_id
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            fatal = Some(e.to_string());
                            break;
                        }
                    }
                }
                if let Some(e) = fatal {
                    error!("Modbus client {client_id} framing error: {e}");
                    break ClientStatus::Error(e);
                }
            }
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if let Some(f) = in_flight.take() {
                    warn!(
                        "Modbus client {client_id} transaction {} unanswered after \
                         {RESPONSE_TIMEOUT:?} decision=timeout",
                        f.tid
                    );
                    enqueue(
                        &turn_tx,
                        Event::new(
                            &MODBUS_ERROR_EVENT,
                            json!({
                                "kind": "timeout",
                                "message": format!(
                                    "no response within {} seconds",
                                    RESPONSE_TIMEOUT.as_secs()
                                ),
                                "function": f.request.function_name(),
                                "address": f.request.start_address(),
                            }),
                        ),
                        client_id,
                    );
                }
            }
            out = outbound_rx.recv() => match out {
                None => break ClientStatus::Disconnected,
                Some(Outbound::Disconnect { ack }) => {
                    let _ = writer.shutdown().await;
                    let _ = ack.send(());
                    info!("Modbus client {client_id} disconnected on request");
                    break ClientStatus::Disconnected;
                }
                Some(Outbound::Request { unit_id, request, ack }) => {
                    if queue.len() + usize::from(in_flight.is_some()) >= MAX_QUEUED {
                        let _ = ack.send(Err(format!(
                            "{MAX_QUEUED} requests are already waiting for a response"
                        )));
                        continue;
                    }
                    let pdu = match encode_request(&request) {
                        Ok(pdu) => pdu,
                        Err(e) => {
                            let _ = ack.send(Err(e));
                            continue;
                        }
                    };
                    queue.push_back(Queued { unit_id, request, pdu });
                    let ahead = queue.len() - 1 + usize::from(in_flight.is_some());
                    match pump(&mut writer, &mut queue, &mut in_flight, &mut next_tid, client_id)
                        .await
                    {
                        Ok(Some(bytes)) => {
                            let _ = ack.send(Ok(Accepted::Written(bytes)));
                        }
                        Ok(None) => {
                            let _ = ack.send(Ok(Accepted::Queued(ahead)));
                        }
                        Err(e) => {
                            let _ = ack.send(Err(format!("write failed: {e}")));
                            error!("Modbus client {client_id} write error: {e}");
                            break ClientStatus::Error(e.to_string());
                        }
                    }
                    continue;
                }
            }
        }
        // A response or a timeout freed the wire: send the next queued request.
        if let Err(e) = pump(
            &mut writer,
            &mut queue,
            &mut in_flight,
            &mut next_tid,
            client_id,
        )
        .await
        {
            error!("Modbus client {client_id} write error: {e}");
            break ClientStatus::Error(e.to_string());
        }
    };

    turn_abort.abort();
    app_state.remove_client_handle(client_id).await;
    app_state.update_client_status(client_id, status).await;
    let _ = status_tx.send(format!("[CLIENT] Modbus client {client_id} disconnected"));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Answer queued events with the model, one at a time, in arrival order.
#[allow(clippy::too_many_arguments)]
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Event>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<ModbusClientProtocol>,
    unit_id: u8,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) {
    while let Some(event) = turn_rx.recv().await {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            continue;
        };
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
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
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                info!(
                    "Modbus client {client_id} {} decision={} actions={}",
                    event.id(),
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    match apply_action(protocol.as_ref(), &outbound_tx, unit_id, action).await {
                        Ok(Applied::Disconnect) => return,
                        Ok(_) => {}
                        Err(e) => {
                            Log::to(&status_tx)
                                .error(format!("Modbus client {client_id} action failed: {e}"));
                        }
                    }
                }
            }
            Err(e) => error!(
                "Modbus client {client_id} {} decision=llm_error: {e}",
                event.id()
            ),
        }
    }
}

/// Execute one action and hand its request to the transport. Shared by the model's turns and
/// injected commands.
async fn apply_action(
    protocol: &ModbusClientProtocol,
    outbound_tx: &mpsc::Sender<Outbound>,
    default_unit: u8,
    action: Value,
) -> Result<Applied> {
    match protocol.execute_action(action)? {
        ClientActionResult::Custom { name, data } if name == REQUEST_RESULT => {
            let parsed = request_from_action(&data)?
                .ok_or_else(|| anyhow!("a request action produced no request"))?;
            let (ack, done) = oneshot::channel();
            outbound_tx
                .send(Outbound::Request {
                    unit_id: parsed.unit_id.unwrap_or(default_unit),
                    request: parsed.request,
                    ack,
                })
                .await
                .map_err(|_| anyhow!("the connection is closed"))?;
            match done
                .await
                .map_err(|_| anyhow!("the connection closed before the request was accepted"))?
                .map_err(|e| anyhow!(e))?
            {
                Accepted::Written(bytes) => Ok(Applied::Sent(bytes)),
                Accepted::Queued(ahead) => Ok(Applied::Queued(ahead)),
            }
        }
        ClientActionResult::Disconnect => {
            let (ack, done) = oneshot::channel();
            if outbound_tx.send(Outbound::Disconnect { ack }).await.is_ok() {
                let _ = done.await;
            }
            Ok(Applied::Disconnect)
        }
        _ => Ok(Applied::Nothing),
    }
}

async fn command_loop(
    mut command_rx: mpsc::Receiver<ClientCommand>,
    protocol: Arc<ModbusClientProtocol>,
    outbound_tx: mpsc::Sender<Outbound>,
    unit_id: u8,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome = match apply_action(protocol.as_ref(), &outbound_tx, unit_id, action.clone())
            .await
        {
            Ok(Applied::Sent(bytes_sent)) => ClientSendOutcome::Sent { bytes_sent },
            Ok(Applied::Queued(ahead)) => ClientSendOutcome::Executed {
                detail: format!("queued behind {ahead} request(s); written when they are answered"),
            },
            Ok(Applied::Nothing) => ClientSendOutcome::Executed {
                detail: "executed (nothing to write)".to_string(),
            },
            Ok(Applied::Disconnect) => ClientSendOutcome::Disconnected,
            Err(e) => ClientSendOutcome::Rejected {
                error: e.to_string(),
            },
        };
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or_default()],
            )
            .await;
        let disconnect = matches!(outcome, ClientSendOutcome::Disconnected);
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, Ok(outcome));
        if disconnect {
            break;
        }
    }
}
