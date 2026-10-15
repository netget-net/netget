//! Streaming wire lifetime and bounded, per-RPC semantic decisions.
use super::{actions, stream_codec, DynamicGrpcService, GrpcStatus};
use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt, Stream};
use hyper::{Request, Response};
use prost::Message;
use prost_reflect::{DynamicMessage, MessageDescriptor, MethodDescriptor};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{mpsc, OwnedSemaphorePermit},
    task::AbortHandle,
};
use tonic::{codec::CompressionEncoding, Status, Streaming};

pub(super) const DEFAULT_REFLECTION: bool = true;
pub(super) const DEFAULT_TIMEOUT_SECS: u64 = 300;
pub(super) const MAX_ACTIVE: usize = 64;
pub(super) const MAX_MESSAGES: usize = 256;
const MAX_PENDING: usize = 16;
const MAX_PENDING_BYTES: usize = stream_codec::MAX_MESSAGE_BYTES;
pub(crate) type Registry = Arc<Mutex<HashMap<u32, Entry>>>;

#[derive(Clone, Default)]
pub(crate) struct OwnedExecutor(Arc<Children>);
#[derive(Default)]
struct Children {
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    closed: AtomicBool,
}
pub(crate) struct ConnectionTasks(pub OwnedExecutor);
impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        let mut tasks = self.0 .0.tasks.lock().unwrap_or_else(|e| e.into_inner());
        self.0 .0.closed.store(true, Ordering::Relaxed);
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}
impl OwnedExecutor {
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> Option<AbortHandle> {
        let mut tasks = self.0.tasks.lock().unwrap_or_else(|e| e.into_inner());
        if self.0.closed.load(Ordering::Relaxed) {
            return None;
        }
        tasks.retain(|task| !task.is_finished());
        let task = tokio::spawn(future);
        let abort = task.abort_handle();
        tasks.push(task);
        Some(abort)
    }
    pub(crate) fn deadline(&self, deadline: tokio::time::Instant) -> Result<DeadlineGuard, Status> {
        let id = tokio::task::try_id().ok_or_else(|| Status::internal("missing stream owner"))?;
        let owner = self
            .0
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|task| task.id() == id)
            .map(|task| task.abort_handle())
            .ok_or_else(|| Status::internal("missing stream owner"))?;
        let timer = self
            .spawn(async move {
                tokio::time::sleep_until(deadline).await;
                // This also cancels an outgoing stream stalled behind HTTP/2 flow control.
                owner.abort();
            })
            .ok_or_else(|| Status::cancelled("connection closed"))?;
        Ok(DeadlineGuard {
            timer,
            deadline,
            retain_expired: false,
        })
    }
}
impl<F> hyper::rt::Executor<F> for OwnedExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let _ = self.spawn(async move {
            let _ = future.await;
        });
    }
}
pub(crate) struct DeadlineGuard {
    timer: AbortHandle,
    deadline: tokio::time::Instant,
    retain_expired: bool,
}
impl DeadlineGuard {
    /// HTTP/1 can continue draining an unfinished request after a timeout response
    /// reaches body EOS. Its expired hard timer must still cancel that connection owner.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn retain_expired(mut self) -> Self {
        self.retain_expired = true;
        self
    }
}
impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        if !self.retain_expired || tokio::time::Instant::now() < self.deadline {
            self.timer.abort();
        }
    }
}

/// The response body keeps admission, activity and the hard timer until EOS/drop.
pub(super) struct BodyGuard {
    pub body: tonic::body::BoxBody,
    pub _permit: OwnedSemaphorePermit,
    pub _busy: crate::server::accept_bounded::BusyGuard,
    pub _timer: DeadlineGuard,
}
impl hyper::body::Body for BodyGuard {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Status>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

pub(crate) fn timeout(headers: &hyper::HeaderMap, maximum: Duration) -> Result<Duration, Status> {
    let mut values = headers.get_all("grpc-timeout").iter();
    let Some(value) = values.next() else {
        return Ok(maximum);
    };
    if values.next().is_some() {
        return Err(Status::invalid_argument("duplicate grpc-timeout"));
    }
    let value = value
        .to_str()
        .map_err(|_| Status::invalid_argument("invalid grpc-timeout"))?;
    if !(2..=9).contains(&value.len()) {
        return Err(Status::invalid_argument("invalid grpc-timeout"));
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Status::invalid_argument("invalid grpc-timeout"));
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| Status::invalid_argument("invalid grpc-timeout"))?;
    let nanos = match unit {
        "H" => n.checked_mul(3_600_000_000_000),
        "M" => n.checked_mul(60_000_000_000),
        "S" => n.checked_mul(1_000_000_000),
        "m" => n.checked_mul(1_000_000),
        "u" => n.checked_mul(1000),
        "n" => Some(n),
        _ => None,
    }
    .ok_or_else(|| Status::invalid_argument("invalid grpc-timeout"))?;
    Ok(maximum.min(Duration::from_nanos(nanos)))
}

pub(super) enum Command {
    Send(DynamicMessage),
    Finish,
    Cancel,
}
pub(crate) struct Entry {
    sender: mpsc::Sender<Command>,
    output: MessageDescriptor,
    input_closed: Arc<AtomicBool>,
    client_streaming: bool,
    server_streaming: bool,
}
struct Registration {
    registry: Registry,
    id: u32,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

pub(super) async fn command_loop(
    mut commands: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    registry: Registry,
    service: Arc<DynamicGrpcService>,
    connection: crate::server::connection::ConnectionId,
) {
    use crate::state::client_handles::ClientSendOutcome;
    while let Some(command) = commands.recv().await {
        let action = command.action.clone();
        let result = (|| -> anyhow::Result<()> {
            service.protocol.execute_action(action.clone())?;
            let id = action["stream_id"]
                .as_u64()
                .and_then(|id| u32::try_from(id).ok())
                .filter(|id| *id != 0)
                .ok_or_else(|| anyhow::anyhow!("stream_id must be 1..4294967295"))?;
            let registry = registry.lock().unwrap_or_else(|e| e.into_inner());
            let entry = registry
                .get(&id)
                .ok_or_else(|| anyhow::anyhow!("stream is no longer active"))?;
            let item = match action["type"].as_str() {
                Some("grpc_stream_send") => {
                    anyhow::ensure!(
                        entry.server_streaming || entry.input_closed.load(Ordering::Relaxed),
                        "client-streaming response requires input half-close"
                    );
                    Command::Send(stream_codec::from_json(&action["message"], &entry.output)?)
                }
                Some("grpc_stream_finish") => {
                    anyhow::ensure!(
                        !entry.client_streaming || entry.input_closed.load(Ordering::Relaxed),
                        "finish requires input half-close"
                    );
                    Command::Finish
                }
                Some("grpc_stream_cancel") => Command::Cancel,
                _ => anyhow::bail!("only stream send/finish/cancel may be injected"),
            };
            entry
                .sender
                .try_send(item)
                .map_err(|_| anyhow::anyhow!("stream command queue full or closed"))?;
            Ok(())
        })();
        let outcome = result.map(|()| ClientSendOutcome::Executed {
            detail: "stream control queued".into(),
        });
        let report = match &outcome {
            Ok(value) => serde_json::to_value(value).unwrap_or(Value::Null),
            Err(error) => json!({"error":error.to_string()}),
        };
        service
            .app_state
            .record_access_log(
                crate::state::AccessLogOwner::Server(service.server_id.as_u32()),
                service.protocol.protocol_name(),
                Some(connection.as_u32()),
                "injected_action",
                action,
                vec![report],
            )
            .await;
        crate::client::command_support::reply(command, outcome);
    }
}

type Replies = Pin<Box<dyn Stream<Item = Result<DynamicMessage, Status>> + Send>>;
type Decision = BoxFuture<'static, Result<Vec<crate::llm::ActionResult>, Status>>;
struct Handler {
    service: Arc<DynamicGrpcService>,
    connection: crate::server::connection::ConnectionId,
    method: MethodDescriptor,
    registry: Registry,
    deadline: tokio::time::Instant,
    id: u32,
}
impl tonic::server::StreamingService<DynamicMessage> for Handler {
    type Response = DynamicMessage;
    type ResponseStream = Replies;
    type Future = BoxFuture<'static, Result<tonic::Response<Replies>, Status>>;
    fn call(&mut self, request: tonic::Request<Streaming<DynamicMessage>>) -> Self::Future {
        let service = self.service.clone();
        let method = self.method.clone();
        let registry = self.registry.clone();
        let deadline = self.deadline;
        let connection = self.connection;
        let id = self.id;
        async move {
            let input_closed = Arc::new(AtomicBool::new(false));
            let (sender, commands) = mpsc::channel(1);
            {
                let mut entries = registry.lock().unwrap_or_else(|e| e.into_inner());
                if entries.len() >= 16 {
                    return Err(Status::unavailable("connection at stream capacity"));
                }
                entries.insert(
                    id,
                    Entry {
                        sender,
                        output: method.output(),
                        input_closed: input_closed.clone(),
                        client_streaming: method.is_client_streaming(),
                        server_streaming: method.is_server_streaming(),
                    },
                );
            }
            #[cfg(not(target_arch = "wasm32"))]
            let http_metadata = request
                .extensions()
                .get::<crate::server::connect_rpc::wire::RpcMetadata>()
                .cloned();
            let state = Controller {
                #[cfg(not(target_arch = "wasm32"))]
                http_metadata,
                service,
                connection,
                method,
                id,
                input: request.into_inner(),
                input_closed,
                commands,
                _registration: Registration { registry, id },
                deadline,
                opened: false,
                pending: VecDeque::new(),
                pending_bytes: 0,
                finished: false,
                input_count: 0,
                output_count: 0,
                event_count: 0,
                handler: None,
                tick: None,
            };
            let replies = futures::stream::unfold(state, |mut state| async move {
                state.next().await.map(|item| (item, state))
            });
            Ok(tonic::Response::new(Box::pin(replies) as Replies))
        }
        .boxed()
    }
}

struct Controller {
    #[cfg(not(target_arch = "wasm32"))]
    http_metadata: Option<crate::server::connect_rpc::wire::RpcMetadata>,
    service: Arc<DynamicGrpcService>,
    connection: crate::server::connection::ConnectionId,
    method: MethodDescriptor,
    id: u32,
    input: Streaming<DynamicMessage>,
    input_closed: Arc<AtomicBool>,
    commands: mpsc::Receiver<Command>,
    _registration: Registration,
    deadline: tokio::time::Instant,
    opened: bool,
    pending: VecDeque<DynamicMessage>,
    pending_bytes: usize,
    finished: bool,
    input_count: usize,
    output_count: usize,
    event_count: usize,
    handler: Option<Decision>,
    tick: Option<tokio::time::Instant>,
}
impl Controller {
    fn event(
        &mut self,
        kind: &'static crate::protocol::EventType,
        message: Option<Value>,
    ) -> Result<(), Status> {
        if self.event_count >= MAX_MESSAGES + 2 {
            return Err(Status::resource_exhausted("stream exceeds event limit"));
        }
        self.event_count += 1;
        #[cfg(not(target_arch = "wasm32"))]
        let kind = if self.http_metadata.is_some() {
            crate::server::connect_rpc::actions::event_type(&kind.id).unwrap_or(kind)
        } else {
            kind
        };
        let mut event = crate::protocol::Event::new(
            kind,
            json!({
                "stream_id": self.id, "service": self.method.parent_service().full_name(), "method": self.method.name(),
                "client_streaming": self.method.is_client_streaming(), "server_streaming": self.method.is_server_streaming(),
                "message": message, "input_count": self.input_count, "output_count": self.output_count,
                "expected_response_schema": DynamicGrpcService::build_message_schema(&self.method.output()),
            }),
        );
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(metadata) = &self.http_metadata {
            event.data["metadata"] = metadata.request.clone();
        }
        let service = self.service.clone();
        let connection = self.connection;
        self.handler = Some(
            async move {
                crate::llm::action_helper::call_llm(
                    &service.llm_client,
                    &service.app_state,
                    service.server_id,
                    Some(connection),
                    &event,
                    service.protocol.as_ref(),
                )
                .await
                .map(|result| result.protocol_results)
                .map_err(|error| {
                    Status::new(
                        tonic::Code::from_i32(super::grpc_status_for_llm_failure(&error) as i32),
                        crate::utils::WireFailure::classify(&error).prefixed_text(),
                    )
                })
            }
            .boxed(),
        );
        Ok(())
    }
    fn send(&mut self, message: DynamicMessage) -> Result<(), Status> {
        if !self.method.is_server_streaming() && !self.input_closed.load(Ordering::Relaxed) {
            return Err(Status::failed_precondition(
                "client-streaming response requires input half-close",
            ));
        }
        let maximum = if self.method.is_server_streaming() {
            MAX_MESSAGES
        } else {
            1
        };
        if self.output_count >= maximum
            || self.pending.len() >= MAX_PENDING
            || message.encoded_len() > MAX_PENDING_BYTES.saturating_sub(self.pending_bytes)
        {
            return Err(Status::resource_exhausted(
                "stream response count or queue limit exceeded",
            ));
        }
        self.output_count += 1;
        self.pending_bytes += message.encoded_len();
        self.pending.push_back(message);
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Status> {
        if !self.method.is_server_streaming()
            && (!self.input_closed.load(Ordering::Relaxed) || self.output_count != 1)
        {
            return Err(Status::failed_precondition(
                "client-streaming success requires half-close and one response",
            ));
        }
        self.finished = true;
        self.handler = None;
        Ok(())
    }
    fn controls(&mut self, actions: Vec<crate::llm::ActionResult>) -> Result<(), Status> {
        if actions.len() > MAX_PENDING {
            return Err(Status::resource_exhausted(
                "stream handler exceeds 16 actions",
            ));
        }
        let mut usable = false;
        for action in actions {
            match action {
                crate::llm::ActionResult::Custom { name, data } => match name.as_str() {
                    #[cfg(not(target_arch = "wasm32"))]
                    "connect_rpc_metadata" => {
                        usable = true;
                        self.http_metadata
                            .as_ref()
                            .ok_or_else(|| {
                                Status::invalid_argument(
                                    "Connect metadata requires Connect transport",
                                )
                            })?
                            .apply(&data)?;
                    }
                    "grpc_stream_send" => {
                        usable = true;
                        let message =
                            stream_codec::from_json(&data["message"], &self.method.output())
                                .map_err(|_| {
                                    Status::invalid_argument(
                                        "response does not fit typed stream schema",
                                    )
                                })?;
                        self.send(message)?;
                    }
                    "grpc_stream_finish" => {
                        usable = true;
                        self.finish()?;
                        break;
                    }
                    "grpc_stream_cancel" => {
                        return Err(Status::cancelled("stream cancelled by handler"))
                    }
                    "grpc_stream_wait" => {
                        usable = true;
                        self.tick = Some(
                            tokio::time::Instant::now()
                                + Duration::from_millis(
                                    data["milliseconds"].as_u64().unwrap_or(100),
                                ),
                        );
                    }
                    "grpc_error" => {
                        let code = GrpcStatus::parse(data["code"].as_str().unwrap_or("INTERNAL"));
                        let code = if code == GrpcStatus::Ok {
                            GrpcStatus::Unknown
                        } else {
                            code
                        };
                        return Err(Status::new(
                            tonic::Code::from_i32(code as i32),
                            super::header_safe(
                                data["message"].as_str().unwrap_or("stream refused"),
                            ),
                        ));
                    }
                    _ => {}
                },
                crate::llm::ActionResult::WaitForMore => {
                    usable = true;
                }
                _ => {}
            }
        }
        if !usable {
            return Err(Status::internal("stream handler supplied no control"));
        }
        Ok(())
    }
    async fn input_message(&mut self, message: DynamicMessage) -> Result<Value, Status> {
        if self.input_count >= MAX_MESSAGES {
            return Err(Status::resource_exhausted(
                "stream exceeds 256 input messages",
            ));
        }
        self.input_count += 1;
        let value = stream_codec::to_json(&message).map_err(|error| {
            Status::new(
                tonic::Code::from_i32(super::grpc_status_for_value_failure(&error) as i32),
                "request does not fit typed stream values",
            )
        })?;
        self.service
            .app_state
            .update_connection_stats(
                self.service.server_id,
                self.connection,
                Some(u64::try_from(message.encoded_len()).unwrap_or(u64::MAX)),
                None,
                Some(1),
                None,
            )
            .await;
        Ok(value)
    }
    async fn step(&mut self) -> Result<Option<DynamicMessage>, Status> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                self.pending_bytes -= message.encoded_len();
                return Ok(Some(message));
            }
            if self.finished {
                return Ok(None);
            }
            if !self.opened {
                self.opened = true;
                let message = if !self.method.is_client_streaming() {
                    let message = self.input.message().await?.ok_or_else(|| {
                        Status::invalid_argument("server-streaming requires one request")
                    })?;
                    let value = self.input_message(message).await?;
                    if self.input.message().await?.is_some() {
                        return Err(Status::invalid_argument(
                            "server-streaming requires one request",
                        ));
                    }
                    self.input_closed.store(true, Ordering::Relaxed);
                    Some(value)
                } else {
                    None
                };
                self.event(&actions::GRPC_STREAM_OPENED_EVENT, message)?;
            }
            tokio::select! {
                Some(command) = self.commands.recv() => match command {
                    Command::Send(message) => self.send(message)?,
                    Command::Finish => self.finish()?,
                    Command::Cancel => return Err(Status::cancelled("stream cancelled by operator")),
                },
                result = async { self.handler.as_mut().unwrap().await }, if self.handler.is_some() => {
                    self.handler = None;
                    self.controls(result?)?;
                }
                message = self.input.message(), if self.handler.is_none() && !self.input_closed.load(Ordering::Relaxed) => {
                    match message? {
                        Some(message) => { let value = self.input_message(message).await?; self.event(&actions::GRPC_STREAM_MESSAGE_EVENT, Some(value))?; }
                        None => { self.input_closed.store(true, Ordering::Relaxed); self.event(&actions::GRPC_STREAM_INPUT_CLOSED_EVENT, None)?; }
                    }
                }
                _ = tokio::time::sleep_until(self.tick.unwrap_or(self.deadline)), if self.handler.is_none() && self.tick.is_some() => {
                    self.tick = None;
                    self.event(&actions::GRPC_STREAM_TICK_EVENT, None)?;
                }
                _ = tokio::time::sleep_until(self.deadline) => return Err(Status::deadline_exceeded("stream deadline exceeded")),
            }
        }
    }
    async fn next(&mut self) -> Option<Result<DynamicMessage, Status>> {
        match tokio::time::timeout_at(self.deadline, self.step()).await {
            Ok(Ok(Some(message))) => Some(Ok(message)),
            Ok(Ok(None)) => None,
            Ok(Err(status)) => {
                self.finished = true;
                self.pending.clear();
                self.handler = None;
                Some(Err(status))
            }
            Err(_) => {
                self.finished = true;
                self.pending.clear();
                self.handler = None;
                Some(Err(Status::deadline_exceeded("stream deadline exceeded")))
            }
        }
    }
}

pub(super) async fn dispatch(
    request: Request<tonic::body::BoxBody>,
    service: Arc<DynamicGrpcService>,
    connection: crate::server::connection::ConnectionId,
    method: MethodDescriptor,
    registry: Registry,
    deadline: tokio::time::Instant,
    id: u32,
) -> Response<tonic::body::BoxBody> {
    if let Err(error) = stream_codec::check_descriptor(&method.input())
        .and_then(|()| stream_codec::check_descriptor(&method.output()))
    {
        return Status::unimplemented(error.to_string()).into_http();
    }
    let codec = stream_codec::DynamicCodec {
        encode: method.output(),
        decode: method.input(),
    };
    let handler = Handler {
        service,
        connection,
        method,
        registry,
        deadline,
        id,
    };
    tonic::server::Grpc::new(codec)
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(stream_codec::MAX_MESSAGE_BYTES)
        .max_encoding_message_size(stream_codec::MAX_MESSAGE_BYTES)
        .streaming(handler, request)
        .await
}
