//! One HTTP/1.1 owner polls the transport, RPC and bounded event handlers.
use crate::server::grpc::stream_codec::{self, DynamicCodec};
#[cfg(not(target_arch = "wasm32"))]
use crate::server::grpc_web::wire;
use crate::{
    client::{command_support, llm_budget::call_llm_for_client},
    llm::actions::client_trait::{Client, ClientActionResult},
    protocol::{ConnectContext, Event},
    state::{
        client_handles::{ClientCommand, ClientSendOutcome},
        AccessLogOwner, ClientStatus,
    },
};

use anyhow::{ensure, Context, Result};
use futures::{
    future::{AbortHandle, Abortable, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use http_body_util::BodyExt;
use hyper::{client::conn::http1, Request, Response};
use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor};
use serde_json::{json, Value};
use std::{
    collections::{HashSet, VecDeque},
    net::{Shutdown, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, Mutex};
use tonic::{body::BoxBody, codec::CompressionEncoding, Status};
type Handler = BoxFuture<'static, (u8, Result<Vec<Value>>)>;
type Operation = BoxFuture<'static, (u32, u8, Event)>;
const MAX_HANDLERS: usize = 16;
const MAX_RESPONSE_MESSAGES: usize = 256;
const MAX_FOLLOWUP: u8 = 4;
const CONNECT_DEPTH: u8 = u8::MAX;
#[derive(Clone, Copy)]
pub(crate) enum Binding {
    #[cfg(not(target_arch = "wasm32"))]
    GrpcWeb,
    #[cfg(not(target_arch = "wasm32"))]
    ConnectRpc,
}
impl Binding {
    fn protocol(self) -> Arc<dyn Client> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::GrpcWeb => Arc::new(crate::client::grpc_web::actions::GrpcWebClientProtocol),
            #[cfg(not(target_arch = "wasm32"))]
            Self::ConnectRpc => {
                Arc::new(crate::client::connect_rpc::actions::ConnectRpcClientProtocol)
            }
        }
    }
    fn name(self) -> &'static str {
        self.protocol().protocol_name()
    }
    fn call(self) -> &'static str {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::GrpcWeb => "grpc_web_call",
            #[cfg(not(target_arch = "wasm32"))]
            Self::ConnectRpc => "connect_rpc_call",
        }
    }
    fn cancel(self) -> &'static str {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::GrpcWeb => "grpc_web_cancel",
            #[cfg(not(target_arch = "wasm32"))]
            Self::ConnectRpc => "connect_rpc_cancel",
        }
    }
    fn is_connect(self) -> bool {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::GrpcWeb => false,
            #[cfg(not(target_arch = "wasm32"))]
            Self::ConnectRpc => true,
        }
    }
    fn event(self, kind: &str) -> &'static crate::protocol::EventType {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::GrpcWeb => {
                use crate::client::grpc_web::actions as a;
                match kind {
                    "connected" => &a::CONNECTED,
                    "opened" => &a::OPENED,
                    "message" => &a::MESSAGE,
                    _ => &a::ENDED,
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::ConnectRpc => {
                use crate::client::connect_rpc::actions as a;
                match kind {
                    "connected" => &a::CONNECTED,
                    "opened" => &a::OPENED,
                    "message" => &a::MESSAGE,
                    _ => &a::ENDED,
                }
            }
        }
    }
}
struct SocketGuard(std::net::TcpStream);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
#[derive(Clone)]
struct Transport {
    binding: Binding,
    sender: Arc<Mutex<http1::SendRequest<BoxBody>>>,
    host: String,
    complete: Arc<AtomicBool>,
}
impl tower::Service<Request<BoxBody>> for Transport {
    type Response = Response<BoxBody>;
    type Error = Status;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Status>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, mut request: Request<BoxBody>) -> Self::Future {
        let sender = self.sender.clone();
        let host = self.host.clone();
        let complete = self.complete.clone();
        let binding = self.binding;
        async move {
            complete.store(false, Ordering::Relaxed);
            *request.version_mut() = hyper::Version::HTTP_11;
            request.headers_mut().insert(
                "host",
                host.parse()
                    .map_err(|_| Status::invalid_argument("invalid host"))?,
            );
            #[cfg(not(target_arch = "wasm32"))]
            let shape = *request
                .extensions()
                .get::<crate::server::connect_rpc::wire::Shape>()
                .unwrap_or(&crate::server::connect_rpc::wire::Shape::Unary);
            #[cfg(not(target_arch = "wasm32"))]
            if binding.is_connect() {
                request = crate::server::connect_rpc::wire::client_request(request, shape).await?;
            }
            #[cfg(not(target_arch = "wasm32"))]
            if !binding.is_connect() {
                request.headers_mut().insert(
                    "content-type",
                    "application/grpc-web+proto".parse().unwrap(),
                );
                request
                    .headers_mut()
                    .insert("accept", "application/grpc-web+proto".parse().unwrap());
                request
                    .headers_mut()
                    .insert("x-grpc-web", "1".parse().unwrap());
                request
                    .headers_mut()
                    .insert("x-user-agent", "netget-grpc-web/0.2".parse().unwrap());
                request.headers_mut().remove("te");
                request.headers_mut().remove("user-agent");
            }
            let mut sender = sender.lock().await;
            sender
                .ready()
                .await
                .map_err(|_| Status::unavailable("HTTP/1.1 connection closed"))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| Status::unavailable("HTTP/1.1 request failed"))?;
            drop(sender);
            #[cfg(not(target_arch = "wasm32"))]
            if binding.is_connect() {
                return crate::server::connect_rpc::wire::client_response(
                    response.map(|body| {
                        body.map_err(|_| Status::unavailable("Connect response transport failed"))
                            .boxed_unsync()
                    }),
                    shape,
                    complete,
                )
                .await;
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                if !wire::bounded_headers(response.headers()) {
                    return Err(Status::resource_exhausted(
                        "gRPC-Web response headers exceed bounds",
                    ));
                }
                if response.status() != hyper::StatusCode::OK {
                    return Err(Status::unavailable("gRPC-Web HTTP status is not 200"));
                }
                if !wire::binary_content_type(response.headers()) {
                    return Err(Status::internal(
                        "expected binary protobuf gRPC-Web response",
                    ));
                }
                if response.headers().contains_key("content-encoding")
                    || response.headers().get_all("grpc-encoding").iter().count() > 1
                {
                    return Err(Status::internal(
                        "unsupported or duplicate response encoding",
                    ));
                }
                let (parts, mut body) = response.into_parts();
                let body = if parts.headers.contains_key("grpc-status") {
                    wire::status(&parts.headers)?;
                    // A status in initial headers is legal only for a real Trailers-Only reply.
                    if body.frame().await.is_some() {
                        return Err(Status::internal(
                            "initial gRPC-Web status accompanies a body",
                        ));
                    }
                    complete.store(true, Ordering::Relaxed);
                    tonic::body::empty_body()
                } else {
                    let gzip = parts
                        .headers
                        .get("grpc-encoding")
                        .is_some_and(|value| value == "gzip");
                    wire::response_body_tracked(
                        body.map_err(|_| Status::unavailable("gRPC-Web response transport failed"))
                            .boxed_unsync(),
                        gzip,
                        Some(complete),
                    )
                };
                Ok(Response::from_parts(parts, body))
            }
            #[cfg(target_arch = "wasm32")]
            unreachable!("Connect response returned above")
        }
        .boxed()
    }
}
fn seconds(
    params: Option<&crate::protocol::StartupParams>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<Duration> {
    let seconds = params
        .map(|p| p.get_optional_u64(key))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    ensure!(
        (1..=maximum).contains(&seconds),
        "{key} must be 1..{maximum}"
    );
    Ok(Duration::from_secs(seconds))
}
pub(crate) struct HttpClient;
impl HttpClient {
    pub async fn connect(ctx: ConnectContext, binding: Binding) -> Result<SocketAddr> {
        let p = ctx.startup_params.as_ref();
        let connect = seconds(p, "connect_timeout_secs", 10, 60)?;
        let timeout = seconds(p, "rpc_timeout_secs", 300, 3600)?;
        let idle = seconds(p, "idle_timeout_secs", 120, 3600)?;
        // StartupParams rejects every undeclared selection before this function, including
        // TLS, text encoding and reflection; there is no silent cleartext fallback.
        let schema = p
            .context("proto_schema required")?
            .get_string("proto_schema")?;
        let uri: hyper::Uri = format!("http://{}", ctx.remote_addr).parse()?;
        let authority = uri.authority().context("remote_addr must be host:port")?;
        ensure!(
            authority.port_u16().is_some_and(|port| port > 0)
                && uri.path() == "/"
                && uri.query().is_none()
                && !authority.as_str().contains('@'),
            "remote_addr must be host:port"
        );
        let host = authority.as_str().to_owned();
        let (pool, transport, socket, local, remote, driver) =
            tokio::time::timeout(connect, async {
                let pool = crate::server::grpc::schema::load(&schema).await?;
                ensure!(
                    pool.services().next().is_some(),
                    "schema must define services"
                );
                let stream = tokio::net::TcpStream::connect(&ctx.remote_addr).await?;
                let local = stream.local_addr()?;
                let remote = stream.peer_addr()?;
                let raw = stream.into_std()?;
                let socket = SocketGuard(raw.try_clone()?);
                let stream = tokio::net::TcpStream::from_std(raw)?;
                let (sender, driver) = http1::Builder::new()
                    .max_headers(64)
                    .max_buf_size(32768)
                    .handshake(hyper_util::rt::TokioIo::new(stream))
                    .await?;
                Ok::<_, anyhow::Error>((
                    Arc::new(pool),
                    Transport {
                        binding,
                        sender: Arc::new(Mutex::new(sender)),
                        host,
                        complete: Arc::new(AtomicBool::new(true)),
                    },
                    socket,
                    local,
                    remote,
                    driver.boxed(),
                ))
            })
            .await
            .context("HTTP/1 RPC connect deadline exceeded")??;
        let now = crate::utils::clock::Instant::now();
        ctx.state
            .with_client_mut(ctx.client_id, |client| {
                client.connection = Some(crate::state::ClientConnectionState {
                    id: ctx.client_id,
                    remote_addr: ctx.remote_addr.clone(),
                    connected_addr: Some(remote),
                    local_addr: Some(local),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ClientStatus::Connected,
                    status_changed_at: now,
                    protocol_info: crate::state::server::ProtocolConnectionInfo::new(
                        json!({"transport":"http1","encoding":if binding.is_connect() {"proto"} else {"binary"},"tls_verified":false}),
                    ),
                });
            })
            .await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Connected)
            .await;
        let commands = command_support::register_command_channel(&ctx.state, ctx.client_id).await;
        let connected = Event::new(
            binding.event("connected"),
            json!({"remote_addr":ctx.remote_addr,"services":pool.services().map(|service|service.full_name().to_owned()).collect::<Vec<_>>(),"tls_verified":false}),
        );
        let state = ctx.state.clone();
        let id = ctx.client_id;
        state
            .spawn_client_task(
                id,
                Self::run(
                    ctx, pool, transport, socket, commands, connected, driver, timeout, idle,
                ),
            )
            .await;
        Ok(local)
    }
    #[allow(clippy::too_many_arguments)]
    async fn run(
        ctx: ConnectContext,
        pool: Arc<DescriptorPool>,
        transport: Transport,
        socket: SocketGuard,
        mut commands: mpsc::Receiver<ClientCommand>,
        connected: Event,
        mut driver: BoxFuture<'static, Result<(), hyper::Error>>,
        timeout: Duration,
        idle: Duration,
    ) {
        let binding = transport.binding;
        let (events, mut incoming) = mpsc::channel(16);
        let mut owner = Owner {
            ctx: ctx.clone(),
            pool,
            transport,
            timeout,
            events,
            operations: FuturesUnordered::new(),
            active: None,
            used: HashSet::new(),
            handlers: FuturesUnordered::new(),
            pending: VecDeque::new(),
        };
        owner
            .handlers
            .push(handler(ctx.clone(), connected, CONNECT_DEPTH, binding));
        let mut activity = tokio::time::Instant::now();
        let mut terminal = None;
        let mut driver_done = false;
        loop {
            while owner.handlers.len() < MAX_HANDLERS {
                let Some((depth, event)) = owner.pending.pop_front() else {
                    break;
                };
                owner
                    .handlers
                    .push(handler(ctx.clone(), event, depth, binding));
            }
            // Completion cannot overtake response events already queued by this RPC.
            // Keep its admission until every queued message precedes the terminal event.
            if terminal.is_some() && owner.pending.len() < 16 {
                while owner.pending.len() < 16 {
                    match incoming.try_recv() {
                        Ok(event) => owner.pending.push_back(event),
                        Err(mpsc::error::TryRecvError::Empty) => {
                            owner.active = None;
                            owner.pending.push_back(terminal.take().unwrap());
                            break;
                        }
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                continue;
            }
            tokio::select! {
                _ = &mut driver, if !driver_done => {
                    if owner.operations.is_empty() {break;}
                    // Let an in-flight RPC observe transport EOF and record its concrete
                    // framing/status failure before the session owner is dropped.
                    driver_done=true;
                },
                command=commands.recv() => {
                    let Some(command)=command else {break;}; activity=tokio::time::Instant::now();
                    if owner.action(command.action.clone(),Some(command),0).await {break;}
                }
                Some((id,depth,event))=owner.operations.next(), if !owner.operations.is_empty() => {
                    activity=tokio::time::Instant::now();
                    debug_assert_eq!(event.data["call_id"],json!(id));
                    if driver_done || !owner.transport.complete.load(Ordering::Relaxed) {
                        // A response refused before validated EOF cannot safely be reused or
                        // drained in the background. Record its terminal diagnosis, then drop
                        // the owner, driver, socket and all pending model work together.
                        // Preserve decoded events which have not yet entered a handler.
                        // A legal Connection: close can race final status just like a
                        // malformed response; teardown must not lose its typed values.
                        while let Some((_,queued))=owner.pending.pop_front() {
                            ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()),binding.name(),None,
                                &queued.event_type.id,queued.data,Vec::new()).await;
                        }
                        while let Ok((_,queued))=incoming.try_recv() {
                            ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()),binding.name(),None,
                                &queued.event_type.id,queued.data,Vec::new()).await;
                        }
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()),binding.name(),None,
                            event.id(),event.data.clone(),Vec::new()).await;
                        break;
                    }
                    terminal=Some((depth,event));
                }
                Some((depth,event))=incoming.recv(), if owner.pending.len()<16 => {
                    activity=tokio::time::Instant::now();owner.pending.push_back((depth,event));
                }
                Some((depth,result))=owner.handlers.next(), if !owner.handlers.is_empty() => {
                    activity=tokio::time::Instant::now();
                    match result {
                        Ok(actions) if actions.len()<=16 => {
                            let mut stop=false;
                            for action in actions {
                                if depth!=CONNECT_DEPTH && depth>=MAX_FOLLOWUP && action["type"]==binding.call() {continue;}
                                let next=if depth==CONNECT_DEPTH {0} else {depth.saturating_add(1)};
                                if owner.action(action,None,next).await {stop=true;break;}
                            }
                            if stop {break;}
                        }
                        Ok(_) => crate::logging::emit::Log::new(Some(&ctx.status_tx)).warn("HTTP/1 RPC handler exceeds 16 actions"),
                        Err(error) => crate::logging::emit::Log::new(Some(&ctx.status_tx)).warn(format!("HTTP/1 RPC handler failed: {error}")),
                    }
                }
                _=tokio::time::sleep_until(activity+idle), if owner.operations.is_empty() && owner.handlers.is_empty() && owner.pending.is_empty() => break,
            }
        }
        drop(owner);
        drop(driver);
        drop(socket);
        ctx.state.remove_client_handle(ctx.client_id).await;
        ctx.state
            .with_client_mut(ctx.client_id, |client| {
                if let Some(connection) = &mut client.connection {
                    connection.status = ClientStatus::Disconnected;
                    connection.status_changed_at = crate::utils::clock::Instant::now();
                }
            })
            .await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Disconnected)
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}
fn handler(ctx: ConnectContext, event: Event, depth: u8, binding: Binding) -> Handler {
    async move {
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
        let result = call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            binding.protocol().as_ref(),
            &ctx.status_tx,
        )
        .await;
        let result = match result {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                Ok(result.actions)
            }
            Err(error) => Err(error),
        };
        (depth, result)
    }
    .boxed()
}
fn ended(
    binding: Binding,
    id: u32,
    code: tonic::Code,
    message: &str,
    count: usize,
    metadata: Value,
) -> Event {
    let mut data = json!({"call_id":id,"code":code as i32,"message":crate::utils::truncate_for_llm(message,512),"response_count":count});
    if binding.is_connect() {
        data["metadata"] = metadata;
    }
    Event::new(binding.event("ended"), data)
}

fn metadata(action: &Value, binding: Binding) -> Result<tonic::metadata::MetadataMap> {
    let mut map = tonic::metadata::MetadataMap::new();
    let Some(headers) = action.get("metadata") else {
        return Ok(map);
    };
    let headers = headers.as_object().context("metadata must be an object")?;
    ensure!(headers.len() <= 16, "metadata exceeds 16 fields");
    let mut total = 0usize;
    for (key, value) in headers {
        let value = value
            .as_str()
            .context("metadata values must be ASCII strings")?;
        ensure!(
            !key.is_empty() && key.len() <= 128 && value.len() <= 1024,
            "metadata field too long"
        );
        ensure!(
            key.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.')),
            "metadata key must be lowercase ASCII"
        );
        ensure!(
            !key.starts_with("grpc-")
                && (!binding.is_connect()
                    || (!key.starts_with("connect-")
                        && !key.starts_with("trailer-")
                        && key != "accept-encoding"))
                && !key.ends_with("-bin")
                && !matches!(
                    key.as_str(),
                    "te" | "host"
                        | "content-type"
                        | "content-length"
                        | "connection"
                        | "transfer-encoding"
                        | "origin"
                        | "accept"
                        | "user-agent"
                        | "x-user-agent"
                        | "x-grpc-web"
                        | "content-encoding"
                ),
            "reserved or binary metadata excluded"
        );
        total = total
            .checked_add(key.len() + value.len())
            .context("metadata size overflow")?;
        ensure!(total <= 8192, "metadata exceeds 8 KiB");
        let key: tonic::metadata::MetadataKey<tonic::metadata::Ascii> = key.parse()?;
        map.insert(key, value.parse()?);
    }
    Ok(map)
}
struct Active {
    id: u32,
    abort: AbortHandle,
    count: Arc<AtomicUsize>,
}
struct Owner {
    ctx: ConnectContext,
    pool: Arc<DescriptorPool>,
    transport: Transport,
    timeout: Duration,
    events: mpsc::Sender<(u8, Event)>,
    operations: FuturesUnordered<Operation>,
    active: Option<Active>,
    used: HashSet<u32>,
    handlers: FuturesUnordered<Handler>,
    pending: VecDeque<(u8, Event)>,
}
impl Owner {
    async fn action(&mut self, action: Value, command: Option<ClientCommand>, depth: u8) -> bool {
        let mut stop = false;
        let outcome = match self
            .transport
            .binding
            .protocol()
            .execute_action(action.clone())
        {
            Err(error) => Err(error),
            Ok(ClientActionResult::Disconnect) => {
                stop = true;
                Ok(ClientSendOutcome::Disconnected)
            }
            Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                detail: "wait_for_more".into(),
            }),
            Ok(ClientActionResult::Custom { name, .. })
                if name == self.transport.binding.cancel() =>
            {
                let id = action["call_id"].as_u64().unwrap() as u32;
                if let Some(active) = self.active.as_ref().filter(|active| active.id == id) {
                    active.abort.abort();
                    let event = ended(
                        self.transport.binding,
                        id,
                        tonic::Code::Cancelled,
                        "RPC cancelled; HTTP/1.1 session disconnected",
                        active.count.load(Ordering::Relaxed),
                        json!({}),
                    );
                    // Cancellation records terminal semantics synchronously. Handler/model
                    // work is then cancelled with the connection instead of extending teardown.
                    self.ctx
                        .state
                        .record_access_log(
                            AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                            self.transport.binding.name(),
                            None,
                            &event.event_type.id,
                            event.data,
                            Vec::new(),
                        )
                        .await;
                    stop = true;
                    Ok(ClientSendOutcome::Disconnected)
                } else {
                    Err(anyhow::anyhow!("call_id is not active"))
                }
            }
            Ok(ClientActionResult::Custom { name, .. })
                if name == self.transport.binding.call() =>
            {
                self.start(&action, depth)
            }
            _ => Err(anyhow::anyhow!("unsupported HTTP/1 RPC action")),
        };
        if let Some(command) = command {
            let outcome = outcome.map_err(|error| {
                anyhow::anyhow!(crate::utils::truncate_for_llm(&error.to_string(), 512))
            });
            self.ctx
                .state
                .record_access_log(
                    AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                    self.transport.binding.name(),
                    None,
                    "injected_action",
                    action,
                    vec![match &outcome {
                        Ok(value) => serde_json::to_value(value).unwrap_or(Value::Null),
                        Err(error) => json!({"error":error.to_string()}),
                    }],
                )
                .await;
            command_support::reply(command, outcome);
        } else if let Err(error) = outcome {
            crate::logging::emit::Log::new(Some(&self.ctx.status_tx))
                .warn(format!("HTTP/1 RPC action refused: {error}"));
        }
        stop
    }
    fn start(&mut self, action: &Value, depth: u8) -> Result<ClientSendOutcome> {
        ensure!(
            self.active.is_none(),
            "one active RPC per HTTP/1.1 connection"
        );
        ensure!(
            self.handlers.len() + self.pending.len() < MAX_HANDLERS,
            "HTTP/1 RPC handler capacity reached"
        );
        ensure!(self.used.len() < 256, "client exceeds 256 call identifiers");
        let id = action["call_id"].as_u64().unwrap() as u32;
        ensure!(!self.used.contains(&id), "call_id was already used");
        let service = self
            .pool
            .get_service_by_name(action["service"].as_str().unwrap())
            .context("unknown service")?;
        let method = service
            .methods()
            .find(|method| method.name() == action["method"].as_str().unwrap())
            .context("unknown method")?;
        ensure!(
            !method.is_client_streaming(),
            "client-streaming and bidi are excluded"
        );
        stream_codec::check_descriptor(&method.input())?;
        stream_codec::check_descriptor(&method.output())?;
        let request = stream_codec::from_json(&action["request"], &method.input())?;
        let metadata = metadata(action, self.transport.binding)?;
        let gzip = action["gzip"].as_bool().unwrap_or(false);
        let (abort, registration) = AbortHandle::new_pair();
        let count = Arc::new(AtomicUsize::new(0));
        self.operations.push(operation(
            id,
            depth,
            method,
            request,
            metadata,
            gzip,
            self.transport.clone(),
            self.timeout,
            self.events.clone(),
            registration,
            count.clone(),
        ));
        self.active = Some(Active { id, abort, count });
        self.used.insert(id);
        Ok(ClientSendOutcome::Executed {
            detail: "RPC started; response events report wire results".into(),
        })
    }
}
#[allow(clippy::too_many_arguments)]
fn operation(
    id: u32,
    depth: u8,
    method: MethodDescriptor,
    request: DynamicMessage,
    metadata: tonic::metadata::MetadataMap,
    gzip: bool,
    transport: Transport,
    timeout: Duration,
    events: mpsc::Sender<(u8, Event)>,
    registration: futures::future::AbortRegistration,
    count: Arc<AtomicUsize>,
) -> Operation {
    async move {
        let binding=transport.binding;
        let mut trailing=json!({});
        let rpc=async {
            let codec=DynamicCodec {encode:method.input(),decode:method.output()};
            let path: http::uri::PathAndQuery=format!("/{}/{}",method.parent_service().full_name(),method.name()).parse().map_err(|_|Status::invalid_argument("invalid path"))?;
            let mut client=tonic::client::Grpc::new(transport).max_encoding_message_size(stream_codec::MAX_MESSAGE_BYTES)
                .max_decoding_message_size(stream_codec::MAX_MESSAGE_BYTES).accept_compressed(CompressionEncoding::Gzip);
            if gzip {client=client.send_compressed(CompressionEncoding::Gzip);}
            client.ready().await.map_err(|_|Status::unavailable("transport not ready"))?;
            let mut request=tonic::Request::new(request);*request.metadata_mut()=metadata;request.set_timeout(timeout);
            #[cfg(not(target_arch = "wasm32"))]
            if binding.is_connect() {request.extensions_mut().insert(if method.is_server_streaming() {crate::server::connect_rpc::wire::Shape::Stream} else {crate::server::connect_rpc::wire::Shape::Unary});}
            let response=client.server_streaming(request,path,codec).await?;
            let mut opened=json!({"call_id":id,"service":method.parent_service().full_name(),"method":method.name(),"server_streaming":method.is_server_streaming()});
            #[cfg(not(target_arch = "wasm32"))]
            if binding.is_connect() {opened["metadata"]=crate::server::connect_rpc::wire::Metadata::from_headers(&response.metadata().clone().into_headers(),"")?.json();}
            let mut response=response.into_inner();
            events.send((depth,Event::new(binding.event("opened"),opened)))
                .await.map_err(|_|Status::cancelled("client removed"))?;
            while let Some(message)=response.message().await? {
                let next=count.load(Ordering::Relaxed)+1;
                if next>MAX_RESPONSE_MESSAGES || (!method.is_server_streaming() && next>1) {return Err(Status::resource_exhausted("response message count exceeded"));}
                let value=stream_codec::to_json(&message).map_err(|error|Status::new(tonic::Code::from_i32(crate::server::grpc::grpc_status_for_value_failure(&error) as i32),"response does not fit typed values"))?;
                count.store(next,Ordering::Relaxed);
                events.send((depth,Event::new(binding.event("message"),json!({"call_id":id,"sequence":next,"response":value}))))
                    .await.map_err(|_|Status::cancelled("client removed"))?;
            }
            if !method.is_server_streaming() && count.load(Ordering::Relaxed)!=1 {return Err(Status::internal("unary success requires one response"));}
            #[cfg(not(target_arch = "wasm32"))]
            if binding.is_connect() {if let Some(headers)=response.trailers().await? {trailing=crate::server::connect_rpc::wire::Metadata::from_headers(&headers.into_headers(),"")?.json();}}
            Ok::<_,Status>(())
        };
        let result=Abortable::new(tokio::time::timeout(timeout,rpc),registration).await;
        let status=match result {Ok(Ok(Ok(())))=>Status::ok(""),Ok(Ok(Err(status)))=>status,
            Ok(Err(_))=>Status::deadline_exceeded("RPC deadline exceeded"),Err(_)=>Status::cancelled("RPC cancelled")};
        #[cfg(not(target_arch = "wasm32"))]
        if binding.is_connect() && status.code()!=tonic::Code::Ok {trailing=crate::server::connect_rpc::wire::Metadata::from_headers(&status.metadata().clone().into_headers(),"").map(|m|m.json()).unwrap_or_else(|_|json!({}));}
        (id,depth,ended(binding,id,status.code(),status.message(),count.load(Ordering::Relaxed),trailing))
    }.boxed()
}
