//! gRPC client implementation
pub mod actions;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod http1;
mod reflection;
mod streaming;

pub use crate::server::grpc::value_codec::{
    dynamic_message_to_json, json_to_dynamic_message, proto_value_to_json,
};
pub use actions::GrpcClientProtocol;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use prost::Message as ProstMessage;
use prost_reflect::{DescriptorPool, DynamicMessage};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::{Channel, Endpoint};
use tower::{Service, ServiceExt};
use tracing::{debug, error, info};

use crate::client::grpc::actions::{
    GRPC_CLIENT_CONNECTED_EVENT, GRPC_CLIENT_ERROR_EVENT, GRPC_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client as ClientTrait, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// gRPC client connection state
#[derive(Debug, Clone)]
enum ConnectionState {
    Idle,
    Processing,
}

/// Shared client data
struct GrpcClientData {
    channel: Channel,
    descriptor_pool: Arc<DescriptorPool>,
    state: ConnectionState,
    automatic: mpsc::Sender<serde_json::Value>,
}

/// gRPC client that connects to remote gRPC servers
pub struct GrpcClient;
pub const DEFAULT_TLS: bool = false;
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

struct SocketGuard(std::net::TcpStream);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}
fn seconds(
    params: Option<&StartupParams>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<std::time::Duration> {
    let seconds = params
        .map(|params| params.get_optional_u64(key))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    anyhow::ensure!(
        (1..=maximum).contains(&seconds),
        "{key} must be 1..{maximum}"
    );
    Ok(std::time::Duration::from_secs(seconds))
}

impl GrpcClient {
    /// Connect to a gRPC server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        let params = startup_params.as_ref();
        let schema = params
            .map(|p| p.get_optional_string("proto_schema"))
            .transpose()?
            .flatten();
        let tls = params
            .map(|p| p.get_optional_bool("use_tls"))
            .transpose()?
            .flatten()
            .unwrap_or(DEFAULT_TLS);
        let connect = seconds(params, "connect_timeout_secs", CONNECT_TIMEOUT_SECS, 60)?;
        let stream_timeout = seconds(
            params,
            "stream_timeout_secs",
            streaming::DEFAULT_STREAM_TIMEOUT,
            3600,
        )?;
        let idle = seconds(
            params,
            "idle_timeout_secs",
            streaming::DEFAULT_IDLE_TIMEOUT,
            3600,
        )?;
        let name = params
            .map(|p| p.get_optional_string("server_name"))
            .transpose()?
            .flatten();
        let ca = params
            .map(|p| p.get_optional_string("ca_file"))
            .transpose()?
            .flatten();
        anyhow::ensure!(
            tls || (name.is_none() && ca.is_none()),
            "server_name/ca_file require use_tls"
        );
        let uri: hyper::Uri =
            format!("{}://{}", if tls { "https" } else { "http" }, remote_addr).parse()?;
        anyhow::ensure!(
            uri.path() == "/" && uri.authority().is_some(),
            "remote address must be host:port"
        );
        let host = uri.host().context("endpoint has no hostname")?.to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let name = name.unwrap_or_else(|| host.clone());
        anyhow::ensure!(
            !name.is_empty() && name.len() <= 253,
            "server_name too long or empty"
        );
        let (channel, descriptor_pool, socket, local, remote) =
            tokio::time::timeout(connect, async {
                let pem = if let Some(path) = ca {
                    Some(
                        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                            use std::io::Read;
                            let metadata = std::fs::metadata(&path)?;
                            anyhow::ensure!(
                                metadata.is_file() && metadata.len() <= 1024 * 1024,
                                "CA must be a regular file at most 1 MiB"
                            );
                            let mut options = std::fs::OpenOptions::new();
                            options.read(true);
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::OpenOptionsExt;
                                options.custom_flags(libc::O_NONBLOCK);
                            }
                            let file = options.open(path)?;
                            let metadata = file.metadata()?;
                            anyhow::ensure!(
                                metadata.is_file() && metadata.len() <= 1024 * 1024,
                                "CA must be a regular file at most 1 MiB"
                            );
                            let mut bytes = Vec::new();
                            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                            anyhow::ensure!(bytes.len() <= 1024 * 1024, "CA exceeds 1 MiB");
                            Ok(bytes)
                        })
                        .await??,
                    )
                } else {
                    None
                };
                let local_schema = if let Some(schema) = schema {
                    Some(load_schema(&schema).await?)
                } else {
                    None
                };
                let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                let local = stream.local_addr()?;
                let remote = stream.peer_addr()?;
                let raw = stream.into_std()?;
                let socket = SocketGuard(raw.try_clone()?);
                let stream = tokio::net::TcpStream::from_std(raw)?;
                let mut endpoint = Endpoint::from(uri)
                    .connect_timeout(connect)
                    .concurrency_limit(16)
                    .buffer_size(16)
                    .initial_stream_window_size(65536)
                    .initial_connection_window_size(1048576)
                    .http2_max_header_list_size(32768);
                if tls {
                    let _ = rustls::crypto::ring::default_provider().install_default();
                    let mut config = tonic::transport::ClientTlsConfig::new()
                        .with_webpki_roots()
                        .domain_name(name);
                    if let Some(pem) = pem {
                        config =
                            config.ca_certificate(tonic::transport::Certificate::from_pem(pem));
                    }
                    endpoint = endpoint.tls_config(config)?;
                }
                let mut stream = Some(stream);
                let connector = tower::service_fn(move |_: hyper::Uri| {
                    let stream = stream.take();
                    async move {
                        stream.map(hyper_util::rt::TokioIo::new).ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotConnected,
                                "gRPC automatic reconnect is disabled",
                            )
                        })
                    }
                });
                let channel = endpoint.connect_with_connector(connector).await?;
                let pool = match local_schema {
                    Some(pool) => pool,
                    None => reflection::discover(channel.clone()).await?,
                };
                anyhow::ensure!(
                    pool.files().len() <= 128 && pool.services().len() <= 128,
                    "schema exceeds 128 files/services"
                );
                anyhow::ensure!(
                    pool.file_descriptor_protos()
                        .map(ProstMessage::encoded_len)
                        .sum::<usize>()
                        <= 4 * 1024 * 1024,
                    "schema exceeds 4 MiB"
                );
                Ok::<_, anyhow::Error>((channel, pool, socket, local, remote))
            })
            .await
            .context("gRPC connection/schema deadline exceeded")??;
        let services: Vec<_> = descriptor_pool
            .services()
            .map(|service| service.full_name().to_owned())
            .collect();
        let (automatic, automatic_rx) = mpsc::channel(16);
        let data = Arc::new(Mutex::new(GrpcClientData {
            channel,
            descriptor_pool: Arc::new(descriptor_pool),
            state: ConnectionState::Idle,
            automatic,
        }));
        let now = crate::utils::clock::Instant::now();
        app_state
            .with_client_mut(client_id, |client| {
                client.connection = Some(crate::state::ClientConnectionState {
                    id: client_id,
                    remote_addr: remote_addr.clone(),
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
                        serde_json::json!({"tls_verified":tls}),
                    ),
                });
                client.set_protocol_field("grpc_client".into(), serde_json::json!("initialized"));
                client.set_protocol_field("server_addr".into(), serde_json::json!(remote_addr));
            })
            .await;
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let commands =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let connected = Event::new(
            &GRPC_CLIENT_CONNECTED_EVENT,
            serde_json::json!({"server_addr":remote_addr,"services":services}),
        );
        let ctx = streaming::ContextData {
            id: client_id,
            data,
            state: app_state.clone(),
            llm: llm_client,
            status: status_tx.clone(),
            protocol: Arc::new(GrpcClientProtocol::new()),
        };
        app_state
            .spawn_client_task(
                client_id,
                streaming::run(
                    ctx,
                    socket,
                    commands,
                    automatic_rx,
                    connected,
                    stream_timeout,
                    idle,
                ),
            )
            .await;
        let _ = status_tx.send("__UPDATE_UI__".into());
        Ok(local)
    }
}

/// Both peers share bounded schema input and an owned protoc child.
async fn load_schema(schema_input: &str) -> Result<DescriptorPool> {
    crate::server::grpc::schema::load(schema_input).await
}

/// The result of a legacy unary action, consumed by the connection owner.
enum Applied {
    /// A gRPC request really went out; `bytes_sent` is the length of the framed
    /// message (5-byte gRPC header + protobuf payload) that was written to the
    /// channel and answered.
    ///
    /// `pending_notify` is the `grpc_response_received` payload when the caller asked
    /// for [`Dispatch::Defer`] - it has not been given to the LLM yet, and the caller
    /// must run [`notify_grpc_response`] with it once it has replied.
    Sent {
        bytes_sent: usize,
        pending_notify: Option<serde_json::Value>,
    },
    /// The action ran but put nothing on the wire; `detail` says why.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// How the `grpc_response_received` event that follows a call is delivered.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Raise it - and run whatever the LLM answers - before returning. Used by the
    /// connected-event handler, which is where that recursion has always lived.
    Inline,
    /// Do the call and raise nothing at all -- neither the success event nor the error
    /// event. Used for a retry the model asks for in answer to `grpc_client_error`: that
    /// retry must not itself raise another error event, or a persistently failing call
    /// would drive the model round the same loop forever.
    Silent,
    /// Hand the event payload back to the caller instead. The injected-command loop
    /// uses this so it can reply with the truthful byte count **first** and only then
    /// raise the event: a client whose events are routed to a manual handler would
    /// otherwise hold `[ send ]`'s answer hostage for the length of a human's think
    /// time, and the operator would see a timeout for a call that in fact succeeded.
    Defer,
}

/// Execute a gRPC client action
async fn execute_grpc_action(
    client_id: ClientId,
    action: serde_json::Value,
    grpc_client_data: Arc<Mutex<GrpcClientData>>,
    app_state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    protocol: &Arc<GrpcClientProtocol>,
    dispatch: Dispatch,
) -> Result<Applied> {
    // Parse action using the protocol's execute_action method
    let action_result = protocol.as_ref().execute_action(action.clone())?;
    apply_grpc_action(
        client_id,
        action_result,
        grpc_client_data,
        app_state,
        llm_client,
        status_tx,
        protocol,
        dispatch,
    )
    .await
}

/// Run one already-executed action. Shared by the connected-event handler and the
/// injected-command loop so the `grpc_call` decoding exists exactly once.
#[allow(clippy::too_many_arguments)]
async fn apply_grpc_action(
    client_id: ClientId,
    action_result: ClientActionResult,
    grpc_client_data: Arc<Mutex<GrpcClientData>>,
    app_state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    protocol: &Arc<GrpcClientProtocol>,
    dispatch: Dispatch,
) -> Result<Applied> {
    match action_result {
        ClientActionResult::Custom { name, data } if name.starts_with("grpc_stream_") => {
            grpc_client_data
                .lock()
                .await
                .automatic
                .try_send(data)
                .context("stream control queue full or closed")?;
            Ok(Applied::Ran("stream control queued".into()))
        }
        ClientActionResult::Custom { name, data } if name == "grpc_call" => {
            let service = data["service"]
                .as_str()
                .context("Missing service in grpc_call")?;
            let method = data["method"]
                .as_str()
                .context("Missing method in grpc_call")?;
            let request = &data["request"];
            let metadata = data.get("metadata").and_then(|v| v.as_object());

            let sent = make_grpc_call(
                client_id,
                service,
                method,
                request.clone(),
                metadata.cloned(),
                grpc_client_data,
                app_state,
                llm_client,
                status_tx,
                protocol,
                dispatch,
            )
            .await?;

            match sent {
                Some(report) => Ok(Applied::Sent {
                    bytes_sent: report.bytes_sent,
                    pending_notify: report.pending_notify,
                }),
                // The per-connection state machine refused the call; nothing was
                // written, and saying "Sent" here would be a lie.
                None => Ok(Applied::Ran(format!(
                    "grpc_call {}/{} skipped: the client is already processing a call",
                    service, method
                ))),
            }
        }
        ClientActionResult::Disconnect => {
            info!("gRPC client {} disconnecting", client_id);
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            let _ = status_tx.send(format!("[CLIENT] gRPC client {} disconnected", client_id));
            Ok(Applied::Disconnect)
        }
        ClientActionResult::WaitForMore => {
            debug!("gRPC client {} waiting", client_id);
            Ok(Applied::Ran("wait_for_more".to_string()))
        }
        ClientActionResult::NoAction => Ok(Applied::Ran("no_action".to_string())),
        // Not swallowed: an action this client cannot carry out says so, rather than
        // looking identical to success.
        ClientActionResult::Custom { name, .. } => Ok(Applied::Ran(format!(
            "custom result '{name}' is not handled by the gRPC client"
        ))),
        ClientActionResult::SendData(_) => Ok(Applied::Ran(
            "send_data has no meaning for a gRPC client (tonic owns the HTTP/2 channel)"
                .to_string(),
        )),
        ClientActionResult::Multiple(_) => Ok(Applied::Ran(
            "multiple results are not produced by the gRPC client".to_string(),
        )),
    }
}

/// Drain injected commands until the channel closes (the client was removed) or an
/// injected `disconnect` ends the session.
///
/// One completed gRPC call.
struct GrpcCallReport {
    /// Framed bytes written to the channel: 5-byte gRPC header + protobuf payload.
    bytes_sent: usize,
    /// `grpc_response_received` payload not yet given to the LLM (see [`Dispatch`]).
    pending_notify: Option<serde_json::Value>,
}

/// Make a gRPC call.
///
/// Returns a [`GrpcCallReport`] when the call went out and was answered, or `None` when
/// the per-connection state machine refused it because another call is in flight. A
/// caller reporting a [`ClientSendOutcome`] must not turn `None` into `Sent`.
///
/// Returns a boxed future rather than being a plain `async fn`.
///
/// The error path can retry the call the model asks for, which means this function calls
/// itself. rustc cannot infer the type of a directly self-referential `async fn` -- it is
/// an infinitely nested opaque type -- so the body is boxed once here and the recursion
/// becomes an ordinary dynamic call.
#[allow(clippy::too_many_arguments)]
fn make_grpc_call<'a>(
    client_id: ClientId,
    service: &'a str,
    method: &'a str,
    request_json: serde_json::Value,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
    grpc_client_data: Arc<Mutex<GrpcClientData>>,
    app_state: &'a Arc<AppState>,
    llm_client: &'a OllamaClient,
    status_tx: &'a mpsc::UnboundedSender<String>,
    protocol: &'a Arc<GrpcClientProtocol>,
    dispatch: Dispatch,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<GrpcCallReport>>> + Send + 'a>>
{
    Box::pin(async move {
        info!("gRPC client {} calling {}/{}", client_id, service, method);

        // Everything that can fail happens **before** the connection is claimed.
        //
        // The state used to be set to `Processing` first and reset to `Idle` only after the
        // network call returned, so any of the four `?`s below — an unknown method, a request
        // the schema rejects, an unbuildable HTTP request — returned early and left the state
        // machine `Processing` forever. Every later call then answered "the client is already
        // processing a call", so one malformed request from the model permanently wedged the
        // client with nothing in the log to say why.
        //
        // Nothing here touches the wire; the descriptor pool is read under the lock and the
        // guard dropped before the conversion, so a slow encode does not block the command
        // loop either.
        let (input_desc, output_desc) = {
            let data = grpc_client_data.lock().await;
            let method_desc = data
                .descriptor_pool
                .get_service_by_name(service)
                .and_then(|s| s.methods().find(|m| m.name() == method))
                .context(format!("Method {}/{} not found in schema", service, method))?;
            (method_desc.input(), method_desc.output())
        };

        // Convert JSON request to protobuf
        let request_msg = json_to_dynamic_message(&request_json, &input_desc)
            .context("Failed to convert request JSON to protobuf")?;

        // Encode request
        let request_bytes = request_msg.encode_to_vec();

        info!(
            "gRPC client {} sending {}-byte request to {}/{}",
            client_id,
            request_bytes.len(),
            service,
            method
        );

        // Build gRPC request path
        let path = format!("/{}/{}", service, method);

        // Create HTTP request with gRPC framing
        use http::HeaderValue;

        let mut request_builder = Request::builder()
            .method("POST")
            .uri(path.clone())
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity");

        // Add custom metadata
        if let Some(meta) = metadata {
            for (key, value) in meta {
                if let Some(val_str) = value.as_str() {
                    if let Ok(header_value) = HeaderValue::from_str(val_str) {
                        request_builder = request_builder.header(key.as_str(), header_value);
                    }
                }
            }
        }

        // Encode gRPC message with 5-byte header (compression flag + length)
        let mut grpc_message = Vec::with_capacity(5 + request_bytes.len());
        grpc_message.push(0); // No compression
        grpc_message.extend_from_slice(
            &u32::try_from(request_bytes.len())
                .context("gRPC request length exceeds u32")?
                .to_be_bytes(),
        );
        grpc_message.extend_from_slice(&request_bytes);

        // Create body using UnsyncBoxBody which is compatible with tonic
        use http_body_util::combinators::UnsyncBoxBody;
        let full_body = http_body_util::Full::new(Bytes::from(grpc_message));
        let body =
            UnsyncBoxBody::new(full_body.map_err(|_: std::convert::Infallible| {
                tonic::Status::internal("infallible error")
            }));
        let http_request = request_builder
            .body(body)
            .context("Failed to build HTTP request")?;

        // Claim the connection and take the channel under one guard: the old check-then-set
        // used two separate acquisitions, so two callers could both see `Idle`.
        let channel = {
            let mut data = grpc_client_data.lock().await;
            if matches!(data.state, ConnectionState::Processing) {
                info!("gRPC client {} is busy, skipping request", client_id);
                return Ok(None);
            }
            data.state = ConnectionState::Processing;
            data.channel.clone()
        };

        // Make the call using the channel
        let result = call_grpc_unary(&channel, http_request).await;

        // Reset to idle. From the claim above to here there is no `?`, so this cannot be
        // skipped by an early return.
        {
            let mut data = grpc_client_data.lock().await;
            data.state = ConnectionState::Idle;
        }

        let framed_len = 5 + request_bytes.len();

        match result {
            Ok(response_bytes) => {
                // Decode response
                let response_msg = DynamicMessage::decode(output_desc.clone(), &response_bytes[..])
                    .context("Failed to decode gRPC response")?;

                // Convert to JSON
                let response_json = dynamic_message_to_json(&response_msg)?;

                info!(
                    "gRPC client {} received response for {}/{}",
                    client_id, service, method
                );

                let event_data = serde_json::json!({
                    "service": service,
                    "method": method,
                    "response": response_json,
                });

                let pending_notify = match dispatch {
                    Dispatch::Inline => {
                        notify_grpc_response(
                            client_id,
                            event_data,
                            grpc_client_data,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                            protocol.clone(),
                        )
                        .await;
                        None
                    }
                    // A retry raises nothing: the caller already reported the original
                    // failure, and re-raising would restart the error loop this bound exists
                    // to prevent.
                    Dispatch::Silent => None,
                    Dispatch::Defer => Some(event_data),
                };

                Ok(Some(GrpcCallReport {
                    bytes_sent: framed_len,
                    pending_notify,
                }))
            }
            Err(e) => {
                error!("gRPC client {} call failed: {}", client_id, e);

                // Tell the model, and DO what it answers.
                //
                // The answer used to be dropped (`let _ = call_llm_for_client(...)`), so a
                // model that saw a call fail and wanted to retry it, call a fallback method,
                // or hang up was ignored -- on the one event whose entire purpose is to let it
                // react.
                //
                // A retry runs with `Dispatch::Silent`, which raises neither the success event
                // nor another error event. That bound is essential: without it a persistently
                // failing call would raise an error, be retried, fail, raise another error,
                // and drive the model round the same loop forever.
                if matches!(dispatch, Dispatch::Silent) {
                    // Already a retry. Do not ask again.
                    return Err(e);
                }
                if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                    let event = Event::new(
                        &GRPC_CLIENT_ERROR_EVENT,
                        serde_json::json!({
                            "service": service,
                            "method": method,
                            "code": "UNKNOWN",
                            "message": e.to_string(),
                        }),
                    );

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
                        Ok(result) => {
                            if let Some(mem) = result.memory_updates {
                                app_state.set_memory_for_client(client_id, mem).await;
                            }
                            for action in result.actions {
                                use crate::llm::actions::client_trait::Client;
                                match protocol.execute_action(action.clone()) {
                                    Ok(ClientActionResult::Custom { name, data })
                                        if name == "grpc_call" =>
                                    {
                                        let retry_service =
                                            data["service"].as_str().unwrap_or(service).to_string();
                                        let retry_method =
                                            data["method"].as_str().unwrap_or(method).to_string();
                                        info!(
                                            "gRPC client {} retrying as {}/{} on the model's \
                                         request",
                                            client_id, retry_service, retry_method
                                        );
                                        let retry = make_grpc_call(
                                            client_id,
                                            &retry_service,
                                            &retry_method,
                                            data.get("request").cloned().unwrap_or_default(),
                                            data.get("metadata")
                                                .and_then(|m| m.as_object())
                                                .cloned(),
                                            grpc_client_data.clone(),
                                            app_state,
                                            llm_client,
                                            status_tx,
                                            protocol,
                                            Dispatch::Silent,
                                        )
                                        .await;
                                        if let Err(re) = retry {
                                            error!(
                                                "gRPC client {} retry also failed: {}",
                                                client_id, re
                                            );
                                        }
                                    }
                                    Ok(ClientActionResult::Disconnect) => {
                                        info!(
                                            "gRPC client {} disconnecting after error, as the \
                                         model asked",
                                            client_id
                                        );
                                        app_state
                                            .update_client_status(
                                                client_id,
                                                crate::state::ClientStatus::Disconnected,
                                            )
                                            .await;
                                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                                    }
                                    Ok(_) => {}
                                    Err(ae) => error!(
                                        "gRPC client {} rejected its own error-path action: {}",
                                        client_id, ae
                                    ),
                                }
                            }
                        }
                        Err(le) => error!(
                            "gRPC client {} LLM error on grpc_client_error: {}",
                            client_id, le
                        ),
                    }
                }

                Err(e)
            }
        }
    })
}

/// Raise `grpc_response_received` for a completed call and run whatever the LLM answers.
///
/// Split out of [`make_grpc_call`] so the injected-command loop can await the network
/// round-trip - and report a truthful byte count - without also awaiting the LLM.
#[allow(clippy::too_many_arguments)]
async fn notify_grpc_response(
    client_id: ClientId,
    event_data: serde_json::Value,
    grpc_client_data: Arc<Mutex<GrpcClientData>>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<GrpcClientProtocol>,
) {
    let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
        return;
    };

    let event = Event::new(&GRPC_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);
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
        Ok(ClientLlmResult {
            actions,
            memory_updates,
        }) => {
            // Update memory
            if let Some(mem) = memory_updates {
                app_state.set_memory_for_client(client_id, mem).await;
            }

            // Execute actions
            for action in actions {
                if let Err(e) = Box::pin(execute_grpc_action(
                    client_id,
                    action,
                    grpc_client_data.clone(),
                    &app_state,
                    &llm_client,
                    &status_tx,
                    &protocol,
                    Dispatch::Inline,
                ))
                .await
                {
                    error!("Failed to execute gRPC action: {}", e);
                }
            }
        }
        Err(e) => {
            error!("LLM error for gRPC client {}: {}", client_id, e);
        }
    }
}

/// Make a unary gRPC call using tonic channel
async fn call_grpc_unary(
    channel: &Channel,
    request: Request<http_body_util::combinators::UnsyncBoxBody<Bytes, tonic::Status>>,
) -> Result<Vec<u8>> {
    // Clone the channel to get a service we can call
    let mut client = channel.clone();

    // Call the service
    let response = client
        .ready()
        .await
        .context("gRPC channel not ready")?
        .call(request)
        .await
        .context("gRPC call failed")?;

    // `grpc-status` is read from the HTTP/2 **trailers** as well as the initial headers.
    //
    // Reading only the headers is why this client mishandled every real gRPC server:
    // grpc-go and tonic send the status in trailers on a normal unary call (headers carry it
    // only in the "trailers-only" shape), so a genuine `5 NOT_FOUND` arrived here as "absent"
    // — which this function treats as success — and the caller then got the meaningless
    // "Response too short" from the empty body that accompanied it. NetGet's own gRPC server
    // puts the status in the headers, so client-against-our-own-server never showed it.
    let (parts, body) = response.into_parts();
    let header_status = grpc_status_of(&parts.headers);

    let collected = body
        .collect()
        .await
        .context("Failed to read response body")?;
    let trailers = collected.trailers().cloned();
    let body_bytes = collected.to_bytes();

    let (status_code, status_message) = match header_status {
        Some(status) => (status, grpc_message_of(&parts.headers)),
        None => match trailers.as_ref().and_then(grpc_status_of) {
            Some(status) => (status, trailers.as_ref().and_then(grpc_message_of)),
            // No status anywhere. Left permissive rather than an error: a body did arrive,
            // and refusing it would break a peer that only sets the status on failure.
            None => (0, None),
        },
    };

    if status_code != 0 {
        return Err(anyhow::anyhow!(
            "gRPC error: status={}, message={}",
            status_code,
            status_message.as_deref().unwrap_or("Unknown error")
        ));
    }

    // Decode gRPC framing (skip 5-byte header)
    if body_bytes.len() < 5 {
        return Err(anyhow::anyhow!("Response too short"));
    }

    let message_bytes = body_bytes.slice(5..);
    Ok(message_bytes.to_vec())
}

/// `grpc-status` from a header or trailer map, if it carries a parseable one.
fn grpc_status_of(headers: &http::HeaderMap) -> Option<i32> {
    headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i32>().ok())
}

/// `grpc-message` from a header or trailer map.
fn grpc_message_of(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
