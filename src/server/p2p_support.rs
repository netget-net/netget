//! Owned, bounded TCP/TLS sessions for hub and peer simulators.
//! Wire formats and decisions remain in each protocol's session implementation.
use crate::{
    llm::actions::{client_trait::Client, protocol_trait::Server},
    protocol::{ConnectContext, Event, SpawnContext},
    server::connection::ConnectionId,
    state::{AccessLogOwner, ClientStatus},
};
use anyhow::{ensure, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type Stream = Box<dyn AsyncIo>;
pub type ReadStream = tokio::io::ReadHalf<Stream>;

pub const DEFAULT_USE_TLS: bool = false;

pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn parameter(
    name: &str,
    kind: &str,
    description: &str,
    required: bool,
) -> crate::llm::actions::Parameter {
    crate::llm::actions::Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<crate::llm::actions::Parameter>,
    example: Value,
) -> crate::llm::actions::ActionDefinition {
    crate::llm::actions::ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(crate::protocol::LogTemplate::new().with_info(name)),
    }
}
pub fn number(v: &Value, key: &str, max: u64) -> Result<u64> {
    let n = v[key]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("{key} must be an unsigned integer"))?;
    ensure!(n <= max, "{key} exceeds {max}");
    Ok(n)
}
/// A bounded framed stream read. The header determines the whole length, validated before allocation.
pub async fn frame(
    stream: &mut Stream,
    header_len: usize,
    max: usize,
    length: fn(&[u8]) -> Result<usize>,
) -> Result<Vec<u8>> {
    let mut header = vec![0; header_len];
    stream.read_exact(&mut header).await?;
    let len = length(&header)?;
    ensure!(len >= header_len && len <= max, "invalid frame length");
    header.resize(len, 0);
    stream.read_exact(&mut header[header_len..]).await?;
    Ok(header)
}
#[async_trait]
pub trait DeviceSession: Send + 'static {
    fn greeting(&mut self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn outgoing(&mut self) -> Option<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        None
    }
    async fn read(&mut self, stream: &mut ReadStream) -> Result<Vec<u8>>;
    /// Automatic transport replies or a semantic request for the handler.
    fn receive(&mut self, frame: &[u8]) -> Result<(Vec<u8>, Option<Value>)>;
    fn answer(&mut self, request: &Value, action: Option<&Value>) -> Result<Vec<u8>>;
}
#[async_trait]
pub trait ScannerSession: Send + 'static {
    fn connected(&self) -> Value {
        serde_json::json!({})
    }
    async fn open(&mut self, stream: &mut Stream) -> Result<()>;
    async fn exchange(&mut self, stream: &mut Stream, action: &Value) -> Result<Value>;
    fn outcome(
        &self,
        _action: &Value,
        response: &Value,
    ) -> crate::state::client_handles::ClientSendOutcome {
        crate::state::client_handles::ClientSendOutcome::Executed {
            detail: response.to_string(),
        }
    }
    async fn close(&mut self, _stream: &mut Stream) -> Result<()> {
        Ok(())
    }
    async fn idle(&mut self, stream: &mut Stream) -> Result<Option<Value>> {
        let mut b = [0];
        stream.read_exact(&mut b).await?;
        anyhow::bail!("unexpected data or peer closed")
    }
}
pub async fn spawn<S: DeviceSession, F: Fn() -> S + Send + Sync + Clone + 'static>(
    ctx: SpawnContext,
    protocol: Arc<dyn Server>,
    factory: F,
    kinds: &'static [crate::protocol::EventType],
) -> Result<SocketAddr> {
    let tls = server_tls(ctx.startup_params.as_ref())?;
    let listener =
        crate::server::socket_helpers::create_reusable_tcp_listener(ctx.legacy_listen_addr())
            .await?;
    spawn_accept_bounded(ctx, protocol, factory, kinds, listener, tls).await
}
pub async fn spawn_accept_bounded<
    S: DeviceSession,
    F: Fn() -> S + Send + Sync + Clone + 'static,
>(
    ctx: SpawnContext,
    protocol: Arc<dyn Server>,
    factory: F,
    kinds: &'static [crate::protocol::EventType],
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<SocketAddr> {
    let local = listener.local_addr()?;
    let state = ctx.state.clone();
    let sid = ctx.server_id;
    let task = tokio::spawn(async move {
        let cap = crate::server::accept_bounded::ConnectionLimiter::new(
            crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS,
        );
        loop {
            let Ok((stream, peer, permit)) = crate::server::accept_bounded::accept_bounded(
                &listener,
                &cap,
                b"",
                protocol.protocol_name(),
                Some(&ctx.status_tx),
            )
            .await
            else {
                break;
            };
            let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
            let now = crate::utils::clock::Instant::now();
            ctx.state
                .add_connection_to_server(
                    sid,
                    crate::state::server::ConnectionState {
                        id,
                        remote_addr: peer,
                        local_addr: local,
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        last_activity: now,
                        status: crate::state::server::ConnectionStatus::Active,
                        status_changed_at: now,
                        protocol_info: crate::state::server::ProtocolConnectionInfo::empty(),
                    },
                )
                .await;
            let mut commands =
                crate::server::peer_support::register_peer_channel(&ctx.state, sid, id.as_u32())
                    .await;
            let factory = factory.clone();
            let tls = tls.clone();
            let child = ctx.clone();
            let p = protocol.clone();
            ctx.state.spawn_server_task(sid, async move {
                let _permit = permit;
                let stream: Stream = if let Some(tls) = tls {
                    let handshake = tokio::time::timeout(RESPONSE_TIMEOUT,tls.accept(stream));
                    tokio::pin!(handshake);
                    let accepted = loop { tokio::select! {
                        result=&mut handshake => break result.ok().and_then(Result::ok),
                        Some(c)=commands.recv() => {
                            let close=c.action["type"]=="disconnect";
                            crate::client::command_support::reply(c, if close {Ok(crate::state::client_handles::ClientSendOutcome::Disconnected)} else {Ok(crate::state::client_handles::ClientSendOutcome::Rejected{error:"TLS handshake pending".into()})});
                            if close {break None;}
                        }
                    }};
                    let Some(stream)=accepted else {
                        child.state.remove_peer_handle(sid,id.as_u32()).await;
                        child.state.update_connection_status(sid,id,crate::state::server::ConnectionStatus::Closed).await;
                        return;
                    }; Box::new(stream)
                } else {Box::new(stream)};
                let mut session = factory(); let mut first = true;
                let mut outgoing=session.outgoing();
                let (mut read_stream,mut write_stream)=tokio::io::split(stream);
                let result: Result<()> = async {
                    tokio::time::timeout(RESPONSE_TIMEOUT,write_stream.write_all(&session.greeting()?)).await??;
                    loop {
                        let input = {
                            let read=tokio::time::timeout(if first {FIRST_BYTE_TIMEOUT} else {IDLE_TIMEOUT},session.read(&mut read_stream));
                            tokio::pin!(read);
                            loop {
                                tokio::select! {
                                    v=&mut read=>break Some(v??),
                                    outbound=async {match outgoing.as_mut(){Some(rx)=>rx.recv().await,None=>std::future::pending().await}}=>{
                                        if let Some(bytes)=outbound {tokio::time::timeout(RESPONSE_TIMEOUT,write_stream.write_all(&bytes)).await??;} else {outgoing=None;}
                                    }
                                    Some(command)=commands.recv()=>{
                                        if command.action["type"]=="disconnect" {crate::client::command_support::reply(command,Ok(crate::state::client_handles::ClientSendOutcome::Disconnected));break None;}
                                        crate::client::command_support::reply(command,Ok(crate::state::client_handles::ClientSendOutcome::Rejected{error:"Only disconnect is valid outside a pending request".into()}));
                                    }
                                }
                            }
                        };
                        let Some(input)=input else {break;};
                        first = false;
                        child.state.update_connection_stats(sid, id, Some(input.len() as u64), None, Some(1), None).await;
                        let (automatic, request) = session.receive(&input)?;
                        let mut reply = automatic;
                        if let Some(request) = request {
                            let event = Event::new(&kinds[0], request.clone());
                            let turn=crate::llm::action_helper::call_llm(&child.llm_client,&child.state,sid,Some(id),&event,p.as_ref());tokio::pin!(turn);
                            let result=loop {tokio::select! {result=&mut turn=>break result,Some(command)=commands.recv()=>{if command.action["type"]=="disconnect" {crate::client::command_support::reply(command,Ok(crate::state::client_handles::ClientSendOutcome::Disconnected));anyhow::bail!("operator disconnected peer");}crate::client::command_support::reply(command,Ok(crate::state::client_handles::ClientSendOutcome::Rejected{error:"Reply to the pending request through its handler; only disconnect is an asynchronous action".into()}));}}};
                            let answer = result.as_ref().ok().and_then(|r| r.protocol_results.iter().find_map(|a| if let crate::llm::ActionResult::Custom {data,..}=a {Some(data)} else {None}));
                            if answer.is_none() { crate::logging::emit::Log::new(Some(&child.status_tx)).warn(format!("{} decision=fail_closed_no_action", p.protocol_name())); }
                            reply.extend(session.answer(&request, answer)?);
                        }
                        if !reply.is_empty() { tokio::time::timeout(RESPONSE_TIMEOUT,write_stream.write_all(&reply)).await??; child.state.update_connection_stats(sid, id, None, Some(reply.len() as u64), None, Some(1)).await; }
                    } Ok(())
                }.await;
                if let Err(e) = result { crate::logging::emit::Log::new(Some(&child.status_tx)).debug(format!("{} peer ended: {e}", p.protocol_name())); }
                let _ = write_stream.shutdown().await;
                child.state.remove_peer_handle(sid, id.as_u32()).await;
                child.state.update_connection_status(sid, id, crate::state::server::ConnectionStatus::Closed).await;
            }).await;
        }
    });
    state.register_server_task(sid, task).await;
    Ok(local)
}
pub async fn connect<S: ScannerSession>(
    ctx: ConnectContext,
    protocol: Arc<dyn Client>,
    mut session: S,
    kinds: [&'static crate::protocol::EventType; 2],
) -> Result<SocketAddr> {
    ensure!(!ctx.remote_addr.is_empty(), "remote_addr is required");
    let tcp =
        tokio::time::timeout(RESPONSE_TIMEOUT, TcpStream::connect(&ctx.remote_addr)).await??;
    let local = tcp.local_addr()?;
    let mut stream = client_transport(tcp, &ctx.remote_addr, ctx.startup_params.as_ref()).await?;
    tokio::time::timeout(RESPONSE_TIMEOUT, session.open(&mut stream)).await??;
    let mut commands =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let state = ctx.state.clone();
    let cid = ctx.client_id;
    state
        .spawn_client_task(cid, async move {
            // Handler work has its own task so an unanswered manual turn does not block injected commands.
            let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<Event>(32);
            let (actions_tx, mut actions_rx) = tokio::sync::mpsc::channel::<Value>(32);
            let event_ctx = ctx.clone();
            let p = protocol.clone();
            let turns = ctx
                .state
                .spawn_client_task(cid, async move {
                    while let Some(event) = events_rx.recv().await {
                        let instruction = event_ctx
                            .state
                            .get_instruction_for_client(cid)
                            .await
                            .unwrap_or_default();
                        let memory = event_ctx
                            .state
                            .get_memory_for_client(cid)
                            .await
                            .unwrap_or_default();
                        match crate::client::llm_budget::call_llm_for_client(
                            &event_ctx.llm_client,
                            &event_ctx.state,
                            cid.to_string(),
                            &instruction,
                            &memory,
                            Some(&event),
                            p.as_ref(),
                            &event_ctx.status_tx,
                        )
                        .await
                        {
                            Ok(result) => {
                                if let Some(memory) = result.memory_updates {
                                    event_ctx.state.set_memory_for_client(cid, memory).await;
                                }
                                for a in result.actions {
                                    if actions_tx.send(a).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => crate::logging::emit::Log::new(Some(&event_ctx.status_tx))
                                .warn(format!("{} client handler: {e}", p.protocol_name())),
                        }
                    }
                })
                .await;
            let _ = events_tx.try_send(Event::new(
                kinds[0],
                {let mut connected=session.connected();if let Some(fields)=connected.as_object_mut(){fields.insert("remote_addr".into(),serde_json::json!(ctx.remote_addr));}connected},
            ));
            loop {
                let (action, command) = tokio::select! {
                    Some(c) = commands.recv() => (c.action.clone(),Some(c)),
                    Some(a) = actions_rx.recv() => (a,None),
                    incoming = session.idle(&mut stream) => {match incoming {Ok(Some(response))=>{ctx.state.record_access_log(AccessLogOwner::Client(cid.as_u32()),protocol.protocol_name(),None,&kinds[1].id,response.clone(),vec![]).await;if events_tx.try_send(Event::new(kinds[1],response)).is_err(){break;}},Ok(None)=>{},Err(_)=>break};continue;},
                    else => break,
                };
                if action["type"] == "disconnect" {
                    if let Some(c) = command {
                        crate::client::command_support::reply(
                            c,
                            Ok(crate::state::client_handles::ClientSendOutcome::Disconnected),
                        );
                    }
                    break;
                }
                match protocol.execute_action(action.clone()) {
                    Err(e)=>{if let Some(c)=command{crate::client::command_support::reply(c,Ok(crate::state::client_handles::ClientSendOutcome::Rejected{error:e.to_string()}));}continue;}
                    Ok(crate::llm::actions::client_trait::ClientActionResult::Disconnect)=>{let _=tokio::time::timeout(RESPONSE_TIMEOUT,session.close(&mut stream)).await;if let Some(c)=command{crate::client::command_support::reply(c,Ok(crate::state::client_handles::ClientSendOutcome::Disconnected));}break;}
                    Ok(crate::llm::actions::client_trait::ClientActionResult::WaitForMore)=>{if let Some(c)=command{crate::client::command_support::reply(c,Ok(crate::state::client_handles::ClientSendOutcome::Executed{detail:"Waiting for peer".into()}));}continue;}
                    Ok(_)=>{}
                }
                if command.is_some(){ctx.state.record_access_log(AccessLogOwner::Client(cid.as_u32()),protocol.protocol_name(),None,"injected_action",action.clone(),vec![]).await;}
                let result = match tokio::time::timeout(
                    RESPONSE_TIMEOUT,
                    session.exchange(&mut stream, &action),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(anyhow::anyhow!("device response deadline exceeded")),
                };
                let terminal = result.is_err();
                match result {
                    Ok(response) => {
                        ctx.state
                            .record_access_log(
                                AccessLogOwner::Client(cid.as_u32()),
                                protocol.protocol_name(),
                                None,
                                &kinds[1].id,
                                response.clone(),
                                vec![],
                            )
                            .await;
                        let _ = events_tx.try_send(Event::new(kinds[1], response.clone()));
                        if let Some(c) = command {
                            crate::client::command_support::reply(
                                c,
                                Ok(session.outcome(&action,&response)),
                            );
                        }
                    }
                    Err(e) => {
                        if let Some(c) = command {
                            crate::client::command_support::reply(c, Err(e));
                        }
                    }
                }
                if terminal {
                    break;
                }
            }
            turns.abort();
            let _ = stream.shutdown().await;
            ctx.state.remove_client_handle(cid).await;
            ctx.state
                .update_client_status(cid, ClientStatus::Disconnected)
                .await;
        })
        .await;
    Ok(local)
}

pub fn tls_parameters(server: bool) -> Vec<crate::llm::actions::ParameterDefinition> {
    let mut fields = vec![crate::llm::actions::ParameterDefinition {
        name: "use_tls".into(),
        type_hint: "boolean".into(),
        description: "Use implicit TLS (ADCS/NNTPS); TLS 1.2+ with certificate validation".into(),
        required: false,
        example: serde_json::json!(true),
        default: Some(serde_json::json!(DEFAULT_USE_TLS)),
    }];
    for (name, description) in if server {
        vec![
            (
                "cert_path",
                "PEM server certificate chain; required with use_tls",
            ),
            ("key_path", "PEM private key; required with use_tls"),
        ]
    } else {
        vec![
            (
                "ca_path",
                "Optional PEM trust anchors, added to public roots",
            ),
            (
                "server_name",
                "Optional expected TLS DNS name; defaults to remote hostname",
            ),
        ]
    } {
        fields.push(crate::llm::actions::ParameterDefinition {
            name: name.into(),
            type_hint: "string".into(),
            description: description.into(),
            required: false,
            example: serde_json::json!(""),
            default: None,
        });
    }
    fields
}
fn optional(params: Option<&crate::protocol::StartupParams>, key: &str) -> Result<Option<String>> {
    Ok(params
        .map(|p| p.get_optional_string(key))
        .transpose()?
        .flatten())
}
pub fn use_tls(params: Option<&crate::protocol::StartupParams>) -> Result<bool> {
    Ok(params
        .map(|p| p.get_optional_bool("use_tls"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_USE_TLS))
}
pub fn server_tls(
    params: Option<&crate::protocol::StartupParams>,
) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    use std::{fs::File, io::BufReader};
    if !use_tls(params)? {
        return Ok(None);
    }
    let cert =
        optional(params, "cert_path")?.ok_or_else(|| anyhow::anyhow!("TLS requires cert_path"))?;
    let key =
        optional(params, "key_path")?.ok_or_else(|| anyhow::anyhow!("TLS requires key_path"))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("PEM key missing"))?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}
pub async fn client_transport(
    tcp: TcpStream,
    remote: &str,
    params: Option<&crate::protocol::StartupParams>,
) -> Result<Stream> {
    use std::{fs::File, io::BufReader};
    if !use_tls(params)? {
        return Ok(Box::new(tcp));
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = optional(params, "ca_path")? {
        for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)) {
            roots.add(cert?)?;
        }
    }
    let name = optional(params, "server_name")?.unwrap_or_else(|| {
        remote
            .rsplit_once(':')
            .map_or(remote, |p| p.0)
            .trim_matches(['[', ']'])
            .to_string()
    });
    let name = rustls::pki_types::ServerName::try_from(name)?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await??;
    Ok(Box::new(stream))
}

/// Cancellation-safe frame accumulator: bytes consumed before an await stay in self.
#[derive(Default)]
pub struct Framer {
    pending: Vec<u8>,
    deadline: Option<tokio::time::Instant>,
}
impl Framer {
    async fn byte(&mut self, stream: &mut (impl AsyncRead + Unpin)) -> Result<u8> {
        let deadline = self
            .deadline
            .unwrap_or_else(|| tokio::time::Instant::now() + IDLE_TIMEOUT);
        let byte = tokio::time::timeout_at(deadline, stream.read_u8()).await??;
        self.deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + RESPONSE_TIMEOUT);
        Ok(byte)
    }
    pub async fn delimited(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        delimiter: u8,
        max: usize,
    ) -> Result<Vec<u8>> {
        loop {
            ensure!(self.pending.len() < max, "frame exceeds cap");
            let byte = self.byte(stream).await?;
            self.pending.push(byte);
            if byte == delimiter {
                self.deadline = None;
                return Ok(std::mem::take(&mut self.pending));
            }
        }
    }
    pub async fn sized(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        header: usize,
        max: usize,
        length: fn(&[u8]) -> Result<usize>,
    ) -> Result<Vec<u8>> {
        loop {
            let wanted = if self.pending.len() < header {
                header
            } else {
                length(&self.pending[..header])?
            };
            ensure!((header..=max).contains(&wanted), "invalid frame size");
            if self.pending.len() == wanted {
                self.deadline = None;
                return Ok(std::mem::take(&mut self.pending));
            }
            let byte = self.byte(stream).await?;
            self.pending.push(byte);
        }
    }
}

pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut value = 0u32;
    let mut bits = 0usize;
    let mut text = String::new();
    for &byte in bytes {
        value = (value << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(ALPHABET[((value >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        text.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    text
}

#[cfg(not(target_arch = "wasm32"))]
pub mod files;
