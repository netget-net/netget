//! SSH commands and bounded SFTP v3 operations on one authenticated owned session.
pub mod actions;
pub mod sftp;
use crate::client::{command_support, llm_budget::call_llm_for_client_batch};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::state::{
    client_handles::{ClientCommand, ClientSendOutcome},
    AccessLogOwner, ClientStatus,
};
pub use actions::SshClientProtocol;
use actions::{
    SSH_CLIENT_CONNECTED_EVENT, SSH_CLIENT_OUTPUT_RECEIVED_EVENT, SSH_OPERATION_FAILED_EVENT,
    SSH_SFTP_RESULT_EVENT,
};
use anyhow::{bail, ensure, Context, Result};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use russh::{
    client::{self, Handle},
    ChannelMsg, Disconnect,
};
use russh_keys::key;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{Shutdown, SocketAddr},
    sync::Arc,
    time::Duration,
};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_OPERATIONS: usize = 16;
pub const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
pub const MAX_CHANNEL_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_CHANNEL_MESSAGES: usize = 4096;
const MAX_FOLLOWUP_DEPTH: u8 = 4;
const CONNECT_DEPTH: u8 = u8::MAX;
type HandlerFuture = BoxFuture<'static, (u8, Result<Vec<Value>>)>;
type OperationFuture = BoxFuture<'static, (u8, Event)>;
struct SocketGuard(Arc<std::net::TcpStream>);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
struct ClientHandler {
    expected: Option<String>,
    channels: HashMap<russh::ChannelId, (usize, usize)>,
}
impl ClientHandler {
    fn receive(&mut self, channel: russh::ChannelId, bytes: usize) -> Result<()> {
        let (received, messages) = self
            .channels
            .get_mut(&channel)
            .context("SSH data for an unowned channel")?;
        ensure!(
            bytes <= MAX_CHANNEL_BYTES.saturating_sub(*received),
            "SSH channel byte budget exceeded"
        );
        ensure!(
            *messages < MAX_CHANNEL_MESSAGES,
            "SSH channel message budget exceeded"
        );
        *received += bytes;
        *messages += 1;
        Ok(())
    }
}
#[async_trait::async_trait]
impl client::Handler for ClientHandler {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, key: &key::PublicKey) -> Result<bool, Self::Error> {
        // Preserve legacy command-only connections; SFTP refuses an unpinned session.
        Ok(self
            .expected
            .as_ref()
            .is_none_or(|pin| key.fingerprint() == *pin))
    }
    async fn channel_open_confirmation(
        &mut self,
        channel: russh::ChannelId,
        _: u32,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        ensure!(
            self.channels.len() < MAX_OPERATIONS,
            "SSH channel count exceeds 16"
        );
        ensure!(
            self.channels.insert(channel, (0, 0)).is_none(),
            "Duplicate SSH channel"
        );
        Ok(())
    }
    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        self.channels.remove(&channel);
        Ok(())
    }
    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, data.len())
    }
    async fn extended_data(
        &mut self,
        channel: russh::ChannelId,
        _: u32,
        data: &[u8],
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, data.len())
    }
    async fn window_adjusted(
        &mut self,
        channel: russh::ChannelId,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn channel_success(
        &mut self,
        channel: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn channel_failure(
        &mut self,
        channel: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn exit_status(
        &mut self,
        channel: russh::ChannelId,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn exit_signal(
        &mut self,
        channel: russh::ChannelId,
        _: russh::Sig,
        _: bool,
        message: &str,
        language: &str,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, message.len() + language.len())
    }
    async fn xon_xoff(
        &mut self,
        channel: russh::ChannelId,
        _: bool,
        _: &mut client::Session,
    ) -> Result<()> {
        self.receive(channel, 0)
    }
    async fn server_channel_open_session(
        &mut self,
        _: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        bail!("Unsolicited SSH session channel")
    }
    async fn server_channel_open_direct_tcpip(
        &mut self,
        _: russh::ChannelId,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        bail!("Unsolicited SSH TCP channel")
    }
    async fn server_channel_open_agent_forward(
        &mut self,
        _: russh::ChannelId,
        _: &mut client::Session,
    ) -> Result<()> {
        bail!("Unsolicited SSH agent channel")
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _: russh::Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        bail!("Unsolicited SSH forwarded channel")
    }
    async fn server_channel_open_x11(
        &mut self,
        _: russh::Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &mut client::Session,
    ) -> Result<()> {
        bail!("Unsolicited SSH X11 channel")
    }
}
fn parameter(
    p: &crate::protocol::StartupParams,
    name: &str,
    default: u64,
    max: u64,
) -> Result<u64> {
    let n = p.get_optional_u64(name)?.unwrap_or(default);
    ensure!(n > 0 && n <= max, "{name} must be 1..{max}");
    Ok(n)
}
pub struct SshClient;
impl SshClient {
    /// Compatibility entry point for callers using the prior command-only API.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: crate::llm::OllamaClient,
        app_state: Arc<crate::state::AppState>,
        status_tx: tokio::sync::mpsc::UnboundedSender<String>,
        client_id: crate::state::ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        Self::connect(ConnectContext {
            remote_addr,
            llm_client,
            state: app_state,
            status_tx,
            client_id,
            startup_params,
        })
        .await
    }
    pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
        let p = ctx
            .startup_params
            .as_ref()
            .context("Missing required startup parameters for SSH client")?;
        let username = p.get_string("username")?;
        let pin = p
            .get_optional_string("host_key_sha256")?
            .map(|pin| -> Result<String> {
                use base64::Engine;
                let hash = pin
                    .strip_prefix("SHA256:")
                    .context("host_key_sha256 must start with SHA256:")?;
                ensure!(
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(hash)?
                        .len()
                        == 32,
                    "host_key_sha256 must contain a SHA256 fingerprint"
                );
                Ok(hash.to_owned())
            })
            .transpose()?;
        let pinned = pin.is_some();
        let handshake = Duration::from_secs(parameter(
            p,
            "handshake_timeout_secs",
            HANDSHAKE_TIMEOUT.as_secs(),
            60,
        )?);
        let deadline = Duration::from_secs(parameter(
            p,
            "operation_timeout_secs",
            OPERATION_TIMEOUT.as_secs(),
            300,
        )?);
        let idle = Duration::from_secs(parameter(
            p,
            "idle_timeout_secs",
            IDLE_TIMEOUT.as_secs(),
            3600,
        )?);
        let key_path = p.get_optional_string("private_key_path")?;
        let method = p.get_optional_string("auth_method")?.unwrap_or_else(|| {
            if key_path.is_some() {
                "publickey"
            } else {
                "password"
            }
            .into()
        });
        enum Credential {
            Password(String),
            Key(Arc<key::KeyPair>),
        }
        let credential = match method.as_str() {
            "password" => Credential::Password(
                p.get_optional_string("password")?
                    .context("auth_method 'password' needs the 'password' startup parameter")?,
            ),
            "publickey" => {
                let path = key_path.context(
                    "auth_method 'publickey' needs the 'private_key_path' startup parameter",
                )?;
                let passphrase = p.get_optional_string("private_key_passphrase")?;
                Credential::Key(Arc::new(
                    russh_keys::load_secret_key(&path, passphrase.as_deref())
                        .with_context(|| format!("Failed to load SSH private key from {path}"))?,
                ))
            }
            _ => bail!("Unknown SSH auth_method '{method}': expected 'password' or 'publickey'"),
        };
        let (session, socket, local, peer) = tokio::time::timeout(handshake, async {
            let stream = tokio::net::TcpStream::connect(&ctx.remote_addr).await.context("Failed to connect to SSH server")?;
            let local = stream.local_addr()?;
            let peer = stream.peer_addr()?;
            let std = stream.into_std()?;
            let socket = SocketGuard(Arc::new(std.try_clone()?));
            let stream = tokio::net::TcpStream::from_std(std)?;
            let config = client::Config { inactivity_timeout: Some(idle), window_size: 256*1024, maximum_packet_size: 32768, ..Default::default() };
            let mut session = client::connect_stream(Arc::new(config), stream, ClientHandler { expected: pin, channels: HashMap::new() }).await.context("Failed to connect to SSH server")?;
            let authenticated = match credential {
                Credential::Password(password) => session.authenticate_password(username.clone(),password).await,
                Credential::Key(key) => session.authenticate_publickey(username.clone(),key).await,
            }.context("SSH authentication failed")?;
            ensure!(authenticated, "SSH authentication failed: the server refused the {method} credential for '{username}'");
            Ok::<_,anyhow::Error>((session,socket,local,peer))
        }).await.context("SSH handshake deadline exceeded")??;
        let now = crate::utils::clock::Instant::now();
        ctx.state
            .with_client_mut(ctx.client_id, |client| {
                client.connection = Some(crate::state::ClientConnectionState {
                    id: ctx.client_id,
                    remote_addr: ctx.remote_addr.clone(),
                    connected_addr: Some(peer),
                    local_addr: Some(local),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ClientStatus::Connected,
                    status_changed_at: now,
                    protocol_info: crate::state::server::ProtocolConnectionInfo::new(
                        json!({"host_key_verified":pinned}),
                    ),
                });
            })
            .await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Connected)
            .await;
        let commands = command_support::register_command_channel(&ctx.state, ctx.client_id).await;
        let state = ctx.state.clone();
        let id = ctx.client_id;
        let event = Event::new(
            &SSH_CLIENT_CONNECTED_EVENT,
            json!({"remote_addr":ctx.remote_addr,"username":username,"host_key_verified":pinned}),
        );
        state
            .spawn_client_task(
                id,
                Self::run(ctx, session, socket, commands, event, deadline, pinned),
            )
            .await;
        Ok(local)
    }
    async fn run(
        ctx: ConnectContext,
        session: Handle<ClientHandler>,
        socket: SocketGuard,
        mut commands: tokio::sync::mpsc::Receiver<ClientCommand>,
        event: Event,
        deadline: Duration,
        pinned: bool,
    ) {
        let session = Arc::new(session);
        let mut operations: FuturesUnordered<OperationFuture> = FuturesUnordered::new();
        let mut handlers: FuturesUnordered<HandlerFuture> = FuturesUnordered::new();
        handlers.push(handle_event(ctx.clone(), event, CONNECT_DEPTH));
        // Command output that arrived while a handler was asking the model, held so that -
        // with batching on - the outputs that finished during one model call are answered
        // together in the next. Only `ssh_output_received`: SFTP results and failures are
        // answered one by one. Each keeps its operation's handler slot until it is answered.
        let mut held: Vec<(u8, Event)> = Vec::new();
        let mut check_closed = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    if enqueue(&ctx,&session,socket.0.clone(),deadline,pinned,&mut operations,handlers.len() + held.len(),command.action.clone(),Some(command),0).await { break; }
                }
                Some((depth,event)) = operations.next(), if !operations.is_empty() => {
                    let hold = event.event_type.id == SSH_CLIENT_OUTPUT_RECEIVED_EVENT.id
                        && !handlers.is_empty()
                        && ctx.state.client_conversation_settings(ctx.client_id).await.is_some_and(|(_, batching)| batching);
                    if hold {
                        held.push((depth, event));
                        if held.len() >= crate::protocol::metadata::MAX_BATCH_EVENTS {
                            handlers.push(handle_events(ctx.clone(), std::mem::take(&mut held)));
                        }
                    } else {
                        handlers.push(handle_event(ctx.clone(),event,depth));
                    }
                }
                Some((depth,result)) = handlers.next(), if !handlers.is_empty() => {
                    match result {
                        Ok(actions) if actions.len() <= MAX_OPERATIONS => {
                            let mut disconnect = false;
                            for action in actions {
                                if depth != CONNECT_DEPTH && depth >= MAX_FOLLOWUP_DEPTH && action["type"] != "disconnect" {
                                    Log::new(Some(&ctx.status_tx)).warn("SSH follow-up depth bound reached");
                                    continue;
                                }
                                let next_depth = if depth == CONNECT_DEPTH {0} else {depth+1};
                                if enqueue(&ctx,&session,socket.0.clone(),deadline,pinned,&mut operations,handlers.len() + held.len(),action,None,next_depth).await { disconnect = true; break; }
                            }
                            if disconnect { break; }
                        }
                        Ok(_) => Log::new(Some(&ctx.status_tx)).warn("SSH handler returned too many actions"),
                        Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("SSH event handler failed: {e}")),
                    }
                    // A model call has ended: what finished during it is answered now, in one
                    // call when there is more than one.
                    if !held.is_empty() {
                        handlers.push(handle_events(ctx.clone(), std::mem::take(&mut held)));
                    }
                }
                _ = check_closed.tick() => { if session.is_closed() { break; } }
            }
        }
        drop(operations);
        drop(handlers);
        if let Ok(mut session) = Arc::try_unwrap(session) {
            let _ = session
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            // Let the transport flush the disconnect, then the socket guard forces
            // closure even if the library's internally spawned driver is stalled.
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut session).await;
        }
        drop(socket);
        ctx.state.remove_client_handle(ctx.client_id).await;
        ctx.state
            .with_client_mut(ctx.client_id, |c| {
                if let Some(connection) = &mut c.connection {
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
fn handle_event(ctx: ConnectContext, event: Event, depth: u8) -> HandlerFuture {
    handle_events(ctx, vec![(depth, event)])
}
/// Ask about one event, or several held outputs in one model call, the newest the trigger.
/// The follow-up depth is the deepest of them, so a batch never extends a chain's bound.
fn handle_events(ctx: ConnectContext, held: Vec<(u8, Event)>) -> HandlerFuture {
    async move {
        let depth = held.iter().map(|(depth, _)| *depth).max().unwrap_or(0);
        let events: Vec<Event> = held.into_iter().map(|(_, event)| event).collect();
        let result = async {
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
            let result = call_llm_for_client_batch(
                &ctx.llm_client,
                &ctx.state,
                ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &SshClientProtocol,
                &ctx.status_tx,
            )
            .await?;
            if let Some(memory) = result.memory_updates {
                ctx.state.set_memory_for_client(ctx.client_id, memory).await;
            }
            Ok(result.actions)
        }
        .await;
        (depth, result)
    }
    .boxed()
}
#[allow(clippy::too_many_arguments)]
async fn enqueue(
    ctx: &ConnectContext,
    session: &Arc<Handle<ClientHandler>>,
    socket: Arc<std::net::TcpStream>,
    deadline: Duration,
    pinned: bool,
    operations: &mut FuturesUnordered<OperationFuture>,
    handlers: usize,
    action: Value,
    command: Option<ClientCommand>,
    depth: u8,
) -> bool {
    let outcome = match SshClientProtocol.execute_action(action.clone()) {
        Err(e) => Ok(ClientSendOutcome::Rejected {
            error: e.to_string(),
        }),
        Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
        Ok(ClientActionResult::WaitForMore | ClientActionResult::NoAction) => {
            Ok(ClientSendOutcome::Executed {
                detail: "wait_for_more".into(),
            })
        }
        Ok(ClientActionResult::Custom { name, .. })
            if name == "execute_command" || name == "sftp_operation" =>
        {
            if name == "sftp_operation" && !pinned {
                Ok(ClientSendOutcome::Rejected {
                    error: "SFTP requires host_key_sha256 at startup".into(),
                })
            } else if operations.len() + handlers >= MAX_OPERATIONS {
                Err(anyhow::anyhow!(
                    "SSH client busy: 16 operations or handlers"
                ))
            } else {
                operations.push(operation_future(
                    ctx.clone(),
                    session.clone(),
                    socket,
                    deadline,
                    action,
                    command,
                    depth,
                ));
                return false;
            }
        }
        Ok(_) => Ok(ClientSendOutcome::Rejected {
            error: "Unsupported SSH action".into(),
        }),
    };
    let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
    record_action(ctx, &action, &outcome).await;
    if let Some(command) = command {
        command_support::reply(command, outcome);
    }
    disconnect
}
async fn record_action(ctx: &ConnectContext, action: &Value, outcome: &Result<ClientSendOutcome>) {
    let result = match outcome {
        Ok(v) => serde_json::to_value(v).unwrap_or(Value::Null),
        Err(e) => json!({"error":e.to_string()}),
    };
    ctx.state
        .record_access_log(
            AccessLogOwner::Client(ctx.client_id.as_u32()),
            "SSH",
            None,
            "injected_action",
            action.clone(),
            vec![result],
        )
        .await;
}
fn operation_future(
    ctx: ConnectContext,
    session: Arc<Handle<ClientHandler>>,
    socket: Arc<std::net::TcpStream>,
    deadline: Duration,
    action: Value,
    command: Option<ClientCommand>,
    depth: u8,
) -> OperationFuture {
    async move {
        let (outcome,event) = match execute(&session,&socket,&action,deadline).await {
            Ok((detail,event)) => (Ok(ClientSendOutcome::Executed {detail}),event),
            Err(error) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("SSH operation failed: {error:#}"));
                let event = Event::new(&SSH_OPERATION_FAILED_EVENT,json!({"action_type":action["type"],"path":action["path"],"command":action["command"],"error":format!("{error:#}")}));
                (Err(error),event)
            }
        };
        ctx.state
            .with_client_mut(ctx.client_id, |client| {
                if let Some(connection) = &mut client.connection {
                    connection.last_activity = crate::utils::clock::Instant::now();
                }
            })
            .await;
        record_action(&ctx,&action,&outcome).await;
        if let Some(command) = command { command_support::reply(command,outcome); }
        (depth,event)
    }.boxed()
}
async fn execute(
    session: &Handle<ClientHandler>,
    socket: &std::net::TcpStream,
    action: &Value,
    deadline: Duration,
) -> Result<(String, Event)> {
    let end = tokio::time::Instant::now() + deadline;
    let mut channel = tokio::time::timeout_at(end, session.channel_open_session())
        .await
        .context("SSH channel-open deadline exceeded")??;
    let result = tokio::time::timeout_at(end, async {
        if action["type"] == "execute_command" {
            let command = action["command"].as_str().context("Missing command")?;
            channel.exec(true, command).await?;
            let mut output = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_code = None;
            let mut eof = false;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        ensure!(
                            data.len()
                                <= MAX_COMMAND_OUTPUT.saturating_sub(output.len() + stderr.len()),
                            "SSH command output exceeds 1 MiB"
                        );
                        output.extend_from_slice(&data);
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        ensure!(
                            data.len()
                                <= MAX_COMMAND_OUTPUT.saturating_sub(output.len() + stderr.len()),
                            "SSH command output exceeds 1 MiB"
                        );
                        stderr.extend_from_slice(&data);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                        if eof {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) => {
                        eof = true;
                        if exit_code.is_some() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Close) => break,
                    None => {
                        ensure!(!session.is_closed(), "SSH connection closed during command");
                        break;
                    }
                    Some(ChannelMsg::Failure) => bail!("SSH server refused command"),
                    _ => {}
                }
            }
            let detail = format!(
                "execute_command {command:?}: exit_code={}, {} bytes of output, {} of stderr",
                exit_code
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                output.len(),
                stderr.len()
            );
            let mut data = json!({"command":command,"output":String::from_utf8_lossy(&output)});
            if !stderr.is_empty() {
                data["stderr"] = json!(String::from_utf8_lossy(&stderr));
            }
            if let Some(code) = exit_code {
                data["exit_code"] = json!(code);
            }
            Ok((detail, Event::new(&SSH_CLIENT_OUTPUT_RECEIVED_EVENT, data)))
        } else {
            channel.request_subsystem(true, "sftp").await?;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => break,
                    Some(ChannelMsg::WindowAdjusted { .. }) => {}
                    _ => bail!("SSH server refused SFTP subsystem"),
                }
            }
            let writer = channel.make_writer();
            let reader = channel.make_reader();
            let result = sftp::exchange(tokio::io::join(reader, writer), action).await?;
            let detail = format!(
                "{} {} completed",
                action["type"].as_str().unwrap_or("sftp"),
                action["path"].as_str().unwrap_or("")
            );
            Ok((detail, Event::new(&SSH_SFTP_RESULT_EVENT, result)))
        }
    })
    .await
    .map_err(|error| anyhow::anyhow!(error).context("SSH operation deadline exceeded"))
    .and_then(|result| result);
    // Closing a timed-out or malformed channel does not end unrelated operations.
    // A blocked transport cannot retain an orphan channel past client removal.
    if tokio::time::timeout(Duration::from_millis(250), async {
        channel.eof().await?;
        channel.close().await
    })
    .await
    .is_err()
    {
        let _ = socket.shutdown(Shutdown::Both);
    }
    result
}
