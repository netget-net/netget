//! Kerberos V5 client: NetGet gets TGTs and service tickets from a KDC, and the model decides
//! which.
//!
//! Two tasks, both registered with the client: **session** owns the credentials (the password,
//! the TGT and the service tickets) and performs every exchange, for the model's actions and for
//! injected ones alike; **turns** asks the model about each result, in order, and hands its
//! actions back with the depth they were asked at. A chain stops at [`MAX_FOLLOWUP_DEPTH`].
//!
//! Every exchange is a fresh UDP socket or TCP connection to the KDC, as MIT's and Heimdal's
//! libraries do it. See `src/client/kerberos/AGENTS.md`.

pub mod actions;
pub mod ccache;
pub mod wire;

pub use actions::KerberosClientProtocol;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::kerberos::codec::{
    self, Key, Principal, KDC_ERR_PREAUTH_REQUIRED, KRB_ERR_RESPONSE_TOO_BIG, MAX_MESSAGE_LEN,
    SUPPORTED_ETYPES,
};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};

use actions::{
    Exchange, DEFAULT_RETRIES, DEFAULT_TIMEOUT_MS, DEFAULT_TRANSPORT, KERBEROS_CLIENT_READY_EVENT,
    KERBEROS_REQUEST_FAILED_EVENT, KERBEROS_SERVICE_TICKET_EVENT, KERBEROS_TGT_OBTAINED_EVENT,
};
use wire::{Credential, Expect, Reply, Request};

/// Turns of model-chosen follow-ups before the chain stops asking.
pub const MAX_FOLLOWUP_DEPTH: u32 = 6;

/// Service tickets kept (and written to the ccache) at once; the oldest is dropped past it.
pub const MAX_SERVICE_TICKETS: usize = 64;

const TURN_QUEUE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// Why an exchange produced no usable reply.
#[derive(Debug)]
struct Failure {
    kind: &'static str,
    message: String,
}

fn failure(kind: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        kind,
        message: message.into(),
    }
}

/// Everything the session owns. Not `Debug`: it holds the password and the keys.
struct Session {
    kdc: SocketAddr,
    transport: Transport,
    timeout: Duration,
    retries: u32,
    client: Principal,
    realm: String,
    password: String,
    tgt: Option<Credential>,
    tickets: Vec<Credential>,
    ccache: Option<PathBuf>,
}

/// The outcome of one action, as an event.
enum Outcome {
    Tgt(Credential),
    Service(Credential),
    Failed(Value),
}

impl Session {
    /// Send one message and read one reply, over the configured transport. A UDP reply of
    /// KRB_ERR_RESPONSE_TOO_BIG is retried over TCP (RFC 4120 §7.2.1).
    async fn exchange(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Failure> {
        if self.transport == Transport::Udp {
            let reply = self.exchange_udp(message).await?;
            if let Ok(Reply::Error(e)) = wire::parse_reply(&reply) {
                if e.error_code.0 as i32 == KRB_ERR_RESPONSE_TOO_BIG {
                    debug!(
                        "Kerberos client: the KDC's reply is too big for UDP; retrying over TCP"
                    );
                    return self.exchange_tcp(message).await;
                }
            }
            return Ok(reply);
        }
        self.exchange_tcp(message).await
    }

    async fn exchange_udp(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Failure> {
        let bind = if self.kdc.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| failure("transport", format!("cannot open a UDP socket: {e}")))?;
        socket
            .connect(self.kdc)
            .await
            .map_err(|e| failure("transport", format!("cannot reach {}: {e}", self.kdc)))?;
        // One byte past the bound, so an oversize datagram is seen as oversize.
        let mut buf = vec![0u8; MAX_MESSAGE_LEN + 1];
        for _ in 0..=self.retries {
            socket
                .send(message)
                .await
                .map_err(|e| failure("transport", format!("send failed: {e}")))?;
            match tokio::time::timeout(self.timeout, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > MAX_MESSAGE_LEN => {
                    return Err(failure(
                        "oversize",
                        format!("the KDC sent a datagram over {MAX_MESSAGE_LEN} bytes"),
                    ))
                }
                Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
                Ok(Err(e)) => return Err(failure("transport", format!("receive failed: {e}"))),
                Err(_) => continue,
            }
        }
        Err(failure(
            "timeout",
            format!(
                "no reply from {} after {} attempt(s)",
                self.kdc,
                self.retries + 1
            ),
        ))
    }

    async fn exchange_tcp(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Failure> {
        let work = async {
            let mut stream = TcpStream::connect(self.kdc).await.map_err(|e| {
                failure("transport", format!("cannot connect to {}: {e}", self.kdc))
            })?;
            let mut framed = Vec::with_capacity(4 + message.len());
            framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
            framed.extend_from_slice(message);
            stream
                .write_all(&framed)
                .await
                .map_err(|e| failure("transport", format!("send failed: {e}")))?;
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).await.map_err(|e| {
                failure("transport", format!("the KDC closed without replying: {e}"))
            })?;
            let len = u32::from_be_bytes(prefix);
            if len & 0x8000_0000 != 0 || len as usize > MAX_MESSAGE_LEN {
                return Err(failure(
                    "oversize",
                    format!("the KDC declared a {len}-byte reply; the limit is {MAX_MESSAGE_LEN}"),
                ));
            }
            let mut reply = vec![0u8; len as usize];
            stream
                .read_exact(&mut reply)
                .await
                .map_err(|e| failure("transport", format!("the reply was cut short: {e}")))?;
            Ok(reply)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(failure(
                "timeout",
                format!("no reply from {} within {:?}", self.kdc, self.timeout),
            )),
        }
    }

    fn failed(stage: &str, service: &Principal, f: Failure) -> Outcome {
        Outcome::Failed(json!({
            "stage": stage,
            "service": service.to_string(),
            "kind": f.kind,
            "message": f.message,
        }))
    }

    fn kdc_error(
        stage: &str,
        service: &Principal,
        e: &picky_krb::messages::KrbErrorInner,
    ) -> Outcome {
        let mut data = wire::error_summary(e);
        data["stage"] = json!(stage);
        data["service"] = json!(service.to_string());
        data["kind"] = json!("kdc_error");
        Outcome::Failed(data)
    }

    /// The AS exchange: unauthenticated first, then pre-authenticated with the salt the KDC
    /// names, as MIT kinit does.
    async fn request_tgt(&mut self, request: &Request) -> Outcome {
        let tgs = Principal::krbtgt(&self.realm);
        let first_nonce = wire::nonce();
        let first = match wire::as_req(
            &self.client,
            &self.realm,
            &tgs,
            request,
            first_nonce,
            Vec::new(),
        ) {
            Ok(m) => m,
            Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
        };
        let reply = match self.exchange(&first).await {
            Ok(r) => r,
            Err(f) => return Self::failed("as", &tgs, f),
        };
        let (rep, key, nonce) = match wire::parse_reply(&reply) {
            Ok(Reply::As(rep)) => {
                // Issued without pre-authentication: the reply names the salt, or the default.
                let etype = codec::int_i64(&rep.enc_part.0.etype.0).unwrap_or(-1) as i32;
                let info = rep
                    .padata
                    .0
                    .as_ref()
                    .map(|p| wire::etype_info_from_padata(&p.0 .0))
                    .unwrap_or_default();
                let salt = info
                    .iter()
                    .find(|(e, _)| *e == etype)
                    .and_then(|(_, s)| s.clone())
                    .unwrap_or_else(|| self.client.default_salt(&self.realm));
                match Key::from_password(etype, &self.password, &salt) {
                    Ok(k) => (rep, k, first_nonce),
                    Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
                }
            }
            Ok(Reply::Error(e)) if e.error_code.0 as i32 == KDC_ERR_PREAUTH_REQUIRED => {
                let info = wire::etype_info_from_error(&e);
                let chosen = info
                    .iter()
                    .find(|(etype, _)| SUPPORTED_ETYPES.contains(etype))
                    .cloned()
                    .unwrap_or((SUPPORTED_ETYPES[0], None));
                let salt = chosen
                    .1
                    .unwrap_or_else(|| self.client.default_salt(&self.realm));
                let key = match Key::from_password(chosen.0, &self.password, &salt) {
                    Ok(k) => k,
                    Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
                };
                let nonce = wire::nonce();
                let second = match wire::pa_enc_timestamp(&key).and_then(|pa| {
                    wire::as_req(&self.client, &self.realm, &tgs, request, nonce, vec![pa])
                }) {
                    Ok(m) => m,
                    Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
                };
                let reply = match self.exchange(&second).await {
                    Ok(r) => r,
                    Err(f) => return Self::failed("as", &tgs, f),
                };
                match wire::parse_reply(&reply) {
                    Ok(Reply::As(rep)) => (rep, key, nonce),
                    Ok(Reply::Error(e)) => return Self::kdc_error("as", &tgs, &e),
                    Ok(Reply::Tgs(_)) => {
                        return Self::failed(
                            "as",
                            &tgs,
                            failure("malformed", "a TGS-REP answered an AS-REQ"),
                        )
                    }
                    Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
                }
            }
            Ok(Reply::Error(e)) => return Self::kdc_error("as", &tgs, &e),
            Ok(Reply::Tgs(_)) => {
                return Self::failed(
                    "as",
                    &tgs,
                    failure("malformed", "a TGS-REP answered an AS-REQ"),
                )
            }
            Err(e) => return Self::failed("as", &tgs, failure("malformed", e.to_string())),
        };
        let expect = Expect {
            client: &self.client,
            client_realm: &self.realm,
            service: &tgs,
            service_realm: &self.realm,
            nonce,
        };
        match wire::verify_rep(&rep, &key, codec::KU_AS_REP_ENC_PART, &expect) {
            Ok(cred) => Outcome::Tgt(cred),
            Err(e) => Self::failed("as", &tgs, failure("integrity", e.to_string())),
        }
    }

    /// The TGS exchange with the current TGT and a fresh subkey.
    async fn request_service(&mut self, service: &Principal, request: &Request) -> Outcome {
        let Some(tgt) = self.tgt.clone() else {
            return Self::failed("tgs", service, failure("no_tgt", "request a TGT first"));
        };
        if tgt.endtime <= codec::now_secs() {
            return Self::failed("tgs", service, failure("no_tgt", "the TGT has expired"));
        }
        let subkey = match Key::random(tgt.session_key.etype()) {
            Ok(k) => k,
            Err(e) => return Self::failed("tgs", service, failure("malformed", e.to_string())),
        };
        let nonce = wire::nonce();
        let message = match wire::tgs_req(&tgt, service, request, nonce, &subkey) {
            Ok(m) => m,
            Err(e) => return Self::failed("tgs", service, failure("malformed", e.to_string())),
        };
        let reply = match self.exchange(&message).await {
            Ok(r) => r,
            Err(f) => return Self::failed("tgs", service, f),
        };
        let rep = match wire::parse_reply(&reply) {
            Ok(Reply::Tgs(rep)) => rep,
            Ok(Reply::Error(e)) => return Self::kdc_error("tgs", service, &e),
            Ok(Reply::As(_)) => {
                return Self::failed(
                    "tgs",
                    service,
                    failure("malformed", "an AS-REP answered a TGS-REQ"),
                )
            }
            Err(e) => return Self::failed("tgs", service, failure("malformed", e.to_string())),
        };
        let expect = Expect {
            client: &self.client,
            client_realm: &self.realm,
            service,
            service_realm: &self.realm,
            nonce,
        };
        match wire::verify_rep(&rep, &subkey, codec::KU_TGS_REP_ENC_SUBKEY, &expect) {
            Ok(cred) => Outcome::Service(cred),
            Err(e) => Self::failed("tgs", service, failure("integrity", e.to_string())),
        }
    }

    fn write_ccache(&self, status_tx: &mpsc::UnboundedSender<String>) {
        let Some(path) = &self.ccache else {
            return;
        };
        let mut creds = Vec::with_capacity(1 + self.tickets.len());
        creds.extend(self.tgt.iter().cloned());
        creds.extend(self.tickets.iter().cloned());
        if let Err(e) = ccache::write_ccache(path, (&self.client, &self.realm), &creds) {
            Log::new(Some(status_tx)).warn(format!("Kerberos client: {e:#}"));
        }
    }
}

/// Parse the startup parameters and start the client's tasks.
pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx
        .startup_params
        .as_ref()
        .context("the Kerberos client needs startup parameters 'principal' and 'password'")?;
    let principal_text = params.get_string("principal")?;
    let password = params.get_string("password")?;
    ensure!(
        !password.is_empty(),
        "the Kerberos client needs a non-empty password"
    );
    let (client, named_realm) = Principal::parse(&principal_text)?;
    let realm = match (named_realm, params.get_optional_string("realm")?) {
        (Some(a), Some(b)) if a != b => bail!("principal names realm {a} but realm is {b}"),
        (Some(a), _) => a,
        (None, Some(b)) => {
            codec::check_realm(&b)?;
            b
        }
        (None, None) => bail!("name the realm: principal alice@REALM, or startup parameter realm"),
    };
    let transport = match params
        .get_optional_string("transport")?
        .unwrap_or_else(|| DEFAULT_TRANSPORT.to_string())
        .as_str()
    {
        "udp" => Transport::Udp,
        "tcp" => Transport::Tcp,
        other => bail!("transport must be udp or tcp, not {other}"),
    };
    let timeout_ms = params
        .get_optional_u64("timeout_ms")?
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    ensure!(
        (100..=60_000).contains(&timeout_ms),
        "timeout_ms must be 100-60000"
    );
    let retries = params
        .get_optional_u64("retries")?
        .unwrap_or(DEFAULT_RETRIES);
    ensure!(retries <= 5, "retries must be 0-5");
    let ccache = params
        .get_optional_string("ccache_path")?
        .map(PathBuf::from);
    ensure!(
        !ctx.remote_addr.trim().is_empty(),
        "the Kerberos client needs the KDC's host:port as remote_addr; refusing to guess one"
    );
    let kdc = tokio::net::lookup_host(ctx.remote_addr.trim())
        .await
        .with_context(|| format!("cannot resolve the KDC {}", ctx.remote_addr))?
        .next()
        .with_context(|| format!("{} resolved to no address", ctx.remote_addr))?;

    let session = Session {
        kdc,
        transport,
        timeout: Duration::from_millis(timeout_ms),
        retries: retries as u32,
        client: client.clone(),
        realm: realm.clone(),
        password,
        tgt: None,
        tickets: Vec::new(),
        ccache,
    };
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Kerberos client {} ready: {client}@{realm} via {kdc} ({})",
        ctx.client_id,
        transport.name()
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURN_QUEUE);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &KERBEROS_CLIENT_READY_EVENT,
            json!({
                "kdc": kdc.to_string(),
                "principal": format!("{client}@{realm}"),
                "transport": transport.name(),
            }),
        ),
        0,
    ));
    let turns = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let turns_abort = turns.abort_handle();
    ctx.state.register_client_task(ctx.client_id, turns).await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        run_session(&session_ctx, session, external, internal, event_tx).await;
        turns_abort.abort();
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(kdc)
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = KerberosClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            warn!(
                "Kerberos client {} not asking the model about {}: {depth} turns deep decision=followup_depth",
                ctx.client_id,
                event.id()
            );
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
                info!(
                    "Kerberos client {} {} decision={} actions={}",
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
            Err(e) => warn!(
                "Kerberos client {} {} decision=llm_error: {e}",
                ctx.client_id,
                event.id()
            ),
        }
    }
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

async fn run_session(
    ctx: &ConnectContext,
    mut session: Session,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) {
    let protocol = KerberosClientProtocol;
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return,
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return,
            },
        };
        let exchange = match protocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                info!("Kerberos client {} stopped on request", ctx.client_id);
                reply(command, ClientSendOutcome::Disconnected);
                return;
            }
            Ok(_) => match actions::exchange_from_action(&action) {
                Ok(Some(x)) => x,
                Ok(None) => continue,
                Err(e) => {
                    reply(
                        command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            },
            Err(e) => {
                warn!("Kerberos client {} refused an action: {e}", ctx.client_id);
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        let outcome = match &exchange {
            Exchange::Tgt(request) => session.request_tgt(request).await,
            Exchange::Service(service, request) => session.request_service(service, request).await,
        };
        let (event, data) = match outcome {
            Outcome::Tgt(cred) => {
                let data = cred.summary();
                info!(
                    "Kerberos client {} obtained a TGT for {} decision=tgt_obtained",
                    ctx.client_id, data["client"]
                );
                session.tgt = Some(cred);
                session.write_ccache(&ctx.status_tx);
                (Event::new(&KERBEROS_TGT_OBTAINED_EVENT, data.clone()), data)
            }
            Outcome::Service(cred) => {
                let data = cred.summary();
                info!(
                    "Kerberos client {} obtained a ticket for {} decision=service_ticket_obtained",
                    ctx.client_id, data["service"]
                );
                session
                    .tickets
                    .retain(|t| !t.service.same_name(&cred.service));
                if session.tickets.len() >= MAX_SERVICE_TICKETS {
                    session.tickets.remove(0);
                }
                session.tickets.push(cred);
                session.write_ccache(&ctx.status_tx);
                (
                    Event::new(&KERBEROS_SERVICE_TICKET_EVENT, data.clone()),
                    data,
                )
            }
            Outcome::Failed(data) => {
                warn!(
                    "Kerberos client {} request failed decision=request_failed: {}",
                    ctx.client_id, data
                );
                (
                    Event::new(&KERBEROS_REQUEST_FAILED_EVENT, data.clone()),
                    data,
                )
            }
        };
        if command.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Kerberos",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![data.clone()],
                )
                .await;
        }
        reply(
            command,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        if events.try_send((event, depth)).is_err() {
            warn!(
                "Kerberos client {} dropped an event: the model is {TURN_QUEUE} events behind decision=turn_queue_full",
                ctx.client_id
            );
        }
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}
