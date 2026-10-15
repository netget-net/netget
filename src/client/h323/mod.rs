//! H.323 client: an endpoint that registers with a gatekeeper and places calls.
//!
//! `remote_addr` is a gatekeeper's RAS address (mode `gatekeeper`) or an endpoint's call
//! signalling address (mode `endpoint`). With a gatekeeper, `connect()` runs discovery (GRQ,
//! unless `discover` is false) and registration (RRQ) before it returns — the model is not
//! consulted inside it — and fails only when the gatekeeper does not answer at all: a GRJ or
//! RRJ is a result, reported in `h323_client_ready`.
//!
//! The session then raises `h323_client_ready` and carries out the model's actions. A call is
//! ARQ (when registered) → TCP connect → Setup with fastStart G.711 proposals and H.245
//! tunnelling → the callee's CallProceeding / Alerting / Connect / Release Complete / Facility,
//! each decoded; tunnelled H.245 runs underneath (`crate::server::h323::h245`). Results arrive
//! as `h323_call_connected`, `h323_call_released`, `h323_call_forwarded`, `h323_call_failed`.
//! Hanging up is Release Complete and, when registered, DRQ.
//!
//! The registration is refreshed with a keep-alive RRQ before its time-to-live runs out; an IRQ
//! from the gatekeeper is answered with IRR and its URQ with UCF. A call arriving on the
//! registered call signalling address is refused (this client places calls).
//!
//! Failing closed: an action the model gives that cannot be carried out is reported back as
//! `h323_error` and nothing is sent for it; a call the model never hangs up is released when
//! the callee does, the connection closes, or — unanswered — after [`ANSWER_TIMEOUT`]. A
//! follow-up chain (a result whose answer places a call whose result …) stops at
//! [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::h323::call::{self, cause, CallLeg, CallState, Incoming, MediaSockets, Role};
use crate::server::h323::q931::{self, ie, msg, Q931};
use crate::server::h323::{gatekeeper, h225, h245};
use crate::state::client_handles::{ClientCommand as External, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use actions::ClientCommand;
pub use actions::H323ClientProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

/// How long to wait for one RAS answer before retransmitting.
pub const RAS_TIMEOUT: Duration = Duration::from_secs(3);
/// How many times a RAS request is sent before it is given up.
pub const RAS_TRIES: u32 = 3;
/// The longest a RequestInProgress may extend one RAS wait.
const MAX_RIP_WAIT: Duration = Duration::from_secs(30);
/// TCP connect to the callee.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a placed call may go unanswered before NetGet releases it.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);
/// Signalling silence a call may keep before NetGet drops it.
pub const CALL_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// How many model turns may follow from one another.
pub const MAX_FOLLOWUP_DEPTH: u32 = 6;
/// The bandwidth asked for in ARQ: 128 kbit/s, two G.711 streams, in units of 100 bit/s.
const CALL_BANDWIDTH: u64 = 1280;
const INBOUND_QUEUE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Gatekeeper,
    Endpoint,
}

struct Config {
    mode: Mode,
    aliases: Vec<Value>,
    ttl: u64,
    discover: bool,
    codecs: Vec<h245::Codec>,
}

fn config(ctx: &ConnectContext, remote: SocketAddr) -> Result<Config> {
    let params = ctx.startup_params.as_ref();
    let mode = params
        .map(|p| p.get_optional_string("mode"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| actions::DEFAULT_MODE.to_string());
    let mode = match mode.as_str() {
        "gatekeeper" => Mode::Gatekeeper,
        "endpoint" => Mode::Endpoint,
        "auto" if remote.port() == 1719 => Mode::Gatekeeper,
        "auto" => Mode::Endpoint,
        other => bail!("mode {other:?} is gatekeeper, endpoint or auto"),
    };
    let aliases = match params
        .map(|p| p.get_optional_array("aliases"))
        .transpose()?
        .flatten()
    {
        Some(a) => h225::aliases(&Value::Array(a.clone()))?,
        None => vec![h225::alias(actions::DEFAULT_ALIAS)?],
    };
    let ttl = params
        .map(|p| p.get_optional_u64("time_to_live"))
        .transpose()?
        .flatten()
        .unwrap_or(gatekeeper::DEFAULT_TTL_SECS);
    anyhow::ensure!(
        (1..=gatekeeper::MAX_TTL_SECS).contains(&ttl),
        "time_to_live is 1 to {} seconds",
        gatekeeper::MAX_TTL_SECS
    );
    let discover = params
        .map(|p| p.get_optional_bool("discover"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_DISCOVER);
    let codecs = crate::server::h323::actions::codecs_from_params(params)?;
    Ok(Config {
        mode,
        aliases,
        ttl,
        discover,
        codecs,
    })
}

/// The RAS side of the client: one socket, one gatekeeper.
struct Ras {
    socket: UdpSocket,
    gatekeeper: SocketAddr,
    local: SocketAddr,
    call_signal: SocketAddr,
    seq: u16,
    gatekeeper_id: Option<String>,
    endpoint_id: Option<String>,
    aliases: Vec<Value>,
    ttl: u64,
    refresh_at: Option<tokio::time::Instant>,
}

impl Ras {
    fn next_seq(&mut self) -> u16 {
        self.seq = if self.seq == u16::MAX { 1 } else { self.seq + 1 };
        self.seq
    }

    /// Send one request and wait for its answer, retransmitting. `Ok(None)` when no answer
    /// came. Requests from the gatekeeper that arrive meanwhile are answered.
    async fn transact(&mut self, kind: &str, mut body: Value) -> Result<Option<(String, Value)>> {
        let seq = self.next_seq();
        body["requestSeqNum"] = json!(seq);
        let bytes = h225::encode_ras(kind, body)?;
        for _ in 0..RAS_TRIES {
            self.socket.send_to(&bytes, self.gatekeeper).await?;
            let mut deadline = tokio::time::Instant::now() + RAS_TIMEOUT;
            let mut buf = vec![0u8; gatekeeper::MAX_RAS_DATAGRAM];
            loop {
                let got = tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buf)).await;
                let (n, from) = match got {
                    Err(_) => break,
                    Ok(r) => r?,
                };
                let Ok((k, b)) = h225::decode_ras(&buf[..n]) else {
                    continue;
                };
                if h225::seq_num(&b) == Some(seq) && k == "requestInProgress" {
                    let delay = b.get("delay").and_then(|d| d.as_u64()).unwrap_or(5000);
                    deadline = tokio::time::Instant::now()
                        + Duration::from_millis(delay).min(MAX_RIP_WAIT);
                    continue;
                }
                if h225::seq_num(&b) == Some(seq)
                    && (k.ends_with("Confirm") || k.ends_with("Reject"))
                {
                    return Ok(Some((k, b)));
                }
                let _ = self.answer_gatekeeper(&k, &b, from).await;
            }
        }
        Ok(None)
    }

    /// Answer a request the gatekeeper started (IRQ, URQ). Returns `true` when the gatekeeper
    /// unregistered this endpoint.
    async fn answer_gatekeeper(
        &mut self,
        kind: &str,
        body: &Value,
        from: SocketAddr,
    ) -> Result<bool> {
        let Some(seq) = h225::seq_num(body) else {
            return Ok(false);
        };
        match kind {
            "infoRequest" => {
                let mut irr = json!({
                    "requestSeqNum": seq,
                    "endpointType": h225::endpoint_type("terminal"),
                    "endpointIdentifier": self.endpoint_id.clone().unwrap_or_else(|| "unregistered".into()),
                    "rasAddress": h225::transport(self.local),
                    "callSignalAddress": [h225::transport(self.call_signal)],
                    "needResponse": false,
                    "unsolicited": false,
                });
                if !self.aliases.is_empty() {
                    irr["endpointAlias"] = Value::Array(self.aliases.clone());
                }
                let bytes = h225::encode_ras("infoRequestResponse", irr)?;
                self.socket.send_to(&bytes, from).await?;
                Ok(false)
            }
            "unregistrationRequest" => {
                let bytes =
                    h225::encode_ras("unregistrationConfirm", json!({"requestSeqNum": seq}))?;
                self.socket.send_to(&bytes, from).await?;
                self.endpoint_id = None;
                self.refresh_at = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn discover(&mut self) -> Result<Option<Value>> {
        let mut grq = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "rasAddress": h225::transport(self.local),
            "endpointType": h225::endpoint_type("terminal"),
            "supportsAssignedGK": false,
        });
        if !self.aliases.is_empty() {
            grq["endpointAlias"] = Value::Array(self.aliases.clone());
        }
        Ok(match self.transact("gatekeeperRequest", grq).await? {
            None => None,
            Some((k, b)) if k == "gatekeeperConfirm" => {
                self.gatekeeper_id = b
                    .get("gatekeeperIdentifier")
                    .and_then(|g| g.as_str())
                    .map(str::to_string);
                if let Some(ras) = b.get("rasAddress").and_then(h225::socket_addr) {
                    if !ras.ip().is_unspecified() {
                        self.gatekeeper = ras;
                    }
                }
                Some(json!({
                    "result": "confirmed",
                    "gatekeeper_id": self.gatekeeper_id.as_deref().map(crate::utils::sanitize::strip_controls),
                    "ras_address": self.gatekeeper.to_string(),
                }))
            }
            Some((_, b)) => Some(json!({
                "result": "rejected",
                "reason": h225::choice_name(b.get("rejectReason")),
            })),
        })
    }

    async fn register(&mut self, aliases: Vec<Value>, ttl: u64, discovered: bool) -> Result<Value> {
        let mut rrq = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "discoveryComplete": discovered,
            "callSignalAddress": [h225::transport(self.call_signal)],
            "rasAddress": [h225::transport(self.local)],
            "terminalType": h225::endpoint_type("terminal"),
            "endpointVendor": h225::vendor(),
            "timeToLive": ttl,
            "keepAlive": false,
            "willSupplyUUIEs": false,
            "maintainConnection": false,
            "supportsAssignedGK": false,
        });
        if !aliases.is_empty() {
            rrq["terminalAlias"] = Value::Array(aliases.clone());
        }
        if let Some(g) = &self.gatekeeper_id {
            rrq["gatekeeperIdentifier"] = json!(g);
        }
        Ok(match self.transact("registrationRequest", rrq).await? {
            None => json!({"request": "RRQ", "result": "timeout"}),
            Some((k, b)) if k == "registrationConfirm" => {
                self.endpoint_id = b
                    .get("endpointIdentifier")
                    .and_then(|e| e.as_str())
                    .map(str::to_string);
                self.aliases = b
                    .get("terminalAlias")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or(aliases);
                self.ttl = b
                    .get("timeToLive")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(ttl)
                    .max(1);
                if self.gatekeeper_id.is_none() {
                    self.gatekeeper_id = b
                        .get("gatekeeperIdentifier")
                        .and_then(|g| g.as_str())
                        .map(str::to_string);
                }
                self.refresh_at = Some(tokio::time::Instant::now() + refresh_interval(self.ttl));
                json!({
                    "request": "RRQ",
                    "result": "confirmed",
                    "endpoint_id": self.endpoint_id.as_deref().map(crate::utils::sanitize::strip_controls),
                    "aliases": self.aliases.iter().map(h225::alias_text).collect::<Vec<_>>(),
                    "time_to_live": self.ttl,
                    "gatekeeper_id": self.gatekeeper_id.as_deref().map(crate::utils::sanitize::strip_controls),
                })
            }
            Some((_, b)) => json!({
                "request": "RRQ",
                "result": "rejected",
                "reason": h225::choice_name(b.get("rejectReason")),
            }),
        })
    }

    /// Lightweight RRQ before the time-to-live runs out.
    async fn keep_alive(&mut self) -> Result<bool> {
        let Some(endpoint_id) = self.endpoint_id.clone() else {
            return Ok(false);
        };
        let mut rrq = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "discoveryComplete": false,
            "callSignalAddress": [h225::transport(self.call_signal)],
            "rasAddress": [h225::transport(self.local)],
            "terminalType": h225::endpoint_type("terminal"),
            "endpointVendor": h225::vendor(),
            "timeToLive": self.ttl,
            "keepAlive": true,
            "endpointIdentifier": endpoint_id,
            "willSupplyUUIEs": false,
            "maintainConnection": false,
            "supportsAssignedGK": false,
        });
        if let Some(g) = &self.gatekeeper_id {
            rrq["gatekeeperIdentifier"] = json!(g);
        }
        let ok = matches!(self.transact("registrationRequest", rrq).await?, Some((k, _)) if k == "registrationConfirm");
        self.refresh_at = ok.then(|| tokio::time::Instant::now() + refresh_interval(self.ttl));
        if !ok {
            self.endpoint_id = None;
        }
        Ok(ok)
    }

    async fn unregister(&mut self) -> Result<Value> {
        let Some(endpoint_id) = self.endpoint_id.clone() else {
            return Ok(json!({"request": "URQ", "result": "rejected", "reason": "not registered"}));
        };
        let mut urq = json!({
            "callSignalAddress": [h225::transport(self.call_signal)],
            "endpointIdentifier": endpoint_id,
        });
        if !self.aliases.is_empty() {
            urq["endpointAlias"] = Value::Array(self.aliases.clone());
        }
        if let Some(g) = &self.gatekeeper_id {
            urq["gatekeeperIdentifier"] = json!(g);
        }
        let answer = self.transact("unregistrationRequest", urq).await?;
        self.endpoint_id = None;
        self.refresh_at = None;
        Ok(match answer {
            None => json!({"request": "URQ", "result": "timeout"}),
            Some((k, _)) if k == "unregistrationConfirm" => {
                json!({"request": "URQ", "result": "confirmed"})
            }
            Some((_, b)) => {
                json!({"request": "URQ", "result": "rejected", "reason": h225::choice_name(b.get("rejectReason"))})
            }
        })
    }
}

fn refresh_interval(ttl: u64) -> Duration {
    Duration::from_secs((ttl * 3 / 4).max(1))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let remote = tokio::net::lookup_host(&ctx.remote_addr)
        .await
        .with_context(|| format!("cannot resolve {}", ctx.remote_addr))?
        .next()
        .with_context(|| format!("{} resolved to no address", ctx.remote_addr))?;
    let cfg = config(&ctx, remote)?;
    let local_ip = gatekeeper::route_source(remote).unwrap_or(if remote.is_ipv4() {
        IpAddr::from([127, 0, 0, 1])
    } else {
        IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])
    });
    let listener = TcpListener::bind(SocketAddr::new(local_ip, 0))
        .await
        .context("binding the call signalling address")?;
    let call_signal = listener.local_addr()?;
    let log = Log::new(Some(&ctx.status_tx));

    let mut ras = None;
    let mut gatekeeper_result = Value::Null;
    let mut registration = Value::Null;
    if cfg.mode == Mode::Gatekeeper {
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))
            .await
            .context("binding the RAS socket")?;
        let local = socket.local_addr()?;
        let mut r = Ras {
            socket,
            gatekeeper: remote,
            local,
            call_signal,
            seq: rand::random::<u16>() % 30_000 + 1,
            gatekeeper_id: None,
            endpoint_id: None,
            aliases: cfg.aliases.clone(),
            ttl: cfg.ttl,
            refresh_at: None,
        };
        let mut discovered = false;
        if cfg.discover {
            match r.discover().await? {
                None => bail!("the gatekeeper at {remote} did not answer GRQ ({RAS_TRIES} tries)"),
                Some(g) => {
                    discovered = g["result"] == "confirmed";
                    gatekeeper_result = g;
                }
            }
        }
        if !cfg.discover || discovered {
            registration = r.register(cfg.aliases.clone(), cfg.ttl, discovered).await?;
            if registration["result"] == "timeout" {
                bail!("the gatekeeper at {remote} did not answer RRQ ({RAS_TRIES} tries)");
            }
        }
        log.info(format!(
            "H.323 client {}: gatekeeper {remote}: {} / {}",
            ctx.client_id, gatekeeper_result, registration
        ));
        ras = Some(r);
    }
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let session_ctx = ctx.clone();
    let ready = json!({
        "mode": if cfg.mode == Mode::Gatekeeper { "gatekeeper" } else { "endpoint" },
        "remote": remote.to_string(),
        "gatekeeper": gatekeeper_result,
        "registration": registration,
        "local_call_signal_address": call_signal.to_string(),
    });
    let task = tokio::spawn(async move {
        let mut s = Session {
            ctx: session_ctx.clone(),
            remote,
            local_ip,
            codecs: cfg.codecs,
            ras,
            listener,
            call: None,
        };
        let reason = s.run(ready, external).await;
        if let Some(c) = s.call.as_mut() {
            let _ = c.leg.release(cause::NORMAL_CLEARING, None).await;
        }
        if let Some(r) = s.ras.as_mut() {
            if r.endpoint_id.is_some() {
                let _ = r.unregister().await;
            }
        }
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "H.323 client {} stopped: {reason}",
            session_ctx.client_id
        ));
        s.ask(&Event::new(
            &actions::DISCONNECTED_EVENT,
            json!({"reason": reason}),
        ))
        .await;
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
    Ok(remote)
}

struct ActiveCall {
    leg: CallLeg,
    rx: mpsc::Receiver<Result<Q931>>,
    reader: tokio::task::AbortHandle,
    destination: String,
    address: SocketAddr,
    progress: Vec<&'static str>,
    admission: Option<Value>,
    depth: u32,
    answer_by: tokio::time::Instant,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

struct Session {
    ctx: ConnectContext,
    remote: SocketAddr,
    local_ip: IpAddr,
    codecs: Vec<h245::Codec>,
    ras: Option<Ras>,
    listener: TcpListener,
    call: Option<ActiveCall>,
}

impl Session {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.ctx.status_tx))
    }

    /// Ask the model about one event; the actions it gave, parsed, and the refused ones.
    async fn ask(&mut self, event: &Event) -> Option<(Vec<ClientCommand>, Vec<(String, String)>)> {
        let instruction = self
            .ctx
            .state
            .get_instruction_for_client(self.ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = self
            .ctx
            .state
            .get_memory_for_client(self.ctx.client_id)
            .await
            .unwrap_or_default();
        let result = match call_llm_for_client(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(event),
            &H323ClientProtocol,
            &self.ctx.status_tx,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                self.log().error(format!(
                    "H.323 client {}: {} not answered decision={tag}: {e}",
                    self.ctx.client_id,
                    event.id()
                ));
                return None;
            }
        };
        if let Some(memory) = result.memory_updates {
            self.ctx
                .state
                .set_memory_for_client(self.ctx.client_id, memory)
                .await;
        }
        let mut commands = Vec::new();
        let mut refused = Vec::new();
        for a in result.actions {
            let kind = a["type"].as_str().unwrap_or_default().to_string();
            match actions::parse_command(&a) {
                Ok(c) => commands.push(c),
                Err(e) => {
                    self.log().error(format!(
                        "H.323 client {}: {kind} refused decision=fail_closed_bad_action: {e:#}",
                        self.ctx.client_id
                    ));
                    refused.push((kind, format!("{e:#}")));
                }
            }
        }
        Some((commands, refused))
    }

    /// Raise an event and carry out what the model answers, `depth` turns into a chain.
    async fn raise(&mut self, event: Event, depth: u32) {
        if depth >= MAX_FOLLOWUP_DEPTH {
            self.log().warn(format!(
                "H.323 client {}: not asking the model about {}: {depth} turns deep decision=followup_depth",
                self.ctx.client_id,
                event.id()
            ));
            return;
        }
        let Some((commands, refused)) = self.ask(&event).await else {
            return;
        };
        if commands.is_empty() && refused.is_empty() {
            self.log().debug(format!(
                "H.323 client {}: {} decision=model_silent",
                self.ctx.client_id,
                event.id()
            ));
        }
        let mut errors = refused;
        for c in commands {
            let name = c.name();
            if let Err(e) = Box::pin(self.apply(c, depth + 1)).await {
                self.log().error(format!(
                    "H.323 client {}: {name} failed decision=fail_closed_bad_action: {e:#}",
                    self.ctx.client_id
                ));
                errors.push((name.to_string(), format!("{e:#}")));
            }
        }
        for (action, message) in errors {
            if depth + 1 >= MAX_FOLLOWUP_DEPTH {
                break;
            }
            let ev = Event::new(
                &actions::ERROR_EVENT,
                json!({"action": action, "message": message}),
            );
            Box::pin(self.raise(ev, depth + 1)).await;
        }
    }

    async fn apply(&mut self, c: ClientCommand, depth: u32) -> Result<String> {
        match c {
            ClientCommand::PlaceCall {
                destination,
                codecs,
                display,
            } => self.place_call(destination, codecs, display, depth).await,
            ClientCommand::Hangup { cause: c, reason } => {
                let Some(mut call) = self.call.take() else {
                    bail!("there is no call to hang up");
                };
                call.leg.release(c, reason.as_deref()).await?;
                let disengage = self.disengage(&call).await;
                self.log().info(format!(
                    "H.323 client {}: hung up the call to {} (cause {c})",
                    self.ctx.client_id, call.destination
                ));
                let event = released_event(&call, "local", Some(c), reason, disengage);
                Box::pin(self.raise(event, depth)).await;
                Ok("Release Complete sent".into())
            }
            ClientCommand::Register { aliases, ttl } => {
                let Some(ras) = self.ras.as_mut() else {
                    bail!("this client was not started against a gatekeeper (mode endpoint)");
                };
                let aliases = aliases.unwrap_or_else(|| ras.aliases.clone());
                let ttl = ttl.unwrap_or(ras.ttl);
                let discovered = ras.gatekeeper_id.is_some();
                let result = ras.register(aliases, ttl, discovered).await?;
                let summary = result.to_string();
                Box::pin(self.raise(Event::new(&actions::REGISTRATION_EVENT, result), depth)).await;
                Ok(summary)
            }
            ClientCommand::Unregister => {
                let Some(ras) = self.ras.as_mut() else {
                    bail!("this client was not started against a gatekeeper (mode endpoint)");
                };
                let result = ras.unregister().await?;
                let summary = result.to_string();
                Box::pin(self.raise(Event::new(&actions::REGISTRATION_EVENT, result), depth)).await;
                Ok(summary)
            }
        }
    }

    async fn disengage(&mut self, call: &ActiveCall) -> Option<String> {
        let ras = self.ras.as_mut()?;
        let endpoint_id = ras.endpoint_id.clone()?;
        call.admission.as_ref()?;
        let mut drq = json!({
            "endpointIdentifier": endpoint_id,
            "conferenceID": call.leg.conference_id,
            "callReferenceValue": call.leg.crv,
            "disengageReason": {"normalDrop": null},
            "callIdentifier": {"guid": call.leg.call_id},
            "answeredCall": false,
        });
        if let Some(g) = &ras.gatekeeper_id {
            drq["gatekeeperIdentifier"] = json!(g);
        }
        match ras.transact("disengageRequest", drq).await {
            Ok(Some((k, b))) if k == "disengageConfirm" => {
                let _ = b;
                Some("DCF".into())
            }
            Ok(Some((_, b))) => Some(format!("DRJ {}", h225::choice_name(b.get("rejectReason")))),
            Ok(None) => Some("no answer".into()),
            Err(e) => Some(format!("not sent: {e:#}")),
        }
    }

    async fn place_call(
        &mut self,
        destination: String,
        codecs: Vec<h245::Codec>,
        display: Option<String>,
        depth: u32,
    ) -> Result<String> {
        if self.call.is_some() {
            bail!("a call is already up; hang it up first");
        }
        let registered = self.ras.as_ref().and_then(|r| r.endpoint_id.clone());
        if self.ras.is_some() && registered.is_none() && destination.parse::<SocketAddr>().is_err()
        {
            bail!(
                "not registered with the gatekeeper, so {destination} cannot be admitted: \
                 register first (h323_register) or call an ip:port directly"
            );
        }
        let crv: u16 = rand::random::<u16>() % 32_000 + 1;
        let call_id = h225::new_guid();
        let conference_id = h225::new_guid();
        let literal = destination.parse::<SocketAddr>().ok();
        let dest_alias = match literal {
            Some(_) => None,
            None => Some(h225::alias(&destination)?),
        };
        // Admission, when registered.
        let mut admission = None;
        let mut address = literal.unwrap_or(self.remote);
        if let (Some(ras), Some(endpoint_id)) = (self.ras.as_mut(), registered) {
            let mut arq = json!({
                "callType": {"pointToPoint": null},
                "callModel": {"direct": null},
                "endpointIdentifier": endpoint_id,
                "srcInfo": if ras.aliases.is_empty() { vec![h225::alias(actions::DEFAULT_ALIAS)?] } else { ras.aliases.clone() },
                "srcCallSignalAddress": h225::transport(ras.call_signal),
                "bandWidth": CALL_BANDWIDTH,
                "callReferenceValue": crv,
                "conferenceID": conference_id,
                "activeMC": false,
                "answerCall": false,
                "canMapAlias": false,
                "callIdentifier": {"guid": call_id},
                "willSupplyUUIEs": false,
                "canMapSrcAlias": false,
            });
            if let Some(a) = &dest_alias {
                arq["destinationInfo"] = json!([a]);
            }
            if let Some(l) = literal {
                arq["destCallSignalAddress"] = h225::transport(l);
            }
            if let Some(g) = &ras.gatekeeper_id {
                arq["gatekeeperIdentifier"] = json!(g);
            }
            match ras.transact("admissionRequest", arq).await? {
                None => {
                    let ev = Event::new(
                        &actions::FAILED_EVENT,
                        json!({
                        "destination": destination, "stage": "admission",
                        "reason": format!("the gatekeeper did not answer ARQ ({RAS_TRIES} tries)")}),
                    );
                    Box::pin(self.raise(ev, depth)).await;
                    return Ok("ARQ unanswered".into());
                }
                Some((k, b)) if k == "admissionConfirm" => {
                    let Some(to) = b.get("destCallSignalAddress").and_then(h225::socket_addr)
                    else {
                        let ev = Event::new(
                            &actions::FAILED_EVENT,
                            json!({
                            "destination": destination, "stage": "admission",
                            "reason": "the ACF named no IP call signalling address"}),
                        );
                        Box::pin(self.raise(ev, depth)).await;
                        return Ok("ACF without an address".into());
                    };
                    address = to;
                    admission = Some(json!({
                        "result": "confirmed",
                        "destination_address": to.to_string(),
                        "bandwidth": b.get("bandWidth"),
                        "call_model": h225::choice_name(b.get("callModel")),
                        "destination_aliases": h225::aliases_text(b.get("destinationInfo")),
                    }));
                }
                Some((_, b)) => {
                    let reason = h225::choice_name(b.get("rejectReason"));
                    self.log().info(format!(
                        "H.323 client {}: ARQ for {destination}: ARJ {reason}",
                        self.ctx.client_id
                    ));
                    let ev = Event::new(
                        &actions::FAILED_EVENT,
                        json!({
                        "destination": destination, "stage": "admission",
                        "reason": format!("ARJ {reason}")}),
                    );
                    Box::pin(self.raise(ev, depth)).await;
                    return Ok(format!("ARJ {reason}"));
                }
            }
        }
        // Call signalling.
        let stream =
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(address))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let ev = Event::new(
                        &actions::FAILED_EVENT,
                        json!({
                    "destination": destination, "stage": "connect",
                    "reason": format!("cannot reach {address}: {e}")}),
                    );
                    Box::pin(self.raise(ev, depth)).await;
                    return Ok("unreachable".into());
                }
                Err(_) => {
                    let ev = Event::new(
                        &actions::FAILED_EVENT,
                        json!({
                    "destination": destination, "stage": "connect",
                    "reason": format!("connecting to {address} timed out")}),
                    );
                    Box::pin(self.raise(ev, depth)).await;
                    return Ok("connect timed out".into());
                }
            };
        let _ = stream.set_nodelay(true);
        let local_ip = stream.local_addr().map(|a| a.ip()).unwrap_or(self.local_ip);
        let (r, w) = stream.into_split();
        let media = MediaSockets::bind(local_ip).await?;
        let mut leg = CallLeg::new(
            w,
            crv,
            Role::Caller,
            call_id,
            conference_id.clone(),
            false,
            media,
            if codecs.is_empty() {
                self.codecs.clone()
            } else {
                codecs.clone()
            },
        );
        let offer = h245::offer_fast_start(&leg.codecs, leg.media.rtp, leg.media.rtcp)?;
        let (src_aliases, endpoint_id, call_signal) = match &self.ras {
            Some(r) => (r.aliases.clone(), r.endpoint_id.clone(), r.call_signal),
            None => (Vec::new(), None, self.listener.local_addr()?),
        };
        let mut setup = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "sourceInfo": h225::endpoint_type("terminal"),
            "activeMC": false,
            "conferenceID": conference_id,
            "conferenceGoal": {"create": null},
            "callType": {"pointToPoint": null},
            "sourceCallSignalAddress": h225::transport(call_signal),
            "callIdentifier": {"guid": leg.call_id},
            "fastStart": offer.iter().map(|o| json!(hex::encode(o))).collect::<Vec<_>>(),
            "mediaWaitForConnect": false,
            "canOverlapSend": false,
            "multipleCalls": false,
            "maintainConnection": false,
            "destCallSignalAddress": h225::transport(address),
        });
        if !src_aliases.is_empty() {
            setup["sourceAddress"] = Value::Array(src_aliases.clone());
        }
        if let Some(a) = &dest_alias {
            setup["destinationAddress"] = json!([a]);
        }
        if let Some(e) = endpoint_id {
            setup["endpointIdentifier"] = json!(e);
        }
        let mut ies = vec![(ie::BEARER_CAPABILITY, q931::bearer_capability())];
        if let Some(d) = &display {
            ies.push((ie::DISPLAY, d.as_bytes().to_vec()));
        }
        if let Some(digits) = src_aliases
            .iter()
            .find_map(|a| a.get("dialledDigits").and_then(|d| d.as_str()))
        {
            ies.push((ie::CALLING_PARTY_NUMBER, q931::number_ie(digits)));
        }
        if let Some(digits) = dest_alias
            .as_ref()
            .and_then(|a| a.get("dialledDigits"))
            .and_then(|d| d.as_str())
        {
            ies.push((ie::CALLED_PARTY_NUMBER, q931::number_ie(digits)));
        }
        let reader = crate::server::accept_bounded::IdleTimeoutReader::new(r, CALL_IDLE_TIMEOUT);
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        let reader_task = tokio::spawn(call::read_loop(reader, tx));
        let reader_abort = reader_task.abort_handle();
        self.ctx
            .state
            .register_client_task(self.ctx.client_id, reader_task)
            .await;
        leg.send(msg::SETUP, "setup", setup, ies).await?;
        self.log().info(format!(
            "H.323 client {}: Setup to {destination} at {address} (crv {crv})",
            self.ctx.client_id
        ));
        self.call = Some(ActiveCall {
            leg,
            rx,
            reader: reader_abort,
            destination: destination.clone(),
            address,
            progress: Vec::new(),
            admission,
            depth,
            answer_by: tokio::time::Instant::now() + ANSWER_TIMEOUT,
        });
        Ok(format!("Setup sent to {address}"))
    }

    /// One message on the active call.
    async fn on_call_message(&mut self, m: Result<Option<Result<Q931>>, ()>) {
        let Some(mut call) = self.call.take() else {
            return;
        };
        let depth = call.depth;
        let m = match m {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                self.log().warn(format!(
                    "H.323 client {}: call signalling decision=protocol_error: {e:#}",
                    self.ctx.client_id
                ));
                let _ = call.leg.release(cause::PROTOCOL_ERROR, None).await;
                let disengage = self.disengage(&call).await;
                let ev = released_event(
                    &call,
                    "connection",
                    None,
                    Some(format!("protocol error: {e:#}")),
                    disengage,
                );
                Box::pin(self.raise(ev, depth + 1)).await;
                return;
            }
            Ok(None) | Err(()) => {
                let disengage = self.disengage(&call).await;
                let ev = released_event(
                    &call,
                    "connection",
                    None,
                    Some("the callee closed the connection".into()),
                    disengage,
                );
                Box::pin(self.raise(ev, depth + 1)).await;
                return;
            }
        };
        let name = q931::message_name(m.message_type);
        match call.leg.on_incoming(&m).await {
            Ok(Incoming::Proceeding) | Ok(Incoming::Alerting) | Ok(Incoming::Other(_)) => {
                if call.progress.len() < 32 {
                    call.progress.push(name);
                }
                if call.leg.h245.ended && call.leg.state != CallState::Released {
                    let _ = call.leg.release(cause::NORMAL_CLEARING, None).await;
                    let disengage = self.disengage(&call).await;
                    let ev = released_event(
                        &call,
                        "remote",
                        None,
                        Some("endSessionCommand".into()),
                        disengage,
                    );
                    Box::pin(self.raise(ev, depth + 1)).await;
                    return;
                }
                self.call = Some(call);
            }
            Ok(Incoming::Connected) => {
                // Start H.245 if the callee tunnels it and has not started it.
                if call.leg.tunnelling() && !call.leg.h245.started() {
                    if let Ok(opening) = call.leg.h245.start() {
                        for m in opening {
                            call.leg.queue_h245(m);
                        }
                        let _ = call.leg.flush_h245().await;
                    }
                }
                self.log().info(format!(
                    "H.323 client {}: call to {} connected: {}",
                    self.ctx.client_id,
                    call.destination,
                    call.leg.media_json()
                ));
                let ev = Event::new(
                    &actions::CONNECTED_EVENT,
                    json!({
                        "destination": call.destination,
                        "address": call.address.to_string(),
                        "progress": call.progress,
                        "call": call.leg.summary(),
                        "admission": call.admission,
                    }),
                );
                self.call = Some(call);
                Box::pin(self.raise(ev, depth + 1)).await;
            }
            Ok(Incoming::Released { cause: c, reason }) => {
                let disengage = self.disengage(&call).await;
                self.log().info(format!(
                    "H.323 client {}: the callee released the call to {} (cause {c:?}, {reason:?})",
                    self.ctx.client_id, call.destination
                ));
                let ev = released_event(&call, "remote", c, reason, disengage);
                Box::pin(self.raise(ev, depth + 1)).await;
            }
            Ok(Incoming::Forwarded { address, aliases }) => {
                let _ = call
                    .leg
                    .release(cause::NORMAL_CLEARING, Some("facilityCallDeflection"))
                    .await;
                let _ = self.disengage(&call).await;
                let ev = Event::new(
                    &actions::FORWARDED_EVENT,
                    json!({
                        "destination": call.destination,
                        "forward_address": address.map(|a| a.to_string()),
                        "forward_aliases": aliases,
                    }),
                );
                Box::pin(self.raise(ev, depth + 1)).await;
            }
            Ok(Incoming::WrongCallReference {
                crv,
                from_destination,
            }) => {
                self.log().warn(format!(
                    "H.323 client {}: {name} for call reference {crv} (flag {from_destination}) on call {} decision=protocol_error; releasing, cause 81",
                    self.ctx.client_id, call.leg.crv
                ));
                let _ = call.leg.release(cause::INVALID_CALL_REFERENCE, None).await;
                let disengage = self.disengage(&call).await;
                let ev = released_event(
                    &call,
                    "local",
                    Some(cause::INVALID_CALL_REFERENCE),
                    Some("the callee answered with another call reference".into()),
                    disengage,
                );
                Box::pin(self.raise(ev, depth + 1)).await;
            }
            Ok(Incoming::UnexpectedSetup) => {
                self.log().warn(format!(
                    "H.323 client {}: the callee sent a Setup decision=protocol_error",
                    self.ctx.client_id
                ));
                let _ = call.leg.release(cause::PROTOCOL_ERROR, None).await;
                let disengage = self.disengage(&call).await;
                let ev = released_event(
                    &call,
                    "local",
                    Some(cause::PROTOCOL_ERROR),
                    Some("the callee sent a Setup".into()),
                    disengage,
                );
                Box::pin(self.raise(ev, depth + 1)).await;
            }
            Err(e) => {
                self.log().warn(format!(
                    "H.323 client {}: {name} not decodable decision=protocol_error: {e:#}",
                    self.ctx.client_id
                ));
                self.call = Some(call);
            }
        }
    }

    async fn run(&mut self, ready: Value, mut external: mpsc::Receiver<External>) -> String {
        Box::pin(self.raise(Event::new(&actions::READY_EVENT, ready), 0)).await;
        let mut ras_buf = vec![0u8; gatekeeper::MAX_RAS_DATAGRAM];
        loop {
            let refresh_at = self.ras.as_ref().and_then(|r| r.refresh_at);
            let answer_by = self
                .call
                .as_ref()
                .filter(|c| c.leg.state != CallState::Connected)
                .map(|c| c.answer_by);
            tokio::select! {
                c = external.recv() => match c {
                    None => return "the client was stopped".into(),
                    Some(c) => self.inject(c).await,
                },
                m = async {
                    match self.call.as_mut() {
                        Some(c) => Ok(c.rx.recv().await),
                        None => std::future::pending().await,
                    }
                }, if self.call.is_some() => self.on_call_message(m).await,
                got = async {
                    match self.ras.as_ref() {
                        Some(r) => r.socket.recv_from(&mut ras_buf).await.map(|(n, from)| (ras_buf[..n].to_vec(), from)),
                        None => std::future::pending().await,
                    }
                }, if self.ras.is_some() => {
                    if let Ok((datagram, from)) = got {
                        if let Ok((kind, body)) = h225::decode_ras(&datagram) {
                            let unregistered = match self.ras.as_mut() {
                                Some(r) => r.answer_gatekeeper(&kind, &body, from).await.unwrap_or(false),
                                None => false,
                            };
                            if unregistered {
                                let ev = Event::new(&actions::REGISTRATION_EVENT, json!({
                                    "request": "gatekeeper_urq", "result": "confirmed",
                                    "reason": h225::choice_name(body.get("reason"))}));
                                Box::pin(self.raise(ev, 0)).await;
                            }
                        }
                    }
                }
                incoming = self.listener.accept() => {
                    if let Ok((mut stream, from)) = incoming {
                        self.log().info(format!(
                            "H.323 client {}: refusing a call from {from} decision=protocol_reject (this client places calls)",
                            self.ctx.client_id
                        ));
                        refuse_incoming(&mut stream).await;
                    }
                }
                _ = async { tokio::time::sleep_until(refresh_at.expect("guarded")).await }, if refresh_at.is_some() => {
                    let ok = match self.ras.as_mut() {
                        Some(r) => r.keep_alive().await.unwrap_or(false),
                        None => true,
                    };
                    if !ok {
                        self.log().warn(format!("H.323 client {}: keep-alive RRQ not confirmed; registration lost", self.ctx.client_id));
                        let ev = Event::new(&actions::REGISTRATION_EVENT, json!({
                            "request": "RRQ", "result": "rejected", "reason": "keep-alive not confirmed"}));
                        Box::pin(self.raise(ev, 0)).await;
                    }
                }
                _ = async { tokio::time::sleep_until(answer_by.expect("guarded")).await }, if answer_by.is_some() => {
                    if let Some(mut call) = self.call.take() {
                        let _ = call.leg.release(cause::NO_ANSWER, None).await;
                        let disengage = self.disengage(&call).await;
                        let depth = call.depth;
                        let ev = released_event(&call, "local", Some(cause::NO_ANSWER), Some(format!("not answered within {}s", ANSWER_TIMEOUT.as_secs())), disengage);
                        Box::pin(self.raise(ev, depth + 1)).await;
                    }
                }
            }
        }
    }

    async fn inject(&mut self, command: External) {
        self.ctx
            .state
            .record_access_log(
                AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                "h323",
                None,
                "injected_action",
                command.action.clone(),
                vec![],
            )
            .await;
        let outcome = match actions::parse_command(&command.action) {
            Err(e) => ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
            Ok(c) => match Box::pin(self.apply(c, 0)).await {
                Ok(detail) => ClientSendOutcome::Executed { detail },
                Err(e) => ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                },
            },
        };
        crate::client::command_support::reply(command, Ok(outcome));
    }
}

fn released_event(
    call: &ActiveCall,
    by: &str,
    c: Option<u8>,
    reason: Option<String>,
    disengage: Option<String>,
) -> Event {
    Event::new(
        &actions::RELEASED_EVENT,
        json!({
            "destination": call.destination,
            "released_by": by,
            "cause": c,
            "reason": reason,
            "reached": call.progress_state(),
            "progress": call.progress,
            "call": call.leg.summary(),
            "disengage": disengage,
        }),
    )
}

impl ActiveCall {
    fn progress_state(&self) -> &'static str {
        if self.leg.ever_connected {
            "connected"
        } else if self.progress.contains(&"Alerting") {
            "alerting"
        } else if self.progress.contains(&"CallProceeding") {
            "proceeding"
        } else {
            "offered"
        }
    }
}

/// Release Complete for a call this client will not take.
async fn refuse_incoming(stream: &mut tokio::net::TcpStream) {
    let read = tokio::time::timeout(Duration::from_secs(5), q931::read_tpkt(stream)).await;
    let crv = match read {
        Ok(Ok(Some(p))) => Q931::parse(&p).map(|m| m.crv).unwrap_or(0),
        _ => 0,
    };
    let body =
        json!({"protocolIdentifier": h225::PROTOCOL_ID, "reason": {"destinationRejection": null}});
    if let Ok(uu) = h225::encode_user_information("releaseComplete", body, false, &[]) {
        let m = Q931::new(msg::RELEASE_COMPLETE, crv, true)
            .with_ie(ie::CAUSE, q931::cause_ie(cause::CALL_REJECTED))
            .with_user_user(&uu);
        if let Ok(bytes) = m.encode().and_then(|b| q931::tpkt(&b)) {
            let _ = stream.write_all(&bytes).await;
        }
    }
    let _ = stream.shutdown().await;
}
