//! GTP client: the near end of one mobile-core path — an SGSN towards a GGSN (GTPv1 Gn), an
//! SGW towards a PGW (GTPv2 S5/S8) or an MME towards an SGW (GTPv2 S11) — with a GTP-U
//! endpoint for the sessions it creates. See `AGENTS.md` beside this file.
pub mod actions;
pub mod msg;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::gtp::codec::{self, GtpV1Message, GtpVersion};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::GtpClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use msg::{Request, Role};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// TS 29.274 §7.6 / TS 29.060 §7.6: wait T3-RESPONSE for an answer, resend at most
/// N3-REQUESTS times, then give up.
pub const T3_RESPONSE: Duration = Duration::from_secs(3);
pub const N3_REQUESTS: u32 = 3;
const T3_RANGE_MS: std::ops::RangeInclusive<u64> = 100..=60_000;
const MAX_N3: u64 = 10;
/// Requests awaiting an answer at once; the next is refused.
pub const MAX_PENDING: usize = 64;
/// Sessions open at once; the next Create is refused.
pub const MAX_SESSIONS: usize = 64;
/// Requests from the peer awaiting the model's gtp_respond, and unknown TEIDs remembered for
/// an Error Indication; past this the oldest is forgotten.
const MAX_REMEMBERED: usize = 64;
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
const TURNS: usize = 64;
pub const DEFAULT_INTERFACE: &str = "s5";
/// This node's restart counter. It never restarts within a process.
const RECOVERY: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Plane {
    Control,
    User,
}

struct Pending {
    request: Request,
    plane: Plane,
    bytes: Vec<u8>,
    dest: SocketAddr,
    sent: u32,
    deadline: Instant,
    depth: u32,
    session: Option<u32>,
    command: Option<ClientCommand>,
}

struct Session {
    ebi: u8,
    qos: msg::BearerQos,
    local_control_teid: u32,
    local_data_teid: u32,
    peer_control_teid: Option<u32>,
    peer_data_teid: Option<u32>,
    peer_data_address: Option<IpAddr>,
    ue_address: Option<IpAddr>,
}

struct Inbound {
    version: GtpVersion,
    message_type: u8,
    session: Option<u32>,
    teid: u32,
}

struct Node {
    role: Role,
    control: UdpSocket,
    user: UdpSocket,
    peer: SocketAddr,
    peer_user_port: u16,
    control_ip: IpAddr,
    user_ip: IpAddr,
    t3: Duration,
    n3: u32,
    seq: u32,
    user_seq: u16,
    next_session: u32,
    sessions: HashMap<u32, Session>,
    pending: HashMap<(Plane, u32), Pending>,
    inbound: HashMap<u32, Inbound>,
    unknown_teids: HashMap<u32, SocketAddr>,
    events: mpsc::Sender<(Event, u32)>,
    client: crate::state::ClientId,
    status_tx: mpsc::UnboundedSender<String>,
}

async fn resolve(raw: &str) -> Result<SocketAddr> {
    let raw = raw.trim();
    if let Ok(a) = raw.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = raw.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, codec::GTPC_PORT));
    }
    let target = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:{}", codec::GTPC_PORT)
    };
    let found = tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("cannot resolve {raw}"))?
        .next();
    found.with_context(|| format!("{raw} resolved to no address"))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let peer = resolve(&ctx.remote_addr).await?;
    let role = match params
        .map(|p| p.get_optional_string("interface"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| DEFAULT_INTERFACE.into())
        .to_ascii_lowercase()
        .as_str()
    {
        "s5" | "s8" | "s5/s8" => Role::S5,
        "s11" => Role::S11,
        "gn" | "gp" | "gn/gp" => Role::Gn,
        other => bail!("interface {other:?} is s5, s11 or gn"),
    };
    let u64_param = |key: &str| -> Result<Option<u64>> {
        Ok(params
            .map(|p| p.get_optional_u64(key))
            .transpose()?
            .flatten())
    };
    let local_port = u64_param("local_port")?.unwrap_or(0);
    ensure!(local_port <= 65535, "local_port is a port number");
    let user_port = u64_param("user_plane_port")?;
    ensure!(
        user_port.unwrap_or(0) <= 65535,
        "user_plane_port is a port number"
    );
    let peer_user_port = u64_param("peer_user_plane_port")?.unwrap_or(codec::GTPU_PORT as u64);
    ensure!(
        (1..=65535).contains(&peer_user_port),
        "peer_user_plane_port is a port number"
    );
    let t3_ms = u64_param("t3_response_ms")?.unwrap_or(T3_RESPONSE.as_millis() as u64);
    ensure!(
        T3_RANGE_MS.contains(&t3_ms),
        "t3_response_ms is {}..={} milliseconds",
        T3_RANGE_MS.start(),
        T3_RANGE_MS.end()
    );
    let n3 = u64_param("n3_requests")?.unwrap_or(N3_REQUESTS as u64);
    ensure!(n3 <= MAX_N3, "n3_requests is 0..={MAX_N3}");

    let wildcard: IpAddr = if peer.is_ipv4() {
        [0, 0, 0, 0].into()
    } else {
        [0u16; 8].into()
    };
    let control = UdpSocket::bind(SocketAddr::new(wildcard, local_port as u16)).await?;
    control
        .connect(peer)
        .await
        .with_context(|| format!("no route to {peer}"))?;
    let local = control.local_addr()?;
    // The address this node advertises in its F-TEIDs and GSN Address IEs is the one the
    // kernel chose to reach the peer from, and the GTP-U endpoint is bound to the same one.
    let user = match UdpSocket::bind(SocketAddr::new(
        local.ip(),
        user_port.unwrap_or(codec::GTPU_PORT as u64) as u16,
    ))
    .await
    {
        Ok(s) => s,
        Err(e) if user_port.is_none() && e.kind() == std::io::ErrorKind::AddrInUse => {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "GTP client {}: {}:{} is taken, so the GTP-U endpoint is on an ephemeral port; a peer that sends G-PDUs to 2152 will not reach it",
                ctx.client_id,
                local.ip(),
                codec::GTPU_PORT
            ));
            UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?
        }
        Err(e) => return Err(e).context("binding the GTP-U endpoint"),
    };
    let user_local = user.local_addr()?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "GTP client {} ({} , GTPv{}) towards {peer} from {local}, GTP-U on {user_local}",
        ctx.client_id,
        role.as_str(),
        role.version().as_number()
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::READY_EVENT,
            json!({"peer": peer.to_string(), "interface": role.as_str(),
                   "version": role.version().as_number(),
                   "local_control": local.to_string(), "local_user_plane": user_local.to_string()}),
        ),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let mut node = Node {
        role,
        control,
        user,
        peer,
        peer_user_port: peer_user_port as u16,
        control_ip: local.ip(),
        user_ip: user_local.ip(),
        t3: Duration::from_millis(t3_ms),
        n3: n3 as u32,
        seq: rand::random::<u16>() as u32,
        user_seq: rand::random::<u16>(),
        next_session: 1,
        sessions: HashMap::new(),
        pending: HashMap::new(),
        inbound: HashMap::new(),
        unknown_teids: HashMap::new(),
        events: event_tx,
        client: ctx.client_id,
        status_tx: ctx.status_tx.clone(),
    };
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = node.run(&session_ctx, external, internal).await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("GTP client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

fn rejected(command: Option<ClientCommand>, error: String) {
    reply(command, ClientSendOutcome::Rejected { error });
}

fn request_label(r: Request) -> &'static str {
    match r {
        Request::Echo => "echo_request",
        Request::Create => "create_session",
        Request::Modify => "modify_bearer",
        Request::Delete => "delete_session",
    }
}

impl Node {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.status_tx))
    }

    fn version(&self) -> GtpVersion {
        self.role.version()
    }

    fn emit(&self, t: &'static EventType, data: Value, depth: u32) {
        if self.events.try_send((Event::new(t, data), depth)).is_err() {
            tracing::warn!(
                "GTP client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full",
                self.client
            );
        }
    }

    fn local(&self, s: &Session) -> msg::Local {
        msg::Local {
            control_ip: self.control_ip,
            user_ip: self.user_ip,
            control_teid: s.local_control_teid,
            data_teid: s.local_data_teid,
        }
    }

    fn fresh_teid(&self) -> u32 {
        loop {
            let t = rand::random::<u32>();
            if t != 0
                && !self
                    .sessions
                    .values()
                    .any(|s| s.local_control_teid == t || s.local_data_teid == t)
            {
                return t;
            }
        }
    }

    /// The next sequence number for this plane, skipping any still waiting for an answer.
    fn next_seq(&mut self, plane: Plane) -> u32 {
        loop {
            let s = match plane {
                Plane::Control => {
                    self.seq = (self.seq + 1) & self.version().max_sequence();
                    self.seq
                }
                Plane::User => {
                    self.user_seq = self.user_seq.wrapping_add(1);
                    self.user_seq as u32
                }
            };
            if !self.pending.contains_key(&(plane, s)) {
                return s;
            }
        }
    }

    fn user_dest(&self, s: Option<&Session>) -> SocketAddr {
        SocketAddr::new(
            s.and_then(|s| s.peer_data_address)
                .unwrap_or(self.peer.ip()),
            self.peer_user_port,
        )
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> Result<()> {
        // One octet past the largest datagram, so a datagram that filled it is known to be cut.
        let mut cbuf = vec![0u8; msg::MAX_DATAGRAM + 1];
        let mut ubuf = vec![0u8; msg::MAX_DATAGRAM + 1];
        loop {
            let deadline = self.pending.values().map(|p| p.deadline).min();
            let (action, depth, command) = tokio::select! {
                r = self.control.recv(&mut cbuf) => {
                    match r {
                        Ok(n) if n > msg::MAX_DATAGRAM => self.log().warn(format!(
                            "GTP client {}: control datagram past {} octets refused decision=refused_oversized", self.client, msg::MAX_DATAGRAM)),
                        Ok(n) => {
                            let d = cbuf[..n].to_vec();
                            self.incoming_control(&d).await;
                        }
                        // ICMP port unreachable surfaces here on a connected socket; the
                        // retransmission timer reports the request.
                        Err(e) => tracing::debug!("GTP client {}: {e}", self.client),
                    }
                    continue;
                }
                r = self.user.recv_from(&mut ubuf) => {
                    match r {
                        Ok((n, _)) if n > msg::MAX_DATAGRAM => self.log().warn(format!(
                            "GTP client {}: user-plane datagram past {} octets refused decision=refused_oversized", self.client, msg::MAX_DATAGRAM)),
                        Ok((n, from)) => {
                            let d = ubuf[..n].to_vec();
                            self.incoming_user(&d, from).await;
                        }
                        Err(e) => tracing::debug!("GTP client {} user plane: {e}", self.client),
                    }
                    continue;
                }
                _ = async {
                    match deadline {
                        Some(d) => tokio::time::sleep_until(d).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.retransmit().await;
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "GTP", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return Ok(()),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return Ok(()),
                },
            };
            match GtpClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(command, ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    rejected(command, e.to_string());
                    continue;
                }
            }
            if let Err(e) = self.perform(&action, depth, command).await {
                self.log()
                    .warn(format!("GTP client {}: {e:#}", self.client));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_request(
        &mut self,
        request: Request,
        plane: Plane,
        seq: u32,
        bytes: Vec<u8>,
        dest: SocketAddr,
        depth: u32,
        session: Option<u32>,
        command: Option<ClientCommand>,
    ) -> Result<()> {
        match plane {
            Plane::Control => self.control.send(&bytes).await,
            Plane::User => self.user.send_to(&bytes, dest).await,
        }
        .with_context(|| format!("sending to {dest}"))?;
        self.pending.insert(
            (plane, seq),
            Pending {
                request,
                plane,
                bytes,
                dest,
                sent: 1,
                deadline: Instant::now() + self.t3,
                depth,
                session,
                command,
            },
        );
        Ok(())
    }

    async fn perform(
        &mut self,
        action: &Value,
        depth: u32,
        command: Option<ClientCommand>,
    ) -> Result<()> {
        let kind = action["type"].as_str().unwrap_or_default();
        let wants_answer = matches!(
            kind,
            actions::ECHO | actions::CREATE | actions::MODIFY | actions::DELETE
        );
        if wants_answer && self.pending.len() >= MAX_PENDING {
            rejected(
                command,
                format!("{MAX_PENDING} requests are already waiting for the peer"),
            );
            return Ok(());
        }
        match kind {
            actions::ECHO => {
                let plane = if action["plane"] == "user" {
                    Plane::User
                } else {
                    Plane::Control
                };
                let seq = self.next_seq(plane);
                let (version, dest) = match plane {
                    Plane::Control => (self.version(), self.peer),
                    // GTP-U is GTPv1 whatever the control plane speaks.
                    Plane::User => (GtpVersion::V1, self.user_dest(None)),
                };
                let bytes = msg::echo_request(version, seq, RECOVERY);
                self.send_request(Request::Echo, plane, seq, bytes, dest, depth, None, command)
                    .await
            }
            actions::CREATE => {
                if self.sessions.len() >= MAX_SESSIONS {
                    rejected(command, format!("{MAX_SESSIONS} sessions are already open"));
                    return Ok(());
                }
                let p = match msg::CreateParams::from_action(self.role, action) {
                    Ok(p) => p,
                    Err(e) => {
                        rejected(command, format!("{e:#}"));
                        return Ok(());
                    }
                };
                let id = self.next_session;
                self.next_session = self.next_session.wrapping_add(1).max(1);
                let s = Session {
                    ebi: p.ebi,
                    qos: p.qos.clone(),
                    local_control_teid: self.fresh_teid(),
                    local_data_teid: 0,
                    peer_control_teid: None,
                    peer_data_teid: None,
                    peer_data_address: None,
                    ue_address: None,
                };
                self.sessions.insert(id, s);
                let data_teid = self.fresh_teid();
                let s = self.sessions.get_mut(&id).expect("just inserted");
                s.local_data_teid = data_teid;
                let local = msg::Local {
                    control_ip: self.control_ip,
                    user_ip: self.user_ip,
                    control_teid: s.local_control_teid,
                    data_teid,
                };
                let seq = self.next_seq(Plane::Control);
                let bytes = match msg::create_request(self.role, &p, &local, seq, RECOVERY) {
                    Ok(b) => b,
                    Err(e) => {
                        self.sessions.remove(&id);
                        rejected(command, format!("{e:#}"));
                        return Ok(());
                    }
                };
                let peer = self.peer;
                let r = self
                    .send_request(
                        Request::Create,
                        Plane::Control,
                        seq,
                        bytes,
                        peer,
                        depth,
                        Some(id),
                        command,
                    )
                    .await;
                if r.is_err() {
                    self.sessions.remove(&id);
                }
                r
            }
            actions::MODIFY | actions::DELETE => {
                let id = actions::session(action)?;
                let Some(s) = self.sessions.get(&id) else {
                    rejected(command, format!("no session {id}"));
                    return Ok(());
                };
                let Some(peer_teid) = s.peer_control_teid else {
                    rejected(
                        command,
                        format!("session {id} has not been created by the peer yet"),
                    );
                    return Ok(());
                };
                let (ebi, qos, local) = (s.ebi, s.qos.clone(), self.local(s));
                let seq = self.next_seq(Plane::Control);
                let (request, bytes) = if kind == actions::MODIFY {
                    (
                        Request::Modify,
                        msg::modify_request(self.role, peer_teid, ebi, &qos, &local, seq),
                    )
                } else {
                    (
                        Request::Delete,
                        msg::delete_request(self.role, peer_teid, ebi, seq),
                    )
                };
                let peer = self.peer;
                self.send_request(
                    request,
                    Plane::Control,
                    seq,
                    bytes,
                    peer,
                    depth,
                    Some(id),
                    command,
                )
                .await
            }
            actions::GPDU | actions::END_MARKER => {
                let id = actions::session(action)?;
                let Some(s) = self.sessions.get(&id) else {
                    rejected(command, format!("no session {id}"));
                    return Ok(());
                };
                let Some(teid) = s.peer_data_teid else {
                    rejected(
                        command,
                        format!(
                            "session {id} has no tunnel yet: the peer has not given its data TEID"
                        ),
                    );
                    return Ok(());
                };
                let dest = self.user_dest(Some(s));
                let bytes = if kind == actions::END_MARKER {
                    msg::end_marker(teid)
                } else {
                    let parts = actions::gpdu_parts(action)?;
                    let source = match (parts.source, s.ue_address) {
                        (Some(a), _) => a,
                        (None, Some(IpAddr::V4(a))) => a,
                        _ => {
                            rejected(
                                command,
                                format!("session {id} has no IPv4 UE address; give source"),
                            );
                            return Ok(());
                        }
                    };
                    self.user_seq = self.user_seq.wrapping_add(1);
                    let packet = msg::ipv4_packet(
                        source,
                        parts.destination,
                        parts.ttl,
                        self.user_seq,
                        &parts.inner,
                        &parts.payload,
                    )?;
                    msg::gpdu(teid, self.user_seq, &packet)
                };
                self.user.send_to(&bytes, dest).await?;
                reply(
                    command,
                    ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    },
                );
                Ok(())
            }
            actions::ERROR_INDICATION => {
                let teid = action["teid"].as_u64().unwrap_or_default() as u32;
                let Some(dest) = self.unknown_teids.remove(&teid) else {
                    rejected(
                        command,
                        format!("no G-PDU to an unknown TEID {teid} has arrived"),
                    );
                    return Ok(());
                };
                self.user_seq = self.user_seq.wrapping_add(1);
                let bytes = msg::error_indication(teid, self.user_seq, self.user_ip);
                self.user.send_to(&bytes, dest).await?;
                reply(
                    command,
                    ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    },
                );
                Ok(())
            }
            actions::RESPOND => {
                let seq = action["sequence"].as_u64().unwrap_or_default() as u32;
                let Some(req) = self.inbound.remove(&seq) else {
                    rejected(
                        command,
                        format!("no request from the peer with sequence {seq} is waiting"),
                    );
                    return Ok(());
                };
                let cause = msg::cause_value(req.version, &action["cause"])?;
                let teid = req
                    .session
                    .and_then(|id| self.sessions.get(&id))
                    .and_then(|s| s.peer_control_teid)
                    .unwrap_or(req.teid);
                let bytes =
                    msg::cause_response(req.version, req.message_type + 1, teid, seq, cause);
                self.control.send(&bytes).await?;
                let deletes = matches!(
                    (req.version, req.message_type),
                    (GtpVersion::V1, 20) | (GtpVersion::V2, 36 | 99)
                );
                if deletes && codec::cause_accepts(req.version, cause) {
                    if let Some(id) = req.session {
                        self.sessions.remove(&id);
                    }
                }
                reply(
                    command,
                    ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    },
                );
                Ok(())
            }
            other => bail!("unexpected action {other}"),
        }
    }

    async fn retransmit(&mut self) {
        let now = Instant::now();
        let due: Vec<(Plane, u32)> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        for key in due {
            let Some(p) = self.pending.get_mut(&key) else {
                continue;
            };
            if p.sent > self.n3 {
                let p = self.pending.remove(&key).expect("present");
                if p.request == Request::Create {
                    if let Some(id) = p.session {
                        self.sessions.remove(&id);
                    }
                }
                let data = json!({"request": request_label(p.request), "sequence": key.1,
                    "session": p.session, "attempts": p.sent,
                    "plane": if p.plane == Plane::User { "user" } else { "control" }});
                self.log().warn(format!(
                    "GTP client {}: {} seq {} unanswered after {} sends decision=timeout",
                    self.client,
                    request_label(p.request),
                    key.1,
                    p.sent
                ));
                reply(
                    p.command,
                    ClientSendOutcome::Executed {
                        detail: json!({"timeout": data}).to_string(),
                    },
                );
                self.emit(&actions::TIMEOUT_EVENT, data, p.depth);
                continue;
            }
            p.sent += 1;
            p.deadline = now + self.t3;
            let (bytes, dest, plane) = (p.bytes.clone(), p.dest, p.plane);
            let _ = match plane {
                Plane::Control => self.control.send(&bytes).await,
                Plane::User => self.user.send_to(&bytes, dest).await,
            };
        }
    }

    fn session_by(&self, f: impl Fn(&Session) -> bool) -> Option<u32> {
        self.sessions.iter().find(|(_, s)| f(s)).map(|(id, _)| *id)
    }

    async fn incoming_control(&mut self, datagram: &[u8]) {
        let c = match msg::decode_control(datagram) {
            Ok(c) => c,
            Err(e) => {
                self.log().warn(format!(
                    "GTP client {} refused a control datagram: {e:#} decision=refused_malformed",
                    self.client
                ));
                return;
            }
        };
        if c.message_type == 1 {
            // Path management is mechanical: answer with this node's Recovery.
            let bytes = msg::echo_response(c.version, c.sequence, RECOVERY);
            let _ = self.control.send(&bytes).await;
            tracing::debug!(
                "GTP client {} answered an Echo Request decision=echo_answered",
                self.client
            );
            return;
        }
        if let Some(p) = self.pending.get(&(Plane::Control, c.sequence)) {
            let expected = p.request.response_type(self.version());
            // Version Not Supported is type 3 in both versions and answers whatever was sent.
            let vns = c.message_type == codec::V1_VERSION_NOT_SUPPORTED;
            if !(vns || (c.version == self.version() && c.message_type == expected)) {
                self.log().warn(format!(
                    "GTP client {}: a {} with sequence {} does not answer the {} sent with it decision=refused_unexpected_type",
                    self.client,
                    c.name(),
                    c.sequence,
                    p.request.name(self.version())
                ));
                return;
            }
            let p = self
                .pending
                .remove(&(Plane::Control, c.sequence))
                .expect("present");
            self.answered(p, c);
            return;
        }
        if c.is_peer_request() {
            let session = self.session_by(|s| s.local_control_teid == c.teid && c.teid != 0);
            let answer = msg::read_answer(self.role, &c);
            let mut data = json!({"message": c.name(), "message_type": c.message_type,
                "version": c.version.as_number(), "sequence": c.sequence, "teid": c.teid,
                "session": session});
            if let Some(cause) = answer.data.get("cause") {
                data["cause"] = cause.clone();
            }
            self.inbound.insert(
                c.sequence,
                Inbound {
                    version: c.version,
                    message_type: c.message_type,
                    session,
                    teid: c.teid,
                },
            );
            if self.inbound.len() > MAX_REMEMBERED {
                if let Some(oldest) = self.inbound.keys().min().copied() {
                    self.inbound.remove(&oldest);
                }
            }
            self.emit(&actions::PEER_REQUEST_EVENT, data, 0);
            return;
        }
        tracing::debug!(
            "GTP client {} ignored a {} with sequence {} it did not ask for decision=ignored_unmatched",
            self.client,
            c.name(),
            c.sequence
        );
    }

    fn answered(&mut self, p: Pending, c: msg::Control) {
        let answer = msg::read_answer(self.role, &c);
        let mut data = answer.data.clone();
        data["request"] = json!(request_label(p.request));
        data["message"] = json!(c.name());
        data["sequence"] = json!(c.sequence);
        data["version"] = json!(c.version.as_number());
        if p.plane == Plane::User {
            data["plane"] = json!("user");
        }
        if c.message_type == codec::V1_VERSION_NOT_SUPPORTED {
            data["accepted"] = json!(false);
        }
        let accepted = answer
            .cause
            .map(|v| codec::cause_accepts(c.version, v))
            .unwrap_or(false);
        if let Some(id) = p.session {
            data["session"] = json!(id);
            match p.request {
                Request::Create if accepted => {
                    if let Some(s) = self.sessions.get_mut(&id) {
                        s.peer_control_teid = answer.peer_control_teid;
                        s.peer_data_teid = answer.peer_data_teid;
                        s.peer_data_address = answer.peer_data_address;
                        s.ue_address = answer.ue_address;
                        data["local_control_teid"] = json!(s.local_control_teid);
                        data["local_data_teid"] = json!(s.local_data_teid);
                    }
                }
                Request::Create => {
                    self.sessions.remove(&id);
                }
                Request::Modify if accepted => {
                    if let Some(s) = self.sessions.get_mut(&id) {
                        if answer.peer_data_teid.is_some() {
                            s.peer_data_teid = answer.peer_data_teid;
                            s.peer_data_address = answer.peer_data_address.or(s.peer_data_address);
                        }
                    }
                }
                Request::Delete if accepted => {
                    self.sessions.remove(&id);
                }
                _ => {}
            }
        }
        self.log().info(format!(
            "GTP client {}: {} answered by {} cause {} decision={}",
            self.client,
            request_label(p.request),
            c.name(),
            data["cause"],
            if p.request == Request::Echo || accepted {
                "peer_accept"
            } else {
                "peer_reject"
            }
        ));
        reply(
            p.command,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        self.emit(&actions::RESPONSE_EVENT, data, p.depth);
    }

    async fn incoming_user(&mut self, datagram: &[u8], from: SocketAddr) {
        let known_source = from.ip() == self.peer.ip()
            || self
                .sessions
                .values()
                .any(|s| s.peer_data_address == Some(from.ip()));
        if !known_source {
            self.log().warn(format!(
                "GTP client {}: user-plane datagram from {from}, which is no peer of this client, refused decision=refused_unknown_source",
                self.client
            ));
            return;
        }
        let m = match codec::peek_version(datagram) {
            Some(1) => GtpV1Message::decode(datagram).map_err(anyhow::Error::from),
            Some(v) => Err(anyhow::anyhow!("GTP-U is version 1, this is {v}")),
            None => Err(anyhow::anyhow!("empty datagram")),
        };
        let m = match m {
            Ok(m) if m.header.protocol_type => m,
            Ok(_) => {
                self.log().warn(format!(
                    "GTP client {}: GTP' on the user plane refused decision=refused_malformed",
                    self.client
                ));
                return;
            }
            Err(e) => {
                self.log().warn(format!(
                    "GTP client {} refused a user-plane datagram from {from}: {e:#} decision=refused_malformed",
                    self.client
                ));
                return;
            }
        };
        let teid = m.header.teid;
        match m.header.message_type {
            codec::V1_ECHO_REQUEST => {
                let bytes = msg::echo_response(
                    GtpVersion::V1,
                    m.header.sequence.unwrap_or(0) as u32,
                    RECOVERY,
                );
                let _ = self.user.send_to(&bytes, from).await;
            }
            codec::V1_ECHO_RESPONSE => {
                let Some(seq) = m.header.sequence else { return };
                if let Some(p) = self.pending.remove(&(Plane::User, seq as u32)) {
                    let ies = codec::parse_v1_ies(&m.body).unwrap_or_default();
                    let c = msg::Control {
                        version: GtpVersion::V1,
                        message_type: codec::V1_ECHO_RESPONSE,
                        sequence: seq as u32,
                        teid,
                        v1: ies,
                        v2: vec![],
                    };
                    self.answered(p, c);
                }
            }
            msg::V1_G_PDU => {
                let session = self.session_by(|s| s.local_data_teid == teid);
                if session.is_none() {
                    self.unknown_teids.insert(teid, from);
                    if self.unknown_teids.len() > MAX_REMEMBERED {
                        if let Some(k) = self.unknown_teids.keys().find(|k| **k != teid).copied() {
                            self.unknown_teids.remove(&k);
                        }
                    }
                }
                let data = json!({"teid": teid, "session": session, "known_tunnel": session.is_some(),
                    "source_address": from.to_string(), "sequence": m.header.sequence,
                    "inner": msg::inner_json(&m.body)});
                self.emit(&actions::TUNNEL_PACKET_EVENT, data, 0);
            }
            msg::V1_ERROR_INDICATION => {
                let ies = match codec::parse_v1_ies(&m.body) {
                    Ok(ies) => ies,
                    Err(e) => {
                        self.log().warn(format!("GTP client {}: Error Indication refused: {e} decision=refused_malformed", self.client));
                        return;
                    }
                };
                let named = codec::find_v1(&ies, codec::V1_IE_TEID_DATA_I)
                    .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                let peer_address =
                    codec::find_v1(&ies, msg::V1_IE_PEER_ADDRESS).and_then(msg::addr);
                let session = named.and_then(|t| self.session_by(|s| s.peer_data_teid == Some(t)));
                self.emit(
                    &actions::TUNNEL_NOTIFICATION_EVENT,
                    json!({"message": "error_indication", "teid": named, "session": session,
                           "peer_address": peer_address.map(|a| a.to_string()), "source_address": from.to_string()}),
                    0,
                );
            }
            msg::V1_END_MARKER => {
                let session = self.session_by(|s| s.local_data_teid == teid);
                self.emit(
                    &actions::TUNNEL_NOTIFICATION_EVENT,
                    json!({"message": "end_marker", "teid": teid, "session": session, "source_address": from.to_string()}),
                    0,
                );
            }
            other => tracing::debug!(
                "GTP client {}: user-plane {} ignored",
                self.client,
                codec::v1_message_name(other)
            ),
        }
    }
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = GtpClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "GTP client {} not asking the model about {}: {depth} turns deep decision=followup_depth",
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
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            // Fail closed: nothing is sent on the model's behalf when it cannot be asked.
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                "GTP client {} handler: {e} decision=fail_closed_llm_error",
                ctx.client_id
            )),
        }
    }
}
