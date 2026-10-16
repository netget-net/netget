//! OpenFlow 1.3 switch — NetGet connects to a controller and is the switch it controls.
//!
//! Rust answers everything a controller asks of a switch from the switch the startup
//! parameters describe (datapath id, ports, table count) and from the flow table the
//! controller's own FLOW_MODs build: HELLO negotiation, FEATURES, ECHO, BARRIER, GET_CONFIG,
//! SET_CONFIG, ROLE, GET_ASYNC/SET_ASYNC, QUEUE_GET_CONFIG and the multipart queries. A
//! FLOW_MOD or PACKET_OUT is validated as a switch would (match prerequisites, lengths, ports)
//! and either applied and reported to the model as a structured event, or refused with the
//! OpenFlow ERROR a switch sends.
//!
//! The model decides what the switch *sees*: it describes packets to send up (PACKET_IN), and
//! port changes and flow removals to report. Nothing is forwarded; there is no data plane.
//!
//! Three tasks: a reader turning the socket into whole messages, the session (which owns the
//! writer, the switch state and every answer, so a slow model never delays an ECHO_REPLY), and
//! the model dispatcher, which asks the model about one event at a time and hands its actions
//! back to the session. The chain of model turns is bounded by [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::openflow::fields;
use crate::server::openflow::packet;
use crate::server::openflow::wire::{
    self, err, mp, msg, FlowMod, Instruction, Match, Message, VERSION_1_3,
};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::OpenFlowClientProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// TCP connect and the controller's HELLO.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// A quiet controller is sent an ECHO_REQUEST after this long, and dropped if it does not
/// answer within the same time.
pub const ECHO_INTERVAL: Duration = Duration::from_secs(15);
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Flow entries the switch keeps; a FLOW_MOD beyond it is refused with TABLE_FULL.
pub const MAX_FLOWS: usize = 4096;
/// Bytes of entries in one multipart reply part, under the 64 KiB message limit.
pub const MAX_PART_BYTES: usize = 60_000;
/// Events waiting for the model.
const TURNS: usize = 64;
pub const DEFAULT_PORT: u16 = 6653;

/// One flow entry the controller installed.
#[derive(Clone, Debug)]
struct FlowEntry {
    table_id: u8,
    priority: u16,
    matched: Match,
    instructions: Vec<Instruction>,
    cookie: u64,
    idle_timeout: u16,
    hard_timeout: u16,
    flags: u16,
    installed: crate::utils::clock::Instant,
}

struct Switch {
    datapath_id: u64,
    ports: Vec<wire::Port>,
    n_tables: u8,
    flows: Vec<FlowEntry>,
    config: (u16, u16),
    role: u32,
    generation_id: u64,
    started: crate::utils::clock::Instant,
}

fn resolve_target(remote: &str) -> String {
    let raw = remote
        .trim()
        .trim_start_matches("tcp://")
        .trim_start_matches("tcp:")
        .trim_end_matches('/');
    let has_port = raw.parse::<SocketAddr>().is_ok()
        || raw
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.ends_with(':') && p.parse::<u16>().is_ok());
    if has_port {
        raw.to_string()
    } else if raw.contains(':') && !raw.starts_with('[') {
        format!("[{raw}]:{DEFAULT_PORT}")
    } else {
        format!("{raw}:{DEFAULT_PORT}")
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let dpid = params
        .map(|p| p.get_optional_string("datapath_id"))
        .transpose()?
        .flatten();
    let ports = params
        .map(|p| p.get_optional_array("ports"))
        .transpose()?
        .flatten()
        .cloned();
    let n_tables = params
        .map(|p| p.get_optional_u64("n_tables"))
        .transpose()?
        .flatten();
    let cfg = actions::switch_config(ports.as_ref(), dpid.as_deref(), n_tables)?;
    let target = resolve_target(&ctx.remote_addr);
    let server = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("cannot resolve {target}"))?
        .next()
        .with_context(|| format!("{target} resolved to no address"))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server))
        .await
        .with_context(|| format!("connecting to {server} timed out"))?
        .with_context(|| format!("cannot reach {server}"))?;
    let _ = stream.set_nodelay(true);
    let (mut r, mut w) = stream.into_split();
    w.write_all(&wire::encode(
        VERSION_1_3,
        msg::HELLO,
        0,
        &wire::hello_body(&[VERSION_1_3]),
    )?)
    .await?;
    let hello = tokio::time::timeout(CONNECT_TIMEOUT, wire::read_message(&mut r))
        .await
        .context("the controller sent no HELLO")?
        .map_err(|e| anyhow::anyhow!("reading the controller's HELLO: {e}"))?;
    if hello.header.msg_type != msg::HELLO {
        bail!(
            "the controller's first message was {}, not HELLO",
            wire::msg_name(hello.header.msg_type)
        );
    }
    let bitmap = wire::parse_hello_bitmap(&hello.body)?;
    if wire::negotiate(hello.header.version, bitmap.as_deref()).is_none() {
        let _ = w
            .write_all(&wire::encode(
                VERSION_1_3,
                msg::ERROR,
                hello.header.xid,
                &wire::error_body(
                    err::HELLO_FAILED,
                    err::HELLO_INCOMPATIBLE,
                    crate::server::openflow::INCOMPATIBLE_TEXT.as_bytes(),
                ),
            )?)
            .await;
        bail!(
            "the controller does not offer OpenFlow 1.3 (it offers {})",
            match &bitmap {
                Some(b) => wire::bitmap_versions(b)
                    .into_iter()
                    .map(wire::version_name)
                    .collect::<Vec<_>>()
                    .join(", "),
                None => wire::version_name(hello.header.version),
            }
        );
    }
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "OpenFlow switch {} ({}) connected to controller {server}, version 1.3",
        ctx.client_id,
        wire::datapath_id_str(cfg.datapath_id)
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (msg_tx, msgs) = mpsc::channel::<std::result::Result<Message, String>>(16);
    let reader = ctx
        .state
        .spawn_client_task(ctx.client_id, async move {
            loop {
                match wire::read_message(&mut r).await {
                    Ok(m) => {
                        if msg_tx.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = msg_tx.send(Err(e.to_string())).await;
                        break;
                    }
                }
            }
        })
        .await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let dispatcher = ctx
        .state
        .spawn_client_task(ctx.client_id, run_turns(ctx.clone(), event_rx, internal_tx))
        .await;
    let session_ctx = ctx.clone();
    ctx.state
        .spawn_client_task(ctx.client_id, async move {
            let mut session = Session {
                ctx: session_ctx.clone(),
                writer: w,
                switch: Switch {
                    datapath_id: cfg.datapath_id,
                    ports: cfg.ports,
                    n_tables: cfg.n_tables,
                    flows: Vec::new(),
                    config: (0, 128),
                    role: 0,
                    generation_id: 0,
                    started: crate::utils::clock::Instant::now(),
                },
                events: event_tx.clone(),
                next_xid: 1,
                announced: false,
                server,
            };
            let reason = session.run(msgs, external, internal).await;
            reader.abort();
            let _ = session.writer.shutdown().await;
            Log::new(Some(&session_ctx.status_tx)).info(format!(
                "OpenFlow switch {} disconnected: {reason}",
                session_ctx.client_id
            ));
            let _ = event_tx
                .send((
                    Event::new(&actions::DISCONNECTED_EVENT, json!({"reason": reason})),
                    0,
                ))
                .await;
            drop(event_tx);
            drop(session);
            let _ = tokio::time::timeout(Duration::from_secs(30), async {
                while !dispatcher.is_finished() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
            dispatcher.abort();
            session_ctx
                .state
                .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
                .await;
            session_ctx
                .state
                .remove_client_handle(session_ctx.client_id)
                .await;
            let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
        })
        .await;
    Ok(server)
}

struct Session {
    ctx: ConnectContext,
    writer: OwnedWriteHalf,
    switch: Switch,
    events: mpsc::Sender<(Event, u32)>,
    next_xid: u32,
    announced: bool,
    server: SocketAddr,
}

/// Whether a flow entry's match is at least as specific as `req` on every field `req` names —
/// OpenFlow's non-strict match for modify, delete and the flow statistics filter.
fn covers(req: &Match, entry: &Match) -> bool {
    req.oxms.iter().all(|r| {
        entry
            .oxms
            .iter()
            .find(|e| e.class == r.class && e.field == r.field)
            .is_some_and(|e| match &r.mask {
                None => e.mask.is_none() && e.value == r.value,
                Some(rm) => {
                    e.value.len() == r.value.len()
                        && e.value
                            .iter()
                            .zip(rm)
                            .zip(&r.value)
                            .all(|((ev, m), rv)| ev & m == rv & m)
                        && e.mask
                            .as_ref()
                            .is_none_or(|em| em.iter().zip(rm).all(|(a, b)| a & b == *b))
                }
            })
    })
}

fn same_match(a: &Match, b: &Match) -> bool {
    let key = |m: &Match| {
        let mut v: Vec<_> = m
            .oxms
            .iter()
            .map(|o| (o.class, o.field, o.value.clone(), o.mask.clone()))
            .collect();
        v.sort();
        v
    };
    key(a) == key(b)
}

fn outputs_to(entry: &FlowEntry, port: u32) -> bool {
    entry.instructions.iter().any(|i| match i {
        Instruction::ApplyActions(a) | Instruction::WriteActions(a) => a
            .iter()
            .any(|x| matches!(x, wire::Action::Output { port: p, .. } if *p == port)),
        _ => false,
    })
}

impl Session {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.ctx.status_tx))
    }

    fn emit(&self, event: &'static EventType, data: Value, depth: u32) {
        if self
            .events
            .try_send((Event::new(event, data), depth))
            .is_err()
        {
            tracing::warn!(
                "OpenFlow switch {} dropped {}: the model is {TURNS} events behind \
                 decision=turn_queue_full",
                self.ctx.client_id,
                event.id
            );
        }
    }

    async fn write(&mut self, msg_type: u8, xid: u32, body: &[u8]) -> Result<()> {
        let bytes = wire::encode(VERSION_1_3, msg_type, xid, body)?;
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn send(&mut self, msg_type: u8, body: &[u8]) -> Result<u32> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1).max(1);
        self.write(msg_type, xid, body).await?;
        Ok(xid)
    }

    async fn refuse(&mut self, m: &Message, etype: u16, code: u16, why: &str) -> Result<()> {
        self.log().warn(format!(
            "OpenFlow switch {} refused the controller's {} with {}/{}: {why}",
            self.ctx.client_id,
            wire::msg_name(m.header.msg_type),
            wire::error_type_name(etype),
            wire::error_code_name(etype, code)
        ));
        self.write(
            msg::ERROR,
            m.header.xid,
            &wire::protocol_error(etype, code, m),
        )
        .await
    }

    async fn run(
        &mut self,
        mut msgs: mpsc::Receiver<std::result::Result<Message, String>>,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> String {
        let mut last_rx = crate::utils::clock::Instant::now();
        let mut echo: Option<(u32, crate::utils::clock::Instant)> = None;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            let step: Result<Option<String>> = tokio::select! {
                m = msgs.recv() => match m {
                    Some(Ok(m)) => {
                        last_rx = crate::utils::clock::Instant::now();
                        if m.header.msg_type == msg::ECHO_REPLY {
                            if echo.is_some_and(|(x, _)| x == m.header.xid) {
                                echo = None;
                            }
                            Ok(None)
                        } else {
                            self.handle(&m).await.map(|_| None)
                        }
                    }
                    Some(Err(e)) => Ok(Some(format!("the connection ended: {e}"))),
                    None => Ok(Some("the controller closed the connection".into())),
                },
                c = external.recv() => match c {
                    Some(c) => {
                        self.ctx.state.record_access_log(
                            AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                            "OpenFlow",
                            None,
                            "injected_action",
                            c.action.clone(),
                            vec![],
                        ).await;
                        let action = c.action.clone();
                        let (outcome, stop) = self.perform(&action).await;
                        crate::client::command_support::reply(c, Ok(outcome));
                        Ok(stop)
                    }
                    None => Ok(Some("the client was stopped".into())),
                },
                a = internal.recv() => match a {
                    Some((action, _depth)) => {
                        let (outcome, stop) = self.perform(&action).await;
                        if let ClientSendOutcome::Rejected { error } = &outcome {
                            self.log().warn(format!(
                                "OpenFlow switch {}: the model's {} was not carried out: {error}",
                                self.ctx.client_id,
                                action["type"].as_str().unwrap_or("action")
                            ));
                        }
                        Ok(stop)
                    }
                    None => Ok(Some("the client was stopped".into())),
                },
                _ = tick.tick() => {
                    let now = crate::utils::clock::Instant::now();
                    match echo {
                        Some((_, at)) if now.duration_since(at) >= ECHO_INTERVAL => {
                            Ok(Some(format!("the controller did not answer ECHO in {ECHO_INTERVAL:?} decision=protocol_timeout")))
                        }
                        None if now.duration_since(last_rx) >= ECHO_INTERVAL => {
                            self.send(msg::ECHO_REQUEST, &[]).await.map(|xid| {
                                echo = Some((xid, now));
                                None
                            })
                        }
                        _ => Ok(None),
                    }
                }
            };
            match step {
                Ok(None) => {}
                Ok(Some(reason)) => return reason,
                Err(e) => return format!("the connection failed: {e:#}"),
            }
        }
    }

    /// Carry out one action (the model's or an operator's). Returns the outcome and, when the
    /// session should end, why.
    async fn perform(&mut self, action: &Value) -> (ClientSendOutcome, Option<String>) {
        match OpenFlowClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                return (
                    ClientSendOutcome::Disconnected,
                    Some("the client disconnected".into()),
                )
            }
            Ok(_) => {}
            Err(e) => {
                return (
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                    None,
                )
            }
        }
        let request = match actions::check(action) {
            Ok(r) => r,
            Err(e) => {
                return (
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                    None,
                )
            }
        };
        let result: Result<(usize, String)> = async {
            match request {
                actions::Request::PacketIn {
                    in_port,
                    frame,
                    reason,
                    table_id,
                    cookie,
                } => {
                    if in_port < wire::port::MAX
                        && !self.switch.ports.iter().any(|p| p.port_no == in_port)
                    {
                        bail!(
                            "in_port {in_port} is not one of this switch's ports ({})",
                            self.port_list()
                        );
                    }
                    let pi = wire::PacketIn {
                        buffer_id: wire::NO_BUFFER,
                        total_len: frame.len() as u16,
                        reason,
                        table_id,
                        cookie,
                        matched: Match {
                            oxms: vec![wire::Oxm::basic(
                                wire::fields::IN_PORT,
                                in_port.to_be_bytes().to_vec(),
                            )],
                        },
                        data: frame,
                    };
                    let body = pi.encode();
                    let xid = self.send(msg::PACKET_IN, &body).await?;
                    Ok((
                        body.len() + wire::HEADER_LEN,
                        format!("PACKET_IN xid {xid:#x} on port {in_port}"),
                    ))
                }
                actions::Request::PortStatus { reason, spec } => {
                    let port_no = fields::port_from_json(&spec["port_no"], "port_no")?;
                    let existing = self.switch.ports.iter().position(|p| p.port_no == port_no);
                    let port = match (reason, existing) {
                        (0, Some(_)) => bail!("port {port_no} already exists"),
                        (0, None) => {
                            if self.switch.ports.len() >= actions::MAX_PORTS {
                                bail!("the switch already has {} ports", actions::MAX_PORTS);
                            }
                            let p = actions::port_from_json(&spec, None)?;
                            self.switch.ports.push(p.clone());
                            p
                        }
                        (_, None) => bail!("there is no port {port_no} ({})", self.port_list()),
                        (1, Some(i)) => self.switch.ports.remove(i),
                        (_, Some(i)) => {
                            let p = actions::port_from_json(&spec, Some(&self.switch.ports[i]))?;
                            self.switch.ports[i] = p.clone();
                            p
                        }
                    };
                    let body = wire::port_status_body(reason, &port);
                    let xid = self.send(msg::PORT_STATUS, &body).await?;
                    Ok((
                        body.len() + wire::HEADER_LEN,
                        format!("PORT_STATUS xid {xid:#x} for port {port_no}"),
                    ))
                }
                actions::Request::FlowRemoved {
                    priority,
                    table_id,
                    matched,
                    reason,
                } => {
                    let i = self
                        .switch
                        .flows
                        .iter()
                        .position(|f| {
                            f.table_id == table_id
                                && f.priority == priority
                                && same_match(&f.matched, &matched)
                        })
                        .context("no installed flow has that table, priority and match")?;
                    let f = self.switch.flows.remove(i);
                    let age = f.installed.elapsed();
                    let fr = wire::FlowRemoved {
                        cookie: f.cookie,
                        priority: f.priority,
                        reason,
                        table_id: f.table_id,
                        duration_sec: age.as_secs() as u32,
                        duration_nsec: age.subsec_nanos(),
                        idle_timeout: f.idle_timeout,
                        hard_timeout: f.hard_timeout,
                        packet_count: 0,
                        byte_count: 0,
                        matched: f.matched,
                    };
                    let body = fr.encode();
                    let xid = self.send(msg::FLOW_REMOVED, &body).await?;
                    Ok((
                        body.len() + wire::HEADER_LEN,
                        format!("FLOW_REMOVED xid {xid:#x}"),
                    ))
                }
            }
        }
        .await;
        match result {
            Ok((bytes_sent, what)) => {
                self.log().info(format!(
                    "OpenFlow switch {} sent {what}",
                    self.ctx.client_id
                ));
                (ClientSendOutcome::Sent { bytes_sent }, None)
            }
            Err(e) => (
                ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                },
                None,
            ),
        }
    }

    fn port_list(&self) -> String {
        self.switch
            .ports
            .iter()
            .map(|p| p.port_no.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Answer or apply one message from the controller.
    async fn handle(&mut self, m: &Message) -> Result<()> {
        if m.header.version != VERSION_1_3 && m.header.msg_type != msg::HELLO {
            return self
                .refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_VERSION,
                    "not the negotiated version",
                )
                .await;
        }
        let xid = m.header.xid;
        match m.header.msg_type {
            msg::HELLO => Ok(()),
            msg::ECHO_REQUEST => self.write(msg::ECHO_REPLY, xid, &m.body).await,
            msg::FEATURES_REQUEST => {
                let f = wire::Features {
                    datapath_id: self.switch.datapath_id,
                    n_buffers: 0,
                    n_tables: self.switch.n_tables,
                    auxiliary_id: 0,
                    capabilities: 1 | 2 | 4,
                };
                self.write(msg::FEATURES_REPLY, xid, &f.encode()).await?;
                if !self.announced {
                    self.announced = true;
                    let ports: Vec<Value> = self
                        .switch
                        .ports
                        .iter()
                        .map(crate::server::openflow::actions::port_json)
                        .collect();
                    self.emit(
                        &actions::CONNECTED_EVENT,
                        json!({
                            "controller": self.server.to_string(),
                            "version": "1.3",
                            "datapath_id": wire::datapath_id_str(self.switch.datapath_id),
                            "ports": ports,
                        }),
                        0,
                    );
                }
                Ok(())
            }
            msg::GET_CONFIG_REQUEST => {
                let (flags, miss) = self.switch.config;
                self.write(msg::GET_CONFIG_REPLY, xid, &wire::config_body(flags, miss))
                    .await
            }
            msg::SET_CONFIG => match wire::parse_config(&m.body) {
                Ok(c) => {
                    self.switch.config = c;
                    Ok(())
                }
                Err(e) => {
                    self.refuse(m, err::SWITCH_CONFIG_FAILED, 1, &e.to_string())
                        .await
                }
            },
            msg::BARRIER_REQUEST => self.write(msg::BARRIER_REPLY, xid, &[]).await,
            msg::ROLE_REQUEST => match wire::parse_role(&m.body) {
                Ok((role, generation_id)) => {
                    if role > 3 {
                        return self
                            .refuse(m, err::ROLE_REQUEST_FAILED, 2, "unknown role")
                            .await;
                    }
                    if role != 0 {
                        self.switch.role = role;
                        if role != 1 {
                            self.switch.generation_id = generation_id;
                        }
                    }
                    let body = wire::role_body(
                        if self.switch.role == 0 {
                            1
                        } else {
                            self.switch.role
                        },
                        self.switch.generation_id,
                    );
                    self.write(msg::ROLE_REPLY, xid, &body).await
                }
                Err(e) => {
                    self.refuse(
                        m,
                        err::BAD_REQUEST,
                        err::BAD_REQUEST_BAD_LEN,
                        &e.to_string(),
                    )
                    .await
                }
            },
            msg::GET_ASYNC_REQUEST => {
                self.write(msg::GET_ASYNC_REPLY, xid, &wire::default_async_body())
                    .await
            }
            msg::SET_ASYNC | msg::TABLE_MOD => Ok(()),
            msg::QUEUE_GET_CONFIG_REQUEST => {
                let port = m.body.get(..4).map(|b| b.to_vec()).unwrap_or(vec![0; 4]);
                let mut body = port;
                body.extend_from_slice(&[0; 4]);
                self.write(msg::QUEUE_GET_CONFIG_REPLY, xid, &body).await
            }
            msg::MULTIPART_REQUEST => self.multipart(m).await,
            msg::FLOW_MOD => self.flow_mod(m).await,
            msg::PACKET_OUT => self.packet_out(m).await,
            msg::ERROR => {
                match wire::ErrorMsg::parse(&m.body) {
                    Ok(e) => {
                        let request = e.offending().map(
                            |(t, x)| json!({"type": wire::msg_name(t), "xid": format!("{x:#x}")}),
                        );
                        self.log().warn(format!(
                            "OpenFlow controller sent ERROR {}/{}",
                            wire::error_type_name(e.etype),
                            wire::error_code_name(e.etype, e.code)
                        ));
                        self.emit(
                            &actions::ERROR_EVENT,
                            json!({
                                "error_type": wire::error_type_name(e.etype),
                                "error_code": wire::error_code_name(e.etype, e.code),
                                "request": request,
                            }),
                            0,
                        );
                    }
                    Err(e) => self.log().warn(format!(
                        "OpenFlow ERROR from the controller unreadable: {e}"
                    )),
                }
                Ok(())
            }
            msg::EXPERIMENTER => {
                self.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_EXPERIMENTER,
                    "no experimenter extensions",
                )
                .await
            }
            msg::GROUP_MOD | msg::METER_MOD | msg::PORT_MOD => {
                self.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_TYPE,
                    "groups, meters and port changes are not supported by this switch",
                )
                .await
            }
            _ => {
                self.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_TYPE,
                    "a controller does not send this to a switch",
                )
                .await
            }
        }
    }

    async fn flow_mod(&mut self, m: &Message) -> Result<()> {
        let fm = match FlowMod::parse(&m.body) {
            Ok(fm) => fm,
            Err((t, c, why)) => return self.refuse(m, t, c, &why).await,
        };
        if let Err((code, why)) = fields::check_prerequisites(&fm.matched) {
            return self.refuse(m, err::BAD_MATCH, code, &why).await;
        }
        let deleting = matches!(
            fm.command,
            wire::flow_cmd::DELETE | wire::flow_cmd::DELETE_STRICT
        );
        if fm.command > wire::flow_cmd::DELETE_STRICT {
            return self
                .refuse(
                    m,
                    err::FLOW_MOD_FAILED,
                    err::FLOW_MOD_FAILED_BAD_COMMAND,
                    "unknown command",
                )
                .await;
        }
        if (fm.table_id == wire::TABLE_ALL && !deleting)
            || (fm.table_id != wire::TABLE_ALL && fm.table_id >= self.switch.n_tables)
        {
            return self
                .refuse(
                    m,
                    err::FLOW_MOD_FAILED,
                    err::FLOW_MOD_FAILED_BAD_TABLE_ID,
                    "no such table",
                )
                .await;
        }
        for i in &fm.instructions {
            if let Instruction::GotoTable(t) = i {
                if *t <= fm.table_id || *t >= self.switch.n_tables {
                    return self
                        .refuse(
                            m,
                            err::BAD_INSTRUCTION,
                            2,
                            "goto_table must go forward to a table that exists",
                        )
                        .await;
                }
            }
            if let Instruction::ApplyActions(a) | Instruction::WriteActions(a) = i {
                for x in a {
                    if let wire::Action::Output { port, .. } = x {
                        let known = *port >= wire::port::MAX
                            || self.switch.ports.iter().any(|p| p.port_no == *port);
                        if !known || *port == wire::port::ANY {
                            return self
                                .refuse(
                                    m,
                                    err::BAD_ACTION,
                                    err::BAD_ACTION_BAD_OUT_PORT,
                                    &format!("no port {port}"),
                                )
                                .await;
                        }
                    }
                    if let wire::Action::Other { atype, .. } = x {
                        return self
                            .refuse(
                                m,
                                err::BAD_ACTION,
                                err::BAD_ACTION_BAD_TYPE,
                                &format!("unsupported action type {atype}"),
                            )
                            .await;
                    }
                }
            }
        }
        let cookie_ok = |f: &FlowEntry| (f.cookie & fm.cookie_mask) == (fm.cookie & fm.cookie_mask);
        let table_ok = |f: &FlowEntry| fm.table_id == wire::TABLE_ALL || f.table_id == fm.table_id;
        let strict = matches!(
            fm.command,
            wire::flow_cmd::MODIFY_STRICT | wire::flow_cmd::DELETE_STRICT
        );
        let selected = |f: &FlowEntry| {
            table_ok(f)
                && cookie_ok(f)
                && if strict {
                    f.priority == fm.priority && same_match(&f.matched, &fm.matched)
                } else {
                    covers(&fm.matched, &f.matched)
                }
        };
        let affected = match fm.command {
            wire::flow_cmd::ADD => {
                let existing = self.switch.flows.iter().position(|f| {
                    f.table_id == fm.table_id
                        && f.priority == fm.priority
                        && same_match(&f.matched, &fm.matched)
                });
                if existing.is_none() && self.switch.flows.len() >= MAX_FLOWS {
                    return self
                        .refuse(
                            m,
                            err::FLOW_MOD_FAILED,
                            err::FLOW_MOD_FAILED_TABLE_FULL,
                            &format!("the switch holds {MAX_FLOWS} flows"),
                        )
                        .await;
                }
                let entry = FlowEntry {
                    table_id: fm.table_id,
                    priority: fm.priority,
                    matched: fm.matched.clone(),
                    instructions: fm.instructions.clone(),
                    cookie: fm.cookie,
                    idle_timeout: fm.idle_timeout,
                    hard_timeout: fm.hard_timeout,
                    flags: fm.flags,
                    installed: crate::utils::clock::Instant::now(),
                };
                match existing {
                    Some(i) => self.switch.flows[i] = entry,
                    None => self.switch.flows.push(entry),
                }
                1
            }
            wire::flow_cmd::MODIFY | wire::flow_cmd::MODIFY_STRICT => {
                let mut n = 0;
                for f in self.switch.flows.iter_mut().filter(|f| selected(f)) {
                    f.instructions = fm.instructions.clone();
                    n += 1;
                }
                n
            }
            _ => {
                let before = self.switch.flows.len();
                let out_port = fm.out_port;
                self.switch.flows.retain(|f| {
                    !(selected(f) && (out_port == wire::port::ANY || outputs_to(f, out_port)))
                });
                before - self.switch.flows.len()
            }
        };
        if fm.buffer_id != wire::NO_BUFFER {
            self.refuse(
                m,
                err::BAD_REQUEST,
                err::BAD_REQUEST_BUFFER_UNKNOWN,
                "this switch buffers no packets",
            )
            .await?;
        }
        self.emit(
            &actions::FLOW_MOD_EVENT,
            json!({
                "command": wire::flow_cmd::NAMES[fm.command as usize],
                "table_id": if fm.table_id == wire::TABLE_ALL { json!("all") } else { json!(fm.table_id) },
                "priority": fm.priority,
                "match": fields::match_to_json(&fm.matched),
                "instructions": fields::instructions_to_json(&fm.instructions),
                "idle_timeout": fm.idle_timeout,
                "hard_timeout": fm.hard_timeout,
                "cookie": format!("{:#x}", fm.cookie),
                "flags": wire::flow_flag_names(fm.flags),
                "flows_affected": affected,
                "flow_count": self.switch.flows.len(),
            }),
            0,
        );
        Ok(())
    }

    async fn packet_out(&mut self, m: &Message) -> Result<()> {
        let po = match wire::PacketOut::parse(&m.body) {
            Ok(p) => p,
            Err((t, c, why)) => return self.refuse(m, t, c, &why).await,
        };
        let known_in_port = po.in_port == wire::port::CONTROLLER
            || po.in_port == wire::port::LOCAL
            || self.switch.ports.iter().any(|p| p.port_no == po.in_port);
        if !known_in_port {
            return self
                .refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_PORT,
                    &format!("in_port {} is not a port of this switch", po.in_port),
                )
                .await;
        }
        if po.buffer_id != wire::NO_BUFFER {
            return self
                .refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BUFFER_UNKNOWN,
                    "this switch buffers no packets",
                )
                .await;
        }
        for x in &po.actions {
            if let wire::Action::Output { port, .. } = x {
                let known = (*port >= wire::port::MAX && *port != wire::port::ANY)
                    || self.switch.ports.iter().any(|p| p.port_no == *port);
                if !known {
                    return self
                        .refuse(
                            m,
                            err::BAD_ACTION,
                            err::BAD_ACTION_BAD_OUT_PORT,
                            &format!("no port {port}"),
                        )
                        .await;
                }
            }
        }
        self.emit(
            &actions::PACKET_OUT_EVENT,
            json!({
                "in_port": fields::port_to_json(po.in_port),
                "actions": fields::actions_to_json(&po.actions),
                "packet": packet::describe(&po.data),
            }),
            0,
        );
        Ok(())
    }

    async fn multipart(&mut self, m: &Message) -> Result<()> {
        let (mtype, flags, body) = match wire::parse_multipart(&m.body) {
            Ok(x) => x,
            Err(e) => {
                return self
                    .refuse(
                        m,
                        err::BAD_REQUEST,
                        err::BAD_REQUEST_BAD_LEN,
                        &e.to_string(),
                    )
                    .await
            }
        };
        if flags & mp::MORE != 0 {
            return self
                .refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_MULTIPART_BUFFER_OVERFLOW,
                    "multipart requests in several parts are not supported",
                )
                .await;
        }
        let xid = m.header.xid;
        let parts: Vec<Vec<u8>> = match mtype {
            mp::DESC => vec![wire::desc_body([
                "NetGet",
                "NetGet OpenFlow switch",
                concat!("NetGet ", env!("CARGO_PKG_VERSION")),
                "none",
                "NetGet switch",
            ])],
            mp::PORT_DESC => {
                let mut b = Vec::new();
                for p in &self.switch.ports {
                    p.encode(&mut b);
                }
                vec![b]
            }
            mp::FLOW | mp::AGGREGATE => {
                let req = match wire::FlowStatsRequest::parse(body) {
                    Ok(r) => r,
                    Err((t, c, why)) => return self.refuse(m, t, c, &why).await,
                };
                let now = crate::utils::clock::Instant::now();
                let selected: Vec<&FlowEntry> = self
                    .switch
                    .flows
                    .iter()
                    .filter(|f| {
                        (req.table_id == wire::TABLE_ALL || f.table_id == req.table_id)
                            && (f.cookie & req.cookie_mask) == (req.cookie & req.cookie_mask)
                            && (req.out_port == wire::port::ANY || outputs_to(f, req.out_port))
                            && covers(&req.matched, &f.matched)
                    })
                    .collect();
                if mtype == mp::AGGREGATE {
                    vec![wire::aggregate_body(0, 0, selected.len() as u32)]
                } else {
                    let mut parts = vec![Vec::new()];
                    for f in selected {
                        let age = now.duration_since(f.installed);
                        let mut entry = Vec::new();
                        wire::FlowStats {
                            table_id: f.table_id,
                            duration_sec: age.as_secs() as u32,
                            duration_nsec: age.subsec_nanos(),
                            priority: f.priority,
                            idle_timeout: f.idle_timeout,
                            hard_timeout: f.hard_timeout,
                            flags: f.flags,
                            cookie: f.cookie,
                            packet_count: 0,
                            byte_count: 0,
                            matched: f.matched.clone(),
                            instructions: f.instructions.clone(),
                        }
                        .encode(&mut entry);
                        let last = parts.len() - 1;
                        if !parts[last].is_empty()
                            && parts[last].len() + entry.len() > MAX_PART_BYTES
                        {
                            parts.push(Vec::new());
                        }
                        let last = parts.len() - 1;
                        parts[last].extend_from_slice(&entry);
                    }
                    parts
                }
            }
            mp::TABLE => {
                let mut b = Vec::new();
                for t in 0..self.switch.n_tables {
                    let active = self.switch.flows.iter().filter(|f| f.table_id == t).count();
                    wire::TableStats {
                        table_id: t,
                        active_count: active as u32,
                        lookup_count: 0,
                        matched_count: 0,
                    }
                    .encode(&mut b);
                }
                vec![b]
            }
            mp::PORT_STATS => {
                let want = body
                    .get(..4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(wire::port::ANY);
                let elapsed = self.switch.started.elapsed();
                let mut b = Vec::new();
                for p in self
                    .switch
                    .ports
                    .iter()
                    .filter(|p| want == wire::port::ANY || p.port_no == want)
                {
                    wire::PortStats {
                        port_no: p.port_no,
                        counters: [0; 12],
                        duration_sec: elapsed.as_secs() as u32,
                        duration_nsec: elapsed.subsec_nanos(),
                    }
                    .encode(&mut b);
                }
                if b.is_empty() && want != wire::port::ANY {
                    return self
                        .refuse(
                            m,
                            err::BAD_REQUEST,
                            err::BAD_REQUEST_BAD_PORT,
                            "no such port",
                        )
                        .await;
                }
                vec![b]
            }
            // No groups, meters or queues: empty lists, and features that offer nothing.
            mp::GROUP | mp::GROUP_DESC | mp::METER | mp::METER_CONFIG | mp::QUEUE => {
                vec![Vec::new()]
            }
            mp::GROUP_FEATURES => vec![vec![0; 40]],
            mp::METER_FEATURES => vec![vec![0; 16]],
            _ => {
                return self
                    .refuse(
                        m,
                        err::BAD_REQUEST,
                        err::BAD_REQUEST_BAD_MULTIPART,
                        &format!("{} queries are not supported", mp::name(mtype)),
                    )
                    .await
            }
        };
        let n = parts.len();
        for (i, part) in parts.iter().enumerate() {
            let more = if i + 1 < n { mp::MORE } else { 0 };
            self.write(
                msg::MULTIPART_REPLY,
                xid,
                &wire::multipart_body(mtype, more, part),
            )
            .await?;
        }
        Ok(())
    }
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = OpenFlowClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "OpenFlow switch {} not asking the model about {}: {depth} turns deep \
                 decision=followup_depth",
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
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                "OpenFlow switch {}: {} not answered; nothing sent decision=fail_closed_llm_error: {e}",
                ctx.client_id,
                event.id()
            )),
        }
    }
}
