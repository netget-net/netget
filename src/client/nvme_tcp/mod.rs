//! NVMe/TCP host client. The model decides whether to read the discovery log, which subsystem
//! to connect to and which commands to run; [`host`] runs the queues. Each result is raised as
//! an event the model (or a handler) answers, the chain bounded at [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;
pub mod host;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::nvme_tcp::auth;
use crate::server::nvme_tcp::nvme::{self, cns, ControllerInfo, Smart};
pub use actions::NvmeTcpClientProtocol;
use anyhow::{bail, Context, Result};
use host::{HostConfig, QueueConn};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// A handler chain (result → event → command …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 16;
pub const DEFAULT_HOST_NQN: &str = "nqn.2026-10.net.netget:host";
pub const DEFAULT_DIGESTS: &str = "none";
pub const DEFAULT_KATO_MS: u32 = 30_000;
/// The KATO range this host asks for.
pub const MIN_KATO_MS: u32 = 1_000;
pub const MAX_KATO_MS: u32 = 600_000;

async fn resolve(remote: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(remote)
        .await
        .with_context(|| format!("resolving {remote}"))?
        .next()
        .with_context(|| format!("{remote} resolves to no address"))
}

/// A UUID's 16 bytes from its text form.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    if h.len() != 32 {
        return None;
    }
    hex::decode(h).ok()?.try_into().ok()
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let hostnqn = get("host_nqn")?.unwrap_or_else(|| DEFAULT_HOST_NQN.into());
    anyhow::ensure!(nvme::valid_nqn(&hostnqn), "host_nqn is an NQN (nqn.…)");
    let hostid = match get("host_id")? {
        Some(s) => parse_uuid(&s).context("host_id is a UUID")?,
        None => *uuid::Uuid::new_v4().as_bytes(),
    };
    let subnqn = get("subsystem_nqn")?;
    if let Some(s) = &subnqn {
        anyhow::ensure!(nvme::valid_nqn(s), "subsystem_nqn is an NQN (nqn.…)");
    }
    let digests = match get("digests")?.as_deref() {
        None | Some("none") => false,
        Some("crc32c") => true,
        Some(_) => bail!("digests is none or crc32c"),
    };
    let kato_ms = match params
        .map(|p| p.get_optional_u64("keep_alive_ms"))
        .transpose()?
        .flatten()
    {
        None => DEFAULT_KATO_MS,
        Some(v) => {
            anyhow::ensure!(
                (MIN_KATO_MS as u64..=MAX_KATO_MS as u64).contains(&v),
                "keep_alive_ms is {MIN_KATO_MS} to {MAX_KATO_MS}"
            );
            v as u32
        }
    };
    let secret = |name: &str| -> Result<Option<auth::Secret>> {
        match get(name)? {
            None => Ok(None),
            Some(s) => auth::Secret::parse(&s)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("{name}: {e}")),
        }
    };
    let dhchap = match (secret("dhchap_secret")?, secret("dhchap_ctrl_secret")?) {
        (Some(secret), ctrl_secret) => Some(std::sync::Arc::new(host::Dhchap {
            secret,
            ctrl_secret,
        })),
        (None, Some(_)) => bail!(
            "dhchap_ctrl_secret needs dhchap_secret: a controller is asked to prove itself only \
             by a host that proves itself"
        ),
        (None, None) => None,
    };
    let config = HostConfig {
        hostnqn: hostnqn.clone(),
        hostid,
        digests,
        kato_ms,
        dhchap,
    };
    let addr = resolve(&ctx.remote_addr).await?;

    ctx.state
        .update_client_status(ctx.client_id, crate::state::ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, event_rx) = mpsc::channel::<(Event, usize)>(32);
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "remote_addr": addr.to_string(),
                "host_nqn": hostnqn,
                "subsystem_nqn": subnqn,
            }),
        ),
        0,
    ))?;
    let dispatcher = spawn_dispatcher(&ctx, event_rx, internal_tx).await;
    let run_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut h = Host {
            ctx: &run_ctx,
            addr,
            config,
            default_subsystem: subnqn,
            session: None,
            next_tid: 0,
        };
        let result = h.run(external, internal_rx, event_tx).await;
        if let Some(mut s) = h.session.take() {
            let _ = host::shutdown(&mut s.admin).await;
        }
        dispatcher.abort();
        let status = match result {
            Ok(()) => crate::state::ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&run_ctx.status_tx)).warn(format!("NVMe/TCP client ended: {e:#}"));
                crate::state::ClientStatus::Error(e.to_string())
            }
        };
        run_ctx
            .state
            .update_client_status(run_ctx.client_id, status)
            .await;
        run_ctx.state.remove_client_handle(run_ctx.client_id).await;
        let _ = run_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    // No queue is open until the model connects, so there is no local address to report.
    Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// Events in, the model (or a handler) asked, its actions out with the depth they were
/// produced at. A failed call sends nothing: fail closed.
async fn spawn_dispatcher(
    ctx: &ConnectContext,
    mut events: mpsc::Receiver<(Event, usize)>,
    actions_tx: mpsc::Sender<(Value, usize)>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            let protocol = NvmeTcpClientProtocol;
            while let Some((event, depth)) = events.recv().await {
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
                            if actions_tx.send((action, depth + 1)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                        "NVMe/TCP client handler failed (nothing sent): {e}"
                    )),
                }
            }
        }
    });
    let abort = task.abort_handle();
    ctx.state.register_client_task(ctx.client_id, task).await;
    abort
}

/// A connected controller: its admin queue and one I/O queue.
struct Session {
    subnqn: String,
    admin: QueueConn,
    io: QueueConn,
    info: ControllerInfo,
    vs: u32,
    max_transfer: usize,
    io_queues: u16,
    /// Block sizes learned from Identify Namespace.
    block_sizes: HashMap<u32, u32>,
    next_keep_alive: tokio::time::Instant,
    /// How the admin queue authenticated, when the target asked it to.
    authenticated: Option<host::Authenticated>,
}

struct Host<'a> {
    ctx: &'a ConnectContext,
    addr: SocketAddr,
    config: HostConfig,
    default_subsystem: Option<String>,
    session: Option<Session>,
    /// The next DH-HMAC-CHAP transaction identifier.
    next_tid: u16,
}

/// What happens to an idle session: a queue ended (and why), or Keep Alive is due.
enum Idle {
    Ended(String),
    KeepAliveDue,
}

async fn idle(session: &mut Option<Session>) -> Idle {
    let Some(s) = session.as_mut() else {
        return std::future::pending().await;
    };
    let due = s.next_keep_alive;
    let (queue, item) = tokio::select! {
        p = s.admin.unsolicited() => ("admin", p),
        p = s.io.unsolicited() => ("I/O", p),
        _ = tokio::time::sleep_until(due) => return Idle::KeepAliveDue,
    };
    Idle::Ended(match item {
        None => format!("the target closed the {queue} queue"),
        Some(Err(e)) => format!("the {queue} queue failed: {e}"),
        Some(Ok(p)) if p.kind() == crate::server::nvme_tcp::pdu::kind::C2H_TERM_REQ => format!(
            "the target ended the {queue} queue with C2HTermReq: {}",
            crate::server::nvme_tcp::pdu::fes::name(p.u16_at(8))
        ),
        Some(Ok(p)) => format!(
            "an unexpected {} on the {queue} queue while no command was outstanding",
            crate::server::nvme_tcp::pdu::kind::name(p.kind())
        ),
    })
}

fn controller_json(info: &ControllerInfo, vs: u32, max_transfer: usize) -> Value {
    json!({
        "cntlid": info.cntlid,
        "model": info.model,
        "serial": info.serial,
        "firmware": info.firmware,
        "version": nvme::version_text(if info.version != 0 { info.version } else { vs }),
        "controller_type": info.controller_type(),
        "subsystem_nqn": info.subnqn,
        "mdts_bytes": max_transfer,
        "max_commands": info.maxcmd,
        "namespaces": info.nn,
        "volatile_write_cache": info.vwc & 1 != 0,
        "keep_alive_granularity_ms": info.kas as u32 * 100,
    })
}

impl Host<'_> {
    async fn run(
        &mut self,
        mut external: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        events: mpsc::Sender<(Event, usize)>,
    ) -> Result<()> {
        use crate::state::client_handles::ClientSendOutcome;
        let log = Log::new(Some(&self.ctx.status_tx));
        let protocol = NvmeTcpClientProtocol;
        loop {
            let (action, depth, mut injected) = tokio::select! {
                command = external.recv() => match command {
                    Some(c) => (c.action.clone(), 0, Some(c)),
                    None => return Ok(()),
                },
                action = internal.recv() => match action {
                    Some((a, depth)) => (a, depth, None),
                    None => return Ok(()),
                },
                what = idle(&mut self.session) => {
                    let reason = match what {
                        Idle::Ended(reason) => Some(reason),
                        Idle::KeepAliveDue => match self.session.as_mut() {
                            Some(s) => {
                                s.next_keep_alive = tokio::time::Instant::now() + keep_alive_interval(self.config.kato_ms);
                                match s.admin.keep_alive().await {
                                    Ok(st) if st.is_success() => None,
                                    Ok(st) => Some(format!("Keep Alive failed: {}", st.describe())),
                                    Err(e) => Some(format!("Keep Alive failed: {e:#}")),
                                }
                            }
                            None => None,
                        },
                    };
                    if let Some(reason) = reason {
                        if let Some(s) = self.session.take() {
                            self.raise(&events, &actions::DISCONNECTED_EVENT, json!({"subsystem_nqn": s.subnqn, "reason": reason}), 0)?;
                        }
                    }
                    continue;
                }
            };
            let reply = |injected: &mut Option<crate::state::client_handles::ClientCommand>,
                         outcome: Result<ClientSendOutcome>| {
                if let Some(command) = injected.take() {
                    crate::client::command_support::reply(command, outcome);
                }
            };
            match protocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(&mut injected, Ok(ClientSendOutcome::Disconnected));
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("NVMe/TCP client action refused: {e:#}"));
                    reply(
                        &mut injected,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                    continue;
                }
            }
            if depth > MAX_FOLLOWUP_DEPTH {
                log.warn(format!(
                    "NVMe/TCP client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            if injected.is_some() {
                self.ctx
                    .state
                    .record_access_log(
                        crate::state::AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                        "NVMe-TCP",
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
            }
            let (event, data) = self.execute(&action).await;
            reply(
                &mut injected,
                Ok(ClientSendOutcome::Executed {
                    detail: data.to_string(),
                }),
            );
            self.raise(&events, event, data, depth)?;
        }
    }

    fn raise(
        &self,
        events: &mpsc::Sender<(Event, usize)>,
        event: &'static EventType,
        data: Value,
        depth: usize,
    ) -> Result<()> {
        anyhow::ensure!(
            events.try_send((Event::new(event, data), depth)).is_ok(),
            "NVMe/TCP event queue full; consumer stalled"
        );
        Ok(())
    }

    async fn register(&self, q: &mut QueueConn) {
        if let Some(t) = q.reader_task.take() {
            self.ctx
                .state
                .register_client_task(self.ctx.client_id, t)
                .await;
        }
    }

    /// Run one action; the event to raise and its data.
    async fn execute(&mut self, action: &Value) -> (&'static EventType, Value) {
        let kind = action["type"].as_str().unwrap_or_default();
        match kind {
            actions::DISCOVER => {
                let data = match self.discover().await {
                    Ok(v) => v,
                    Err(e) => json!({"entries": [], "error": format!("{e:#}")}),
                };
                (&actions::DISCOVERY_LOG_EVENT, data)
            }
            actions::CONNECT => (&actions::CONNECT_RESULT_EVENT, self.connect(action).await),
            actions::DISCONNECT => {
                let Some(mut s) = self.session.take() else {
                    return (
                        &actions::DISCONNECTED_EVENT,
                        json!({"subsystem_nqn": "", "reason": "not connected"}),
                    );
                };
                let reason = match host::shutdown(&mut s.admin).await {
                    Ok(()) => "shut down by this host".to_string(),
                    Err(e) => format!("shutdown failed, queues closed anyway: {e:#}"),
                };
                (
                    &actions::DISCONNECTED_EVENT,
                    json!({"subsystem_nqn": s.subnqn, "reason": reason}),
                )
            }
            _ => {
                let operation = kind.trim_start_matches("nvme_tcp_").to_string();
                let mut data = json!({"operation": operation});
                if let Err(e) = self.command(kind, action, &mut data).await {
                    data["error"] = json!(format!("{e:#}"));
                }
                (&actions::COMMAND_RESULT_EVENT, data)
            }
        }
    }

    /// The discovery controller's log: connect, enable, identify, read the log, shut down.
    async fn discover(&mut self) -> Result<Value> {
        let mut q = QueueConn::open(self.addr, 0, &self.config).await?;
        self.register(&mut q).await;
        let c = q
            .connect(
                &self.config,
                nvme::DISCOVERY_NQN,
                nvme::CNTLID_DYNAMIC,
                host::ADMIN_SQSIZE,
            )
            .await?;
        if !c.status().is_success() {
            bail!(
                "the discovery controller refused the Connect: {}",
                host::connect_refusal(&c.cqe)
            );
        }
        let cntlid = (c.cqe.dw0 & 0xFFFF) as u16;
        let (cap, vs, info) = host::enable(&mut q, cntlid).await?;
        let log = host::read_discovery_log(&mut q, cap, &info).await?;
        let _ = host::shutdown(&mut q).await;
        let entries: Vec<Value> = log
            .entries
            .iter()
            .map(|e| {
                json!({
                    "subsystem_nqn": e.subnqn,
                    "transport": e.trtype_name(),
                    "address_family": e.adrfam_name(),
                    "address": e.traddr,
                    "port": e.trsvcid,
                    "subsystem_type": e.subtype_name(),
                    "port_id": e.portid,
                    "controller_id": e.cntlid,
                    "admin_queue_size": e.asqsz,
                    "treq": e.treq,
                })
            })
            .collect();
        Ok(json!({
            "entries": entries,
            "generation": log.generation,
            "controller": {"model": info.model, "serial": info.serial,
                           "version": nvme::version_text(vs), "controller_type": info.controller_type()},
        }))
    }

    async fn connect(&mut self, action: &Value) -> Value {
        let subnqn = action["subsystem_nqn"]
            .as_str()
            .map(str::to_string)
            .or_else(|| self.default_subsystem.clone());
        let Some(subnqn) = subnqn else {
            return json!({"subsystem_nqn": "", "connected": false,
                "error": "no subsystem_nqn: name one, or read the discovery log first"});
        };
        if let Some(s) = &self.session {
            return json!({"subsystem_nqn": subnqn, "connected": false,
                "error": format!("already connected to {}; disconnect first", s.subnqn)});
        }
        match self.open_session(&subnqn).await {
            Ok(Ok(s)) => {
                let data = json!({
                    "subsystem_nqn": subnqn,
                    "connected": true,
                    "controller": {
                        "io_queues": s.io_queues,
                        "digests": s.admin.digests.header,
                        "max_h2c_data": s.io.maxh2cdata,
                        "in_capsule_data": s.io.in_capsule,
                    },
                    "authentication": s.authenticated.as_ref().map(|a| json!({
                        "protocol": "DH-HMAC-CHAP",
                        "hash": a.hash.name(),
                        "dh_group": a.group.name(),
                        "bidirectional": a.bidirectional,
                    })),
                    "namespaces": [],
                });
                let mut data = data;
                let mut ctrl = controller_json(&s.info, s.vs, s.max_transfer);
                if let (Some(c), Some(extra)) =
                    (ctrl.as_object_mut(), data["controller"].as_object())
                {
                    for (k, v) in extra {
                        c.insert(k.clone(), v.clone());
                    }
                }
                data["controller"] = ctrl;
                self.session = Some(s);
                match self.list_namespaces().await {
                    Ok(ids) => data["namespaces"] = json!(ids),
                    Err(e) => data["error"] = json!(format!("listing namespaces: {e:#}")),
                }
                data
            }
            Ok(Err(refusal)) => json!({"subsystem_nqn": subnqn, "connected": false,
                "status": refusal}),
            Err(e) => json!({"subsystem_nqn": subnqn, "connected": false,
                "error": format!("{e:#}")}),
        }
    }

    /// Connect an admin queue and an I/O queue. `Ok(Err(status))`: the target refused.
    async fn open_session(&mut self, subnqn: &str) -> Result<Result<Session, String>> {
        let mut admin = QueueConn::open(self.addr, 0, &self.config).await?;
        self.register(&mut admin).await;
        let c = admin
            .connect(
                &self.config,
                subnqn,
                nvme::CNTLID_DYNAMIC,
                host::ADMIN_SQSIZE,
            )
            .await?;
        if !c.status().is_success() {
            return Ok(Err(host::connect_refusal(&c.cqe)));
        }
        let cntlid = (c.cqe.dw0 & 0xFFFF) as u16;
        let authenticated = match self.authenticate(&mut admin, c.cqe.dw0, subnqn).await {
            Ok(a) => a,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let (cap, vs, info) = host::enable(&mut admin, cntlid).await?;
        anyhow::ensure!(
            info.cntrltype != 2,
            "{subnqn} is a discovery controller; read it with nvme_tcp_discover"
        );
        anyhow::ensure!(
            info.icdoff == 0,
            "the controller puts in-capsule data at offset {} (this host sends it at 0)",
            info.icdoff
        );
        anyhow::ensure!(
            info.sgls & 0x3 != 0,
            "the controller does not support SGLs, which NVMe over Fabrics requires"
        );
        let io_queues = host::set_queue_count(&mut admin, 1).await?;
        anyhow::ensure!(io_queues >= 1, "the controller granted no I/O queue");
        let mqes = (cap & 0xFFFF) as u16;
        let mut io = QueueConn::open(self.addr, 1, &self.config).await?;
        self.register(&mut io).await;
        io.in_capsule = (info.ioccsz as usize * 16).saturating_sub(64);
        let c = io
            .connect(&self.config, subnqn, cntlid, host::IO_SQSIZE.min(mqes))
            .await?;
        if !c.status().is_success() {
            let _ = host::shutdown(&mut admin).await;
            return Ok(Err(format!(
                "the I/O queue's Connect: {}",
                host::connect_refusal(&c.cqe)
            )));
        }
        // nvmet authenticates the admin queue only; a target that asks it of I/O queues too
        // gets it there as well.
        if let Err(refusal) = self.authenticate(&mut io, c.cqe.dw0, subnqn).await {
            let _ = host::shutdown(&mut admin).await;
            return Ok(Err(format!("the I/O queue: {refusal}")));
        }
        let max_transfer = host::max_transfer(cap, info.mdts);
        Ok(Ok(Session {
            subnqn: subnqn.to_string(),
            admin,
            io,
            info,
            vs,
            max_transfer,
            io_queues,
            block_sizes: HashMap::new(),
            next_keep_alive: tokio::time::Instant::now() + keep_alive_interval(self.config.kato_ms),
            authenticated,
        }))
    }

    /// Authenticate a queue whose Connect completion (`dw0`) asks for it. `Ok(None)`: it was
    /// not asked; `Err`: why it failed, as the result reports it.
    async fn authenticate(
        &mut self,
        q: &mut QueueConn,
        dw0: u32,
        subnqn: &str,
    ) -> std::result::Result<Option<host::Authenticated>, String> {
        if dw0 & auth::CONNECT_ASCR != 0 {
            return Err(
                "the target requires secure channel concatenation (AUTHREQ.ASCR), which needs \
                 TLS; this host has none"
                    .into(),
            );
        }
        if dw0 & auth::CONNECT_ATR == 0 {
            return Ok(None);
        }
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);
        let log = Log::new(Some(&self.ctx.status_tx));
        match q.authenticate(&self.config, subnqn, tid).await {
            Ok(a) => {
                log.info(format!(
                    "NVMe/TCP client: queue {} authenticated to {subnqn} ({}, {}{})",
                    q.qid,
                    a.hash.name(),
                    a.group.name(),
                    if a.bidirectional { ", both ways" } else { "" }
                ));
                Ok(Some(a))
            }
            Err(e) => {
                log.warn(format!(
                    "NVMe/TCP client: queue {} failed authentication to {subnqn}: {e:#}",
                    q.qid
                ));
                Err(format!("AUTHENTICATION FAILED: {e:#}"))
            }
        }
    }

    fn session(&mut self) -> Result<&mut Session> {
        self.session
            .as_mut()
            .context("not connected: run nvme_tcp_connect first")
    }

    /// A failure inside a command ends the session: nothing on those queues can be trusted.
    fn ended<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            self.session = None;
        }
        r.map_err(|e| e.context("the controller's queues were closed"))
    }

    async fn list_namespaces(&mut self) -> Result<Vec<u32>> {
        let s = self.session()?;
        let r = s.admin.identify(cns::ACTIVE_NAMESPACES, 0).await;
        let c = self.ended(r)?;
        anyhow::ensure!(
            c.status().is_success(),
            "Identify (active namespaces): {}",
            c.status().describe()
        );
        Ok(nvme::parse_ns_list(&c.data))
    }

    /// The block size of a namespace, from Identify Namespace when not yet known.
    async fn block_size(&mut self, nsid: u32) -> Result<u32> {
        if let Some(b) = self.session()?.block_sizes.get(&nsid) {
            return Ok(*b);
        }
        let s = self.session()?;
        let r = host::identify_namespace(&mut s.admin, nsid).await;
        let (status, info) = self.ended(r)?;
        let Some(info) = info else {
            bail!("Identify Namespace {nsid}: {}", status.describe());
        };
        anyhow::ensure!(
            info.nsze > 0 && (512..=65536).contains(&info.block_size),
            "namespace {nsid} is not active (or reports a block size of {})",
            info.block_size
        );
        let bs = info.block_size as u32;
        self.session()?.block_sizes.insert(nsid, bs);
        Ok(bs)
    }

    async fn command(&mut self, kind: &str, action: &Value, data: &mut Value) -> Result<()> {
        self.session()?;
        match kind {
            actions::IDENTIFY_CONTROLLER => {
                let s = self.session()?;
                let r = s.admin.identify(cns::CONTROLLER, 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
                if c.status().is_success() {
                    let info = ControllerInfo::decode(&c.data).context("a short Identify")?;
                    let s = self.session()?;
                    data["controller"] = controller_json(&info, s.vs, s.max_transfer);
                }
            }
            actions::LIST_NAMESPACES => {
                let ids = self.list_namespaces().await?;
                data["status"] = json!("SUCCESS");
                data["namespaces"] = json!(ids);
            }
            actions::IDENTIFY_NAMESPACE => {
                let nsid = actions::nsid_of(action)?;
                data["nsid"] = json!(nsid);
                let s = self.session()?;
                let r = host::identify_namespace(&mut s.admin, nsid).await;
                let (status, info) = self.ended(r)?;
                data["status"] = json!(status.describe());
                if let Some(info) = info {
                    let s = self.session()?;
                    let r = s.admin.identify(cns::NAMESPACE_DESCRIPTORS, nsid).await;
                    let d = self.ended(r)?;
                    let descriptors: Vec<Value> = if d.status().is_success() {
                        nvme::parse_ns_descriptors(&d.data)
                            .into_iter()
                            .map(|(t, v)| json!({"type": t, "value": v}))
                            .collect()
                    } else {
                        vec![]
                    };
                    if info.nsze > 0 {
                        self.session()?
                            .block_sizes
                            .insert(nsid, info.block_size as u32);
                    }
                    data["namespace"] = json!({
                        "active": info.nsze > 0,
                        "blocks": info.nsze,
                        "block_size": info.block_size,
                        "size_bytes": info.nsze.saturating_mul(info.block_size),
                        "write_protected": info.write_protected,
                        "shared": info.shared,
                        "nguid": hex::encode(info.nguid),
                        "eui64": hex::encode(info.eui64),
                        "descriptors": descriptors,
                    });
                }
            }
            actions::READ => {
                let nsid = actions::nsid_of(action)?;
                let bs = self.block_size(nsid).await?;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let blocks = action["blocks"].as_u64().unwrap_or(1) as usize;
                let len = blocks * bs as usize;
                anyhow::ensure!(
                    len <= actions::MAX_TRANSFER,
                    "{blocks} blocks of {bs} bytes is more than {} bytes",
                    actions::MAX_TRANSFER
                );
                data["nsid"] = json!(nsid);
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let sqe = host::rw_sqe(nvme::io::READ, nsid, lba, blocks as u32);
                let s = self.session()?;
                let r = s.io.exec(sqe, None, len).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
                if c.status().is_success() {
                    anyhow::ensure!(
                        c.data.len() == len,
                        "the read brought back {} bytes of {len}",
                        c.data.len()
                    );
                    let (text, encoding, zeros) =
                        crate::client::iscsi::render_data(&c.data, action["encoding"] == "hex");
                    data["data"] = json!(text);
                    data["encoding"] = json!(encoding);
                    data["bytes"] = json!(c.data.len());
                    if encoding == "utf8" {
                        data["trailing_zero_bytes"] = json!(zeros);
                    }
                }
            }
            actions::WRITE => {
                let nsid = actions::nsid_of(action)?;
                let bs = self.block_size(nsid).await? as usize;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let mut bytes = actions::write_data(action)?;
                bytes.resize(bytes.len().div_ceil(bs) * bs, 0);
                anyhow::ensure!(
                    bytes.len() <= actions::MAX_TRANSFER,
                    "the padded write is more than {} bytes",
                    actions::MAX_TRANSFER
                );
                let blocks = (bytes.len() / bs) as u32;
                data["nsid"] = json!(nsid);
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let sqe = host::rw_sqe(nvme::io::WRITE, nsid, lba, blocks);
                let s = self.session()?;
                let r = s.io.exec(sqe, Some(&bytes), 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
                if c.status().is_success() {
                    data["bytes"] = json!(bytes.len());
                }
            }
            actions::WRITE_ZEROES => {
                let nsid = actions::nsid_of(action)?;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let blocks = action["blocks"].as_u64().unwrap_or(1);
                data["nsid"] = json!(nsid);
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let sqe = host::rw_sqe(nvme::io::WRITE_ZEROES, nsid, lba, blocks as u32);
                let s = self.session()?;
                let r = s.io.exec(sqe, None, 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
            }
            actions::FLUSH => {
                let nsid = actions::nsid_of(action)?;
                data["nsid"] = json!(nsid);
                let mut sqe = nvme::Sqe::new(nvme::io::FLUSH, 0);
                sqe.set_nsid(nsid);
                let s = self.session()?;
                let r = s.io.exec(sqe, None, 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
            }
            actions::GET_LOG_PAGE => {
                let page = action["page"].as_str().unwrap_or("smart");
                data["page"] = json!(page);
                let (lid, len) = match page {
                    "error" => (nvme::log::ERROR, 64),
                    "firmware_slot" => (nvme::log::FIRMWARE_SLOT, 512),
                    "changed_namespaces" => (nvme::log::CHANGED_NAMESPACES, 4096),
                    _ => (nvme::log::SMART, 512),
                };
                let s = self.session()?;
                let r = s.admin.get_log_page(lid, 0xFFFF_FFFF, 0, len).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe());
                if c.status().is_success() {
                    data["log"] = log_json(page, &c.data);
                }
            }
            actions::COMPARE => {
                let nsid = actions::nsid_of(action)?;
                let bs = self.block_size(nsid).await? as usize;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let mut bytes = actions::write_data(action)?;
                bytes.resize(bytes.len().div_ceil(bs) * bs, 0);
                anyhow::ensure!(
                    bytes.len() <= actions::MAX_TRANSFER,
                    "the padded data is more than {} bytes",
                    actions::MAX_TRANSFER
                );
                let blocks = (bytes.len() / bs) as u32;
                data["nsid"] = json!(nsid);
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let sqe = host::rw_sqe(nvme::io::COMPARE, nsid, lba, blocks);
                let s = self.session()?;
                let r = s.io.exec(sqe, Some(&bytes), 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe_io());
                data["matches"] = json!(c.status().is_success());
            }
            actions::VERIFY => {
                let nsid = actions::nsid_of(action)?;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let blocks = action["blocks"].as_u64().unwrap_or(1);
                data["nsid"] = json!(nsid);
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let sqe = host::rw_sqe(nvme::io::VERIFY, nsid, lba, blocks as u32);
                let s = self.session()?;
                let r = s.io.exec(sqe, None, 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe_io());
            }
            actions::COPY => {
                let nsid = actions::nsid_of(action)?;
                let destination = action["destination_lba"]
                    .as_u64()
                    .context("destination_lba is a number")?;
                let ranges = actions::copy_ranges_of(action)?;
                data["nsid"] = json!(nsid);
                data["destination_lba"] = json!(destination);
                data["ranges"] = json!(ranges.len());
                let mut descriptors = Vec::new();
                for (lba, blocks) in &ranges {
                    descriptors.extend(nvme::copy_range(*lba, *blocks));
                }
                let mut sqe = nvme::Sqe::new(nvme::io::COPY, 0);
                sqe.set_nsid(nsid);
                sqe.set_u64(40, destination);
                sqe.set_cdw(12, (ranges.len() - 1) as u32);
                let s = self.session()?;
                let r = s.io.exec(sqe, Some(&descriptors), 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe_io());
            }
            actions::RESERVATION_REGISTER
            | actions::RESERVATION_ACQUIRE
            | actions::RESERVATION_RELEASE => {
                let nsid = actions::nsid_of(action)?;
                let (opcode, cdw10, payload) = actions::reservation_command(kind, action)?;
                data["nsid"] = json!(nsid);
                data["action"] = action["action"].clone();
                if !action["reservation_type"].is_null() {
                    data["reservation_type"] = action["reservation_type"].clone();
                }
                let mut sqe = nvme::Sqe::new(opcode, 0);
                sqe.set_nsid(nsid);
                sqe.set_cdw(10, cdw10);
                let s = self.session()?;
                let r = s.io.exec(sqe, Some(&payload), 0).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe_io());
            }
            actions::RESERVATION_REPORT => {
                let nsid = actions::nsid_of(action)?;
                data["nsid"] = json!(nsid);
                let len = actions::REPORT_LEN;
                let mut sqe = nvme::Sqe::new(nvme::io::RESV_REPORT, 0);
                sqe.set_nsid(nsid);
                sqe.set_cdw(10, (len / 4 - 1) as u32);
                sqe.set_cdw(11, 1); // the extended data structure: 128-bit host identifiers
                let s = self.session()?;
                let r = s.io.exec(sqe, None, len).await;
                let c = self.ended(r)?;
                data["status"] = json!(c.status().describe_io());
                if c.status().is_success() {
                    let report = crate::server::nvme_tcp::resv::Report::decode(&c.data)
                        .context("a short reservation report")?;
                    data["reservation"] = host::reservation_json(&report);
                }
            }
            other => bail!("unknown operation {other}"),
        }
        Ok(())
    }
}

/// How often Keep Alive goes out: a third of KATO, so two can be lost before it expires.
fn keep_alive_interval(kato_ms: u32) -> Duration {
    Duration::from_millis((kato_ms / 3).max(500) as u64)
}

/// A log page's fields, as the model reads them.
fn log_json(page: &str, b: &[u8]) -> Value {
    match page {
        "smart" => match Smart::decode(b) {
            Some(s) => json!({
                "critical_warning": s.critical_warning,
                "temperature_celsius": s.temperature_kelvin as i32 - 273,
                "available_spare_percent": s.available_spare,
                "percentage_used": s.percentage_used,
                "data_units_read": s.data_units_read.to_string(),
                "data_units_written": s.data_units_written.to_string(),
                "host_read_commands": s.host_read_commands.to_string(),
                "host_write_commands": s.host_write_commands.to_string(),
                "power_on_hours": s.power_on_hours.to_string(),
                "media_errors": s.media_errors.to_string(),
            }),
            None => json!({"error": "a short SMART log"}),
        },
        "error" => {
            let count = b
                .get(0..8)
                .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
                .unwrap_or(0);
            json!({"newest_error_count": count, "status": if count == 0 { "no errors logged" } else { "errors logged" }})
        }
        "firmware_slot" => json!({
            "active_slot": b.first().map_or(0, |a| a & 0x7),
            "slot1": b.get(8..16).map(nvme::text_field).unwrap_or_default(),
        }),
        _ => json!({"changed_namespaces": nvme::parse_ns_list(b)}),
    }
}
