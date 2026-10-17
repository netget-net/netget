//! LoRaWAN gateway: a Semtech UDP packet forwarder that carries simulated LoRaWAN 1.0.x
//! devices to a network server. NetGet keeps the forwarder's side (keepalives, stat, acks,
//! TX_ACK) and every device's side (DevNonce, session keys, counters, MIC, encryption); the
//! model decides which device says what.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::lorawan::semtech::{Packet, Rxpk, Txpk};
use crate::server::lorawan::{self as ns, actions::payload_field, mac, region, semtech};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use crate::utils::clock::Instant;
pub use actions::LorawanClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const MAX_FOLLOWUP_DEPTH: usize = 8;
/// How long the first PULL_DATA may go unacknowledged before connecting fails.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// DevNonces remembered per device so a fresh Join Request never reuses one.
const MAX_NONCES: usize = 256;

struct DeviceState {
    config: ns::DeviceConfig,
    used_nonces: Vec<u16>,
    pending_join: Option<u16>,
    /// How deep in a handler chain the device's last frame was sent: the network's answer to
    /// it continues that chain, so the follow-up bound holds across the air.
    chain_depth: usize,
    session: Option<Session>,
}

struct Session {
    dev_addr: u32,
    nwk: mac::Key,
    app: mac::Key,
    fcnt_up: u32,
    fcnt_down: Option<u32>,
    /// A confirmed downlink arrived: the next uplink carries ACK.
    ack_due: bool,
    /// The network asked DevStatusReq: the next uplink answers.
    status_due: bool,
}

impl DeviceState {
    fn label(&self) -> String {
        self.config
            .name
            .clone()
            .or_else(|| self.config.dev_eui.as_ref().map(mac::eui_hex))
            .or_else(|| self.session.as_ref().map(|s| mac::dev_addr_hex(s.dev_addr)))
            .unwrap_or_default()
    }
    fn matches(&self, name: &str) -> bool {
        self.config.name.as_deref() == Some(name)
            || self
                .config
                .dev_eui
                .is_some_and(|e| mac::eui_hex(&e).eq_ignore_ascii_case(name))
    }
}

struct Settings {
    gateway: mac::Eui,
    keepalive: Duration,
    stat_interval: Duration,
    devices: Vec<ns::DeviceConfig>,
}

fn settings(ctx: &ConnectContext) -> Result<Settings> {
    let p = ctx.startup_params.as_ref();
    if let Some(r) = p
        .map(|p| p.get_optional_string("region"))
        .transpose()?
        .flatten()
    {
        region::check_region(&r)?;
    }
    let gateway = mac::parse_eui(
        "gateway_eui",
        &p.map(|p| p.get_optional_string("gateway_eui"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| actions::DEFAULT_GATEWAY_EUI.into()),
    )?;
    let keepalive = p
        .map(|p| p.get_optional_u64("keepalive_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_KEEPALIVE_SECS);
    ensure!((1..=300).contains(&keepalive), "keepalive_secs is 1..=300");
    let stat = p
        .map(|p| p.get_optional_u64("stat_interval_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_STAT_INTERVAL_SECS);
    ensure!((1..=3600).contains(&stat), "stat_interval_secs is 1..=3600");
    let devices = match p
        .map(|p| p.get_optional_array("devices"))
        .transpose()?
        .flatten()
    {
        Some(list) => ns::parse_devices(list)?,
        None => bail!("devices is required: the gateway carries configured devices only"),
    };
    Ok(Settings {
        gateway,
        keepalive: Duration::from_secs(keepalive),
        stat_interval: Duration::from_secs(stat),
        devices,
    })
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let settings = settings(&ctx)?;
    let server: SocketAddr = tokio::net::lookup_host(&ctx.remote_addr)
        .await?
        .next()
        .context("the network server's address does not resolve")?;
    let bind: SocketAddr = match (server.is_ipv4(), server.ip().is_loopback()) {
        (true, true) => "127.0.0.1:0".parse()?,
        (true, false) => "0.0.0.0:0".parse()?,
        (false, true) => "[::1]:0".parse()?,
        (false, false) => "[::]:0".parse()?,
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    let local = socket.local_addr()?;
    // The first PULL_DATA must be acknowledged: that is the network server saying it is there.
    let token: u16 = rand::random();
    socket
        .send(&semtech::encode(&Packet::PullData {
            version: semtech::PROTOCOL_VERSION,
            token,
            gateway: settings.gateway,
        })?)
        .await?;
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut buf = vec![0u8; semtech::MAX_DATAGRAM + 1];
        loop {
            let n = socket.recv(&mut buf).await?;
            if let Ok(Packet::PullAck { token: t, .. }) = semtech::parse(&buf[..n]) {
                if t == token {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }
    })
    .await
    .context("the network server did not acknowledge PULL_DATA")??;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(64);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(64);
    let devices: Vec<DeviceState> = settings
        .devices
        .iter()
        .map(|d| DeviceState {
            config: d.clone(),
            used_nonces: Vec::new(),
            pending_join: None,
            chain_depth: 0,
            session: d.abp.map(|(dev_addr, nwk, app)| Session {
                dev_addr,
                nwk,
                app,
                fcnt_up: 0,
                fcnt_down: None,
                ack_due: false,
                status_due: false,
            }),
        })
        .collect();
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "network_server": server.to_string(),
                "gateway_eui": mac::eui_hex(&settings.gateway),
                "devices": devices.iter().map(|d| json!({
                    "name": d.config.name,
                    "dev_eui": d.config.dev_eui.as_ref().map(mac::eui_hex),
                    "activation": if d.config.abp.is_some() { "abp" } else { "otaa" },
                    "has_session": d.session.is_some(),
                })).collect::<Vec<_>>(),
            }),
        ),
        0,
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        while let Some((event, depth)) = event_rx.recv().await {
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                &LorawanClientProtocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx)).warn(format!(
                    "LoRaWAN gateway handler failed; nothing sent: {e}"
                )),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut g = Gateway {
            ctx: &session_ctx,
            socket,
            eui: settings.gateway,
            devices,
            started: Instant::now(),
            events: event_tx,
            rxnb: 0,
            txnb: 0,
            dwnb: 0,
            pushed: 0,
            push_acked: 0,
            pull_token: token,
            unanswered_pulls: 0,
        };
        let result = g
            .run(
                external,
                internal_rx,
                settings.keepalive,
                settings.stat_interval,
            )
            .await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx))
                    .warn(format!("LoRaWAN gateway ended: {e:#}"));
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

struct Gateway<'a> {
    ctx: &'a ConnectContext,
    socket: UdpSocket,
    eui: mac::Eui,
    devices: Vec<DeviceState>,
    started: Instant,
    events: mpsc::Sender<(Event, usize)>,
    rxnb: u32,
    txnb: u32,
    dwnb: u32,
    pushed: u32,
    push_acked: u32,
    pull_token: u16,
    unanswered_pulls: u32,
}

fn reply(caller: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = caller {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

impl Gateway<'_> {
    /// The concentrator's free-running microsecond counter.
    fn tmst(&self) -> u32 {
        self.started.elapsed().as_micros() as u32
    }

    async fn run(
        &mut self,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        keepalive: Duration,
        stat_interval: Duration,
    ) -> Result<()> {
        let log = Log::new(Some(&self.ctx.status_tx));
        let mut buf = vec![0u8; semtech::MAX_DATAGRAM + 1];
        let mut keepalive = tokio::time::interval(keepalive);
        keepalive.tick().await;
        let mut stat = tokio::time::interval(stat_interval);
        loop {
            let (action, depth, caller) = tokio::select! {
                r = self.socket.recv(&mut buf) => {
                    let n = r?;
                    let d = buf[..n].to_vec();
                    if let Err(e) = self.incoming(&d).await {
                        log.debug(format!("LoRaWAN datagram from the network server ignored: {e:#}"));
                    }
                    continue;
                }
                _ = keepalive.tick() => {
                    self.unanswered_pulls += 1;
                    if self.unanswered_pulls == 4 {
                        log.warn("LoRaWAN: the network server has not acknowledged 3 PULL_DATA keepalives");
                    }
                    self.pull_token = rand::random();
                    self.socket.send(&semtech::encode(&Packet::PullData {
                        version: semtech::PROTOCOL_VERSION, token: self.pull_token, gateway: self.eui,
                    })?).await?;
                    continue;
                }
                _ = stat.tick() => {
                    self.send_stat().await?;
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => (c.action.clone(), 0, Some(c)),
                    None => return Ok(()),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return Ok(()),
                },
            };
            match LorawanClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(caller, ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("LoRaWAN action refused: {e:#}"));
                    reply(
                        caller,
                        ClientSendOutcome::Rejected {
                            error: format!("{e:#}"),
                        },
                    );
                    continue;
                }
            }
            if depth > MAX_FOLLOWUP_DEPTH {
                log.warn(format!(
                    "LoRaWAN gateway: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            if caller.is_some() {
                self.ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                        "LoRaWAN",
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
            }
            match self.act(&action, depth).await {
                Ok(bytes_sent) => reply(caller, ClientSendOutcome::Sent { bytes_sent }),
                Err(e) => {
                    log.warn(format!("LoRaWAN action refused: {e:#}"));
                    reply(
                        caller,
                        ClientSendOutcome::Rejected {
                            error: format!("{e:#}"),
                        },
                    );
                }
            }
        }
    }

    async fn send_stat(&mut self) -> Result<()> {
        let ackr = if self.pushed == 0 {
            100.0
        } else {
            100.0 * self.push_acked as f64 / self.pushed as f64
        };
        let stat = semtech::Stat {
            time: Some(
                chrono::Utc::now()
                    .format("%Y-%m-%d %H:%M:%S GMT")
                    .to_string(),
            ),
            rxnb: Some(self.rxnb),
            rxok: Some(self.rxnb),
            rxfw: Some(self.rxnb),
            ackr: Some(ackr),
            dwnb: Some(self.dwnb),
            txnb: Some(self.txnb),
            ..Default::default()
        };
        self.push(Vec::new(), Some(stat)).await.map(|_| ())
    }

    async fn push(&mut self, rxpk: Vec<Rxpk>, stat: Option<semtech::Stat>) -> Result<usize> {
        let bytes = semtech::encode(&Packet::PushData {
            version: semtech::PROTOCOL_VERSION,
            token: rand::random(),
            gateway: self.eui,
            rxpk,
            stat,
        })?;
        self.socket.send(&bytes).await?;
        self.pushed += 1;
        Ok(bytes.len())
    }

    fn device_index(&self, name: &str) -> Result<usize> {
        self.devices
            .iter()
            .position(|d| d.matches(name))
            .with_context(|| format!("no configured device is called {name}"))
    }

    /// Carry one device frame to the network server.
    async fn act(&mut self, v: &Value, depth: usize) -> Result<usize> {
        let (freq, dr, rssi, snr) = actions::radio_of(v)?;
        let i = self.device_index(v["device"].as_str().unwrap_or_default())?;
        self.devices[i].chain_depth = depth;
        let phy = match v["type"].as_str().unwrap_or_default() {
            actions::SEND_JOIN => {
                let d = &mut self.devices[i];
                let (Some(dev_eui), Some(app_key)) = (d.config.dev_eui, d.config.app_key) else {
                    bail!("{} is an ABP device: it does not join", d.label());
                };
                ensure!(
                    d.used_nonces.len() < MAX_NONCES,
                    "{} has used {MAX_NONCES} DevNonces",
                    d.label()
                );
                let nonce = loop {
                    let n: u16 = rand::random();
                    if !d.used_nonces.contains(&n) {
                        break n;
                    }
                };
                d.used_nonces.push(nonce);
                d.pending_join = Some(nonce);
                mac::encode_join_request(
                    &mac::JoinRequest {
                        app_eui: d.config.app_eui,
                        dev_eui,
                        dev_nonce: nonce,
                    },
                    &app_key,
                )
            }
            actions::SEND_UPLINK => {
                let d = &mut self.devices[i];
                let label = d.label();
                let s = d
                    .session
                    .as_mut()
                    .with_context(|| format!("{label} has not joined: send a Join Request first"))?;
                let port = ns::actions::port_of(v)?;
                let payload = ns::actions::payload_bytes(v)?;
                let confirmed = ns::actions::confirmed_of(v)?;
                let mut f_opts = Vec::new();
                if v["link_check"].as_bool().unwrap_or(false) {
                    f_opts.push(mac::CID_LINK_CHECK);
                }
                if s.status_due {
                    f_opts.extend(mac::dev_status_ans(actions::battery_of(v)?, snr.round() as i8));
                }
                let max = region::max_frm_payload(dr, f_opts.len());
                ensure!(
                    payload.len() <= max,
                    "a {}-byte payload does not fit DR{dr} ({max} bytes)",
                    payload.len()
                );
                let phy = mac::encode_data(
                    &mac::OutFrame {
                        mtype: if confirmed {
                            mac::MTYPE_CONFIRMED_UP
                        } else {
                            mac::MTYPE_UNCONFIRMED_UP
                        },
                        dev_addr: s.dev_addr,
                        adr: false,
                        adr_ack_req: false,
                        ack: s.ack_due,
                        f_pending: false,
                        f_cnt: s.fcnt_up,
                        f_opts: &f_opts,
                        f_port: Some(port),
                        payload: &payload,
                    },
                    &s.nwk,
                    &s.app,
                )?;
                s.fcnt_up = s.fcnt_up.wrapping_add(1);
                s.ack_due = false;
                s.status_due = false;
                phy
            }
            other => bail!("{other} is not a device frame"),
        };
        let rxpk = Rxpk {
            time: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            tmms: None,
            tmst: Some(self.tmst()),
            freq: region::mhz(freq),
            chan: 0,
            rfch: 0,
            stat: 1,
            modu: "LORA".into(),
            datr: json!(region::data_rate_name(dr)?),
            codr: Some("4/5".into()),
            rssi,
            lsnr: snr,
            size: phy.len() as u32,
            data: semtech::b64_encode(&phy),
        };
        self.rxnb += 1;
        self.push(vec![rxpk], None).await
    }

    async fn incoming(&mut self, d: &[u8]) -> Result<()> {
        match semtech::parse(d)? {
            Packet::PushAck { .. } => self.push_acked += 1,
            Packet::PullAck { token, .. } => {
                if token == self.pull_token {
                    self.unanswered_pulls = 0;
                }
            }
            Packet::PullResp {
                version,
                token,
                txpk,
            } => {
                self.dwnb += 1;
                let error = self.tx_error(&txpk);
                if version >= 2 {
                    self.socket
                        .send(&semtech::encode(&Packet::TxAck {
                            version,
                            token,
                            gateway: self.eui,
                            error: Some(error.into()),
                        })?)
                        .await?;
                }
                if error != "NONE" {
                    Log::new(Some(&self.ctx.status_tx)).warn(format!(
                        "LoRaWAN downlink refused with TX_ACK {error}: {}",
                        serde_json::to_string(&txpk).unwrap_or_default()
                    ));
                    return Ok(());
                }
                self.txnb += 1;
                self.downlink(&txpk)?;
            }
            other => bail!("{other:?} is not sent to a gateway"),
        }
        Ok(())
    }

    /// Whether a real concentrator would transmit this (PROTOCOL.TXT §6 error codes).
    fn tx_error(&self, txpk: &Txpk) -> &'static str {
        let Ok(freq) = region::hz(txpk.freq) else {
            return "TX_FREQ";
        };
        if !region::in_band(freq) {
            return "TX_FREQ";
        }
        if txpk.powe.is_some_and(|p| p > region::MAX_TX_POWER_DBM) {
            return "TX_POWER";
        }
        if !txpk.imme {
            match txpk.tmst {
                // A wrapping comparison: in the past by less than half the counter's range.
                Some(t) if (t.wrapping_sub(self.tmst()) as i32) < 0 => return "TOO_LATE",
                Some(_) => {}
                // Neither immediate nor timed: GPS time (tmms) needs a GPS this gateway lacks.
                None => return "GPS_UNLOCKED",
            }
        }
        "NONE"
    }

    fn downlink(&mut self, txpk: &Txpk) -> Result<()> {
        let phy = semtech::b64_decode(&txpk.data)?;
        let log = Log::new(Some(&self.ctx.status_tx));
        let events = self.events.clone();
        let raise = |event: Event, depth: usize| {
            events
                .try_send((event, depth))
                .context("LoRaWAN event queue full; consumer stalled")
        };
        match mac::mtype_of(&phy)? {
            mac::MTYPE_JOIN_ACCEPT => {
                for d in self.devices.iter_mut() {
                    let (Some(nonce), Some(app_key)) = (d.pending_join, d.config.app_key) else {
                        continue;
                    };
                    let Ok(ja) = mac::decode_join_accept(&phy, &app_key) else {
                        continue;
                    };
                    let (nwk, app) = mac::session_keys(&app_key, ja.app_nonce, ja.net_id, nonce);
                    d.pending_join = None;
                    d.session = Some(Session {
                        dev_addr: ja.dev_addr,
                        nwk,
                        app,
                        fcnt_up: 0,
                        fcnt_down: None,
                        ack_due: false,
                        status_due: false,
                    });
                    let label = d.label();
                    log.info(format!(
                        "LoRaWAN {label} joined as {}",
                        mac::dev_addr_hex(ja.dev_addr)
                    ));
                    return raise(Event::new(
                        &actions::JOINED_EVENT,
                        json!({
                            "device": label,
                            "dev_eui": d.config.dev_eui.as_ref().map(mac::eui_hex),
                            "dev_addr": mac::dev_addr_hex(ja.dev_addr),
                            "net_id": format!("{:06x}", ja.net_id),
                            "rx1_dr_offset": ja.rx1_dr_offset,
                            "rx2_data_rate": ja.rx2_data_rate,
                            "rx_delay": ja.rx_delay,
                        }),
                    ), d.chain_depth);
                }
                log.warn("LoRaWAN Join Accept for no device with a pending join (or its MIC does not verify)");
                Ok(())
            }
            mac::MTYPE_UNCONFIRMED_DOWN | mac::MTYPE_CONFIRMED_DOWN => {
                let frame = mac::parse_data(&phy)?;
                let Some(d) = self
                    .devices
                    .iter_mut()
                    .find(|d| d.session.as_ref().is_some_and(|s| s.dev_addr == frame.dev_addr))
                else {
                    log.debug(format!(
                        "LoRaWAN downlink for DevAddr {} (no device here)",
                        mac::dev_addr_hex(frame.dev_addr)
                    ));
                    return Ok(());
                };
                let depth = d.chain_depth;
                let label = d.label();
                let s = d.session.as_mut().expect("found by session");
                let full = match mac::classify_fcnt(s.fcnt_down, frame.f_cnt) {
                    mac::FcntCheck::Fresh(f) => f,
                    other => {
                        log.warn(format!("LoRaWAN downlink to {label} dropped: counter {other:?}"));
                        return Ok(());
                    }
                };
                if !mac::data_mic_ok(&phy, &s.nwk, mac::DIR_DOWN, frame.dev_addr, full) {
                    log.warn(format!("LoRaWAN downlink to {label} dropped: MIC does not verify"));
                    return Ok(());
                }
                s.fcnt_down = Some(full);
                let key = if frame.f_port == Some(0) { s.nwk } else { s.app };
                let plain =
                    mac::crypt_frm(&key, mac::DIR_DOWN, frame.dev_addr, full, &frame.frm_payload);
                let (payload, commands) = if frame.f_port == Some(0) {
                    (Vec::new(), mac::decode_mac_commands(&plain, false))
                } else {
                    (plain, mac::decode_mac_commands(&frame.f_opts, false))
                };
                if frame.confirmed() {
                    s.ack_due = true;
                }
                if commands.iter().any(|c| c["command"] == "dev_status_req") {
                    s.status_due = true;
                }
                let (payload, encoding) = payload_field(&payload);
                let data_rate = txpk.datr.as_str().unwrap_or_default().to_string();
                raise(Event::new(
                    &actions::DOWNLINK_EVENT,
                    json!({
                        "device": label,
                        "dev_addr": mac::dev_addr_hex(frame.dev_addr),
                        "confirmed": frame.confirmed(),
                        "f_cnt": full,
                        "f_port": frame.f_port,
                        "payload": payload,
                        "payload_encoding": encoding,
                        "mac_commands": commands,
                        "ack": frame.ack,
                        "f_pending": frame.f_pending,
                        "frequency_mhz": txpk.freq,
                        "data_rate": data_rate,
                        "immediate": txpk.imme,
                    }),
                ), depth)
            }
            other => bail!("a {} in a PULL_RESP", mac::mtype_name(other)),
        }
    }
}
