//! LoRaWAN 1.0.x network server over the Semtech UDP packet-forwarder protocol.
//!
//! Gateways (packet forwarders) push the frames they heard; NetGet acknowledges every
//! datagram, verifies each frame's MIC with the keys from configuration, refuses replayed
//! counters and reused DevNonces, decrypts, and only then asks the model — whether a device
//! may join, and what to send it back. NetGet builds, encrypts, signs and schedules every
//! downlink on the gateway that heard the uplink (PULL_RESP), in RX1 or RX2 per EU868.
//!
//! No radio: the packet forwarder owns the radio, NetGet speaks to the forwarder.
pub mod actions;
pub mod mac;
pub mod region;
pub mod semtech;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use actions::LorawanProtocol;
use anyhow::{bail, ensure, Context, Result};
use mac::{Eui, Key};
use semtech::{Packet, Rxpk, Txpk};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};

pub const DEFAULT_NET_ID: &str = "000000";
pub const MAX_DEVICES: usize = 256;
pub const MAX_GATEWAYS: usize = 64;
/// Application downlinks waiting for a device's next uplink.
pub const MAX_QUEUED_DOWNLINKS: usize = 8;
/// Model calls running at once; an uplink past this is dropped (logged), as a busy network
/// server's would be: the device retransmits or sends the next reading.
pub const MAX_IN_FLIGHT: usize = 16;
/// DevNonces remembered per device to refuse a replayed Join Request.
pub const MAX_NONCES: usize = 256;
/// A gateway that sends nothing (not even a PULL_DATA keepalive) for this long is gone.
pub const GATEWAY_TIMEOUT: Duration = Duration::from_secs(90);
/// Copies of one frame from several gateways arriving within this window are one uplink.
pub const DEDUP_WINDOW: Duration = Duration::from_millis(200);
const DEDUP_ENTRIES: usize = 256;
/// How long before the receive window a PULL_RESP must leave for the gateway to schedule it.
pub const SCHEDULE_MARGIN: Duration = Duration::from_millis(250);
/// TX_ACK tokens remembered to name the downlink an acknowledgement belongs to.
const TX_TOKENS: usize = 128;

/// One configured device.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub name: Option<String>,
    pub dev_eui: Option<Eui>,
    pub app_eui: Eui,
    pub app_key: Option<Key>,
    pub abp: Option<(u32, Key, Key)>,
}

impl DeviceConfig {
    fn label(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.dev_eui.as_ref().map(mac::eui_hex))
            .or_else(|| self.abp.map(|a| mac::dev_addr_hex(a.0)))
            .unwrap_or_default()
    }
}

fn hex_field<'a>(o: &'a serde_json::Map<String, Value>, k: &str) -> Result<Option<&'a str>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => bail!("{k} is a hex string"),
    }
}

/// Parse the `devices` startup parameter (shared with the gateway client).
pub fn parse_devices(list: &[Value]) -> Result<Vec<DeviceConfig>> {
    ensure!(
        list.len() <= MAX_DEVICES,
        "at most {MAX_DEVICES} devices, not {}",
        list.len()
    );
    let mut out: Vec<DeviceConfig> = Vec::new();
    for (i, d) in list.iter().enumerate() {
        let o = d
            .as_object()
            .with_context(|| format!("devices[{i}] is an object"))?;
        let name = match o.get("name") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                ensure!(
                    s.len() <= 64 && !crate::utils::sanitize::has_controls(s),
                    "devices[{i}].name is one line of at most 64 bytes"
                );
                Some(s.clone())
            }
            Some(_) => bail!("devices[{i}].name is a string"),
        };
        let dev_eui = hex_field(o, "dev_eui")?
            .map(|s| mac::parse_eui("dev_eui", s))
            .transpose()?;
        let app_eui = hex_field(o, "app_eui")?
            .or(hex_field(o, "join_eui")?)
            .map(|s| mac::parse_eui("app_eui", s))
            .transpose()?
            .unwrap_or([0; 8]);
        let app_key = hex_field(o, "app_key")?
            .map(|s| mac::parse_key("app_key", s))
            .transpose()?;
        let abp = match (
            hex_field(o, "dev_addr")?,
            hex_field(o, "nwk_s_key")?,
            hex_field(o, "app_s_key")?,
        ) {
            (None, None, None) => None,
            (Some(a), Some(n), Some(s)) => Some((
                mac::parse_dev_addr(a)?,
                mac::parse_key("nwk_s_key", n)?,
                mac::parse_key("app_s_key", s)?,
            )),
            _ => bail!("devices[{i}]: an ABP device needs dev_addr, nwk_s_key and app_s_key"),
        };
        match (&app_key, &abp) {
            (Some(_), None) => ensure!(
                dev_eui.is_some(),
                "devices[{i}]: an OTAA device needs its dev_eui"
            ),
            (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                bail!("devices[{i}] is either OTAA (app_key) or ABP (session keys), not both")
            }
            (None, None) => {
                bail!("devices[{i}] needs an app_key (OTAA) or dev_addr and session keys (ABP)")
            }
        }
        if let Some(e) = dev_eui {
            ensure!(
                out.iter().all(|d| d.dev_eui != Some(e)),
                "devices[{i}]: dev_eui {} is configured twice",
                mac::eui_hex(&e)
            );
        }
        if let Some((a, _, _)) = abp {
            ensure!(
                out.iter().all(|d| d.abp.map(|x| x.0) != Some(a)),
                "devices[{i}]: dev_addr {} is configured twice",
                mac::dev_addr_hex(a)
            );
        }
        out.push(DeviceConfig {
            name,
            dev_eui,
            app_eui,
            app_key,
            abp,
        });
    }
    Ok(out)
}

struct QueuedDownlink {
    f_port: u8,
    payload: Vec<u8>,
    confirmed: bool,
}

struct Session {
    dev_eui: Option<Eui>,
    name: Option<String>,
    nwk: Key,
    app: Key,
    fcnt_up: Option<u32>,
    fcnt_down: u32,
    queue: VecDeque<QueuedDownlink>,
    dev_status_req: bool,
}

struct GatewayState {
    pull: Option<(SocketAddr, u8)>,
    last_seen: Instant,
    connection: ConnectionId,
    stat: Option<semtech::Stat>,
}

/// What Rust knows about the radio side of one uplink, for scheduling its answer.
#[derive(Clone)]
struct Reception {
    gateway: Eui,
    tmst: Option<u32>,
    freq_hz: u64,
    data_rate: u8,
    rssi: i32,
    snr: f64,
    received: Instant,
    gateways: Arc<std::sync::atomic::AtomicUsize>,
}

impl Reception {
    fn radio_fields(&self) -> Value {
        json!({
            "gateway": mac::eui_hex(&self.gateway),
            "gateways": self.gateways.load(std::sync::atomic::Ordering::Relaxed),
            "rssi": self.rssi,
            "snr": self.snr,
            "frequency_mhz": region::mhz(self.freq_hz),
            "data_rate": format!("{} (DR{})", region::data_rate_name(self.data_rate).unwrap_or_default(), self.data_rate),
        })
    }
}

struct Ns {
    socket: UdpSocket,
    local: SocketAddr,
    devices: Vec<DeviceConfig>,
    net_id: u32,
    sessions: Mutex<HashMap<u32, Session>>,
    nonces: Mutex<HashMap<Eui, VecDeque<u16>>>,
    gateways: Mutex<HashMap<Eui, GatewayState>>,
    recent: Mutex<VecDeque<(Vec<u8>, Instant, Arc<std::sync::atomic::AtomicUsize>)>>,
    tx_tokens: Mutex<VecDeque<(u16, String)>>,
    in_flight: Arc<Semaphore>,
}

fn decision(ctx: &SpawnContext, op: &str, device: &str, decision: &str) {
    let line = format!("LoRaWAN operation={op} device={device} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed") {
        log.error(line)
    } else {
        log.info(line)
    }
}

fn config(ctx: &SpawnContext) -> Result<(Vec<DeviceConfig>, u32)> {
    let params = ctx.startup_params.as_ref();
    if let Some(r) = params
        .map(|p| p.get_optional_string("region"))
        .transpose()?
        .flatten()
    {
        region::check_region(&r)?;
    }
    let net_id = params
        .map(|p| p.get_optional_string("net_id"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| DEFAULT_NET_ID.into());
    let net_id_bytes = hex::decode(&net_id).context("net_id is 6 hex digits")?;
    ensure!(net_id_bytes.len() == 3, "net_id is 6 hex digits");
    let net_id = u32::from_be_bytes([0, net_id_bytes[0], net_id_bytes[1], net_id_bytes[2]]);
    let devices = match params
        .map(|p| p.get_optional_array("devices"))
        .transpose()?
        .flatten()
    {
        Some(list) => parse_devices(list)?,
        None => Vec::new(),
    };
    Ok((devices, net_id))
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let (devices, net_id) = config(&ctx)?;
    let socket = UdpSocket::bind(ctx.legacy_listen_addr()).await?;
    let local = socket.local_addr()?;
    let mut sessions = HashMap::new();
    for d in &devices {
        if let Some((addr, nwk, app)) = d.abp {
            sessions.insert(
                addr,
                Session {
                    dev_eui: d.dev_eui,
                    name: d.name.clone(),
                    nwk,
                    app,
                    fcnt_up: None,
                    fcnt_down: 0,
                    queue: VecDeque::new(),
                    dev_status_req: false,
                },
            );
        }
    }
    Log::new(Some(&ctx.status_tx)).info(format!(
        "LoRaWAN network server (EU868, NetID {net_id:06x}) listening on {local} for {} device(s)",
        devices.len()
    ));
    let ns = Arc::new(Ns {
        socket,
        local,
        devices,
        net_id,
        sessions: Mutex::new(sessions),
        nonces: Mutex::new(HashMap::new()),
        gateways: Mutex::new(HashMap::new()),
        recent: Mutex::new(VecDeque::new()),
        tx_tokens: Mutex::new(VecDeque::new()),
        in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
    });
    let reaper_ctx = ctx.clone();
    let reaper_ns = ns.clone();
    ctx.state
        .spawn_server_task(ctx.server_id, async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let gone: Vec<(Eui, ConnectionId)> = {
                    let mut gws = reaper_ns.gateways.lock().await;
                    let stale: Vec<Eui> = gws
                        .iter()
                        .filter(|(_, g)| g.last_seen.elapsed() > GATEWAY_TIMEOUT)
                        .map(|(e, _)| *e)
                        .collect();
                    stale
                        .into_iter()
                        .filter_map(|e| gws.remove(&e).map(|g| (e, g.connection)))
                        .collect()
                };
                for (eui, id) in gone {
                    Log::new(Some(&reaper_ctx.status_tx))
                        .info(format!("LoRaWAN gateway {} timed out", mac::eui_hex(&eui)));
                    reaper_ctx
                        .state
                        .update_connection_status(reaper_ctx.server_id, id, ConnectionStatus::Closed)
                        .await;
                }
            }
        })
        .await;
    let recv_ctx = ctx.clone();
    ctx.state
        .spawn_server_task(ctx.server_id, async move {
            let mut buf = vec![0u8; semtech::MAX_DATAGRAM + 1];
            loop {
                let (n, from) = match ns.socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Err(e) = datagram(&recv_ctx, &ns, &buf[..n], from).await {
                    Log::new(Some(&recv_ctx.status_tx))
                        .debug(format!("LoRaWAN datagram from {from} ignored: {e:#}"));
                }
            }
        })
        .await;
    Ok(local)
}

async fn touch_gateway(
    ctx: &SpawnContext,
    ns: &Ns,
    eui: Eui,
    from: SocketAddr,
    bytes: usize,
    pull: Option<u8>,
) -> Result<()> {
    let now = Instant::now();
    let (id, fresh) = {
        let mut gws = ns.gateways.lock().await;
        match gws.get_mut(&eui) {
            Some(g) => {
                g.last_seen = now;
                if let Some(v) = pull {
                    g.pull = Some((from, v));
                }
                (g.connection, false)
            }
            None => {
                ensure!(
                    gws.len() < MAX_GATEWAYS,
                    "gateway {} refused: {MAX_GATEWAYS} gateways already connected",
                    mac::eui_hex(&eui)
                );
                let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
                gws.insert(
                    eui,
                    GatewayState {
                        pull: pull.map(|v| (from, v)),
                        last_seen: now,
                        connection: id,
                        stat: None,
                    },
                );
                (id, true)
            }
        }
    };
    if fresh {
        ctx.state
            .add_connection_to_server(
                ctx.server_id,
                ConnectionState {
                    id,
                    remote_addr: from,
                    local_addr: ns.local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(
                        json!({"gateway_eui": mac::eui_hex(&eui)}),
                    ),
                },
            )
            .await;
        Log::new(Some(&ctx.status_tx)).info(format!(
            "LoRaWAN gateway {} at {from}",
            mac::eui_hex(&eui)
        ));
    }
    ctx.state
        .update_connection_stats(ctx.server_id, id, Some(bytes as u64), None, Some(1), None)
        .await;
    Ok(())
}

async fn datagram(ctx: &SpawnContext, ns: &Arc<Ns>, d: &[u8], from: SocketAddr) -> Result<()> {
    let packet = semtech::parse(d)?;
    match packet {
        Packet::PushData {
            version,
            token,
            gateway,
            rxpk,
            stat,
        } => {
            touch_gateway(ctx, ns, gateway, from, d.len(), None).await?;
            ns.socket
                .send_to(
                    &semtech::encode(&Packet::PushAck { version, token })?,
                    from,
                )
                .await?;
            if let Some(stat) = stat {
                Log::new(Some(&ctx.status_tx)).debug(format!(
                    "LoRaWAN gateway {} stat: {}",
                    mac::eui_hex(&gateway),
                    serde_json::to_string(&stat).unwrap_or_default()
                ));
                if let Some(g) = ns.gateways.lock().await.get_mut(&gateway) {
                    g.stat = Some(stat);
                }
            }
            for r in rxpk {
                if let Err(e) = uplink(ctx, ns, gateway, &r).await {
                    Log::new(Some(&ctx.status_tx)).warn(format!(
                        "LoRaWAN frame from gateway {} dropped: {e:#}",
                        mac::eui_hex(&gateway)
                    ));
                }
            }
        }
        Packet::PullData {
            version,
            token,
            gateway,
        } => {
            touch_gateway(ctx, ns, gateway, from, d.len(), Some(version)).await?;
            ns.socket
                .send_to(
                    &semtech::encode(&Packet::PullAck { version, token })?,
                    from,
                )
                .await?;
        }
        Packet::TxAck {
            token,
            gateway,
            error,
            ..
        } => {
            touch_gateway(ctx, ns, gateway, from, d.len(), None).await?;
            let what = {
                let tokens = ns.tx_tokens.lock().await;
                tokens
                    .iter()
                    .find(|(t, _)| *t == token)
                    .map(|(_, w)| w.clone())
                    .unwrap_or_else(|| "an unknown downlink".into())
            };
            let log = Log::new(Some(&ctx.status_tx));
            match error.as_deref() {
                None | Some("NONE") => {
                    log.debug(format!("LoRaWAN TX_ACK for {what}: transmitted"))
                }
                Some(e) => log.warn(format!(
                    "LoRaWAN gateway {} refused {what}: {e}",
                    mac::eui_hex(&gateway)
                )),
            }
        }
        other => bail!("{other:?} is not sent to a network server"),
    }
    Ok(())
}

/// The first sighting of a frame records it; a copy within the window counts one more gateway.
async fn first_sighting(ns: &Ns, phy: &[u8]) -> Option<Arc<std::sync::atomic::AtomicUsize>> {
    let mut recent = ns.recent.lock().await;
    while recent
        .front()
        .is_some_and(|(_, t, _)| t.elapsed() > DEDUP_WINDOW)
    {
        recent.pop_front();
    }
    if let Some((_, _, n)) = recent.iter().find(|(p, _, _)| p == phy) {
        n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    if recent.len() >= DEDUP_ENTRIES {
        recent.pop_front();
    }
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(1));
    recent.push_back((phy.to_vec(), Instant::now(), n.clone()));
    Some(n)
}

async fn uplink(ctx: &SpawnContext, ns: &Arc<Ns>, gateway: Eui, r: &Rxpk) -> Result<()> {
    ensure!(r.stat == 1, "CRC status {} (only CRC-OK frames are used)", r.stat);
    let dr = semtech::lora_data_rate(&r.modu, &r.datr)?;
    let phy = semtech::b64_decode(&r.data)?;
    ensure!(
        phy.len() <= region::max_phy_payload(dr),
        "a {}-byte PHYPayload exceeds DR{dr}'s {}",
        phy.len(),
        region::max_phy_payload(dr)
    );
    let freq_hz = region::hz(r.freq)?;
    let mtype = mac::mtype_of(&phy)?;
    match mtype {
        mac::MTYPE_JOIN_REQUEST => {
            let jr = mac::parse_join_request(&phy)?;
            let Some(device) = ns
                .devices
                .iter()
                .find(|d| d.dev_eui == Some(jr.dev_eui) && d.app_key.is_some())
                .cloned()
            else {
                decision(
                    ctx,
                    "join",
                    &mac::eui_hex(&jr.dev_eui),
                    "fail_closed_unknown_device",
                );
                return Ok(());
            };
            let Some(gateways) = first_sighting(ns, &phy).await else {
                return Ok(());
            };
            let app_key = device.app_key.expect("filtered on app_key");
            if !mac::join_request_mic_ok(&phy, &app_key) {
                decision(ctx, "join", &device.label(), "fail_closed_bad_mic");
                return Ok(());
            }
            if jr.app_eui != device.app_eui {
                decision(ctx, "join", &device.label(), "fail_closed_wrong_app_eui");
                return Ok(());
            }
            {
                let mut nonces = ns.nonces.lock().await;
                let used = nonces.entry(jr.dev_eui).or_default();
                if used.contains(&jr.dev_nonce) {
                    decision(ctx, "join", &device.label(), "fail_closed_dev_nonce_reused");
                    return Ok(());
                }
                if used.len() >= MAX_NONCES {
                    used.pop_front();
                }
                used.push_back(jr.dev_nonce);
            }
            let rx = Reception {
                gateway,
                tmst: r.tmst,
                freq_hz,
                data_rate: dr,
                rssi: r.rssi,
                snr: r.lsnr,
                received: Instant::now(),
                gateways,
            };
            let Ok(permit) = ns.in_flight.clone().try_acquire_owned() else {
                decision(ctx, "join", &device.label(), "fail_closed_busy");
                return Ok(());
            };
            let (task_ctx, task_ns) = (ctx.clone(), ns.clone());
            ctx.state
                .spawn_server_task(ctx.server_id, async move {
                    join(&task_ctx, &task_ns, device, jr, app_key, rx).await;
                    drop(permit);
                })
                .await;
        }
        mac::MTYPE_UNCONFIRMED_UP | mac::MTYPE_CONFIRMED_UP => {
            let frame = mac::parse_data(&phy)?;
            let Some(gateways) = first_sighting(ns, &phy).await else {
                return Ok(());
            };
            let addr = mac::dev_addr_hex(frame.dev_addr);
            let (label, dev_eui, payload, mac_commands, full_fcnt) = {
                let mut sessions = ns.sessions.lock().await;
                let Some(s) = sessions.get_mut(&frame.dev_addr) else {
                    decision(ctx, "uplink", &addr, "fail_closed_unknown_dev_addr");
                    return Ok(());
                };
                let label = s.name.clone().unwrap_or_else(|| addr.clone());
                let full = match mac::classify_fcnt(s.fcnt_up, frame.f_cnt) {
                    mac::FcntCheck::Fresh(f) => f,
                    mac::FcntCheck::Repeat(_) => {
                        decision(ctx, "uplink", &label, "fail_closed_repeated_fcnt");
                        return Ok(());
                    }
                    mac::FcntCheck::TooFar(f) => {
                        Log::new(Some(&ctx.status_tx)).warn(format!(
                            "LoRaWAN {label}: FCnt {f} is a replay or beyond MAX_FCNT_GAP of {:?}",
                            s.fcnt_up
                        ));
                        decision(ctx, "uplink", &label, "fail_closed_fcnt_replay");
                        return Ok(());
                    }
                };
                if !mac::data_mic_ok(&phy, &s.nwk, mac::DIR_UP, frame.dev_addr, full) {
                    decision(ctx, "uplink", &label, "fail_closed_bad_mic");
                    return Ok(());
                }
                s.fcnt_up = Some(full);
                let key = if frame.f_port == Some(0) { s.nwk } else { s.app };
                let plain = mac::crypt_frm(&key, mac::DIR_UP, frame.dev_addr, full, &frame.frm_payload);
                let (payload, commands) = if frame.f_port == Some(0) {
                    (Vec::new(), mac::decode_mac_commands(&plain, true))
                } else {
                    (plain, mac::decode_mac_commands(&frame.f_opts, true))
                };
                (label, s.dev_eui, payload, commands, full)
            };
            let rx = Reception {
                gateway,
                tmst: r.tmst,
                freq_hz,
                data_rate: dr,
                rssi: r.rssi,
                snr: r.lsnr,
                received: Instant::now(),
                gateways,
            };
            let Ok(permit) = ns.in_flight.clone().try_acquire_owned() else {
                decision(ctx, "uplink", &label, "fail_closed_busy");
                return Ok(());
            };
            let up = Uplink {
                frame,
                label,
                dev_eui,
                payload,
                mac_commands,
                full_fcnt,
            };
            let (task_ctx, task_ns) = (ctx.clone(), ns.clone());
            ctx.state
                .spawn_server_task(ctx.server_id, async move {
                    data_uplink(&task_ctx, &task_ns, up, rx).await;
                    drop(permit);
                })
                .await;
        }
        other => bail!("{} frames are not handled", mac::mtype_name(other)),
    }
    Ok(())
}

/// The model's actions, flattened.
fn answers(result: crate::llm::actions::executor::ExecutionResult) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut stack = result.protocol_results;
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { name, data } if name.starts_with("lorawan_") => {
                out.push((name, data))
            }
            ActionResult::Multiple(items) => stack.extend(items),
            _ => {}
        }
    }
    out.reverse();
    out
}

/// Ask the model; `None` when it failed (already logged as fail-closed).
async fn ask(
    ctx: &SpawnContext,
    ns: &Ns,
    gateway: &Eui,
    event: &Event,
    op: &str,
    device: &str,
) -> Option<Vec<(String, Value)>> {
    let connection = ns.gateways.lock().await.get(gateway).map(|g| g.connection);
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        connection,
        event,
        &LorawanProtocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => Some(answers(r)),
        Ok(_) => {
            decision(ctx, op, device, "fail_closed_invalid_reply");
            None
        }
        Err(_) => {
            decision(ctx, op, device, "fail_closed_llm_error");
            None
        }
    }
}

/// Which receive window a downlink can still make, as the txpk's timing and radio fields.
fn window(rx: &Reception, rx1_us: u32, rx2_us: u32) -> Option<(Option<u32>, u64, u8)> {
    let elapsed = rx.received.elapsed() + SCHEDULE_MARGIN;
    let rx1 = Duration::from_micros(rx1_us as u64);
    let rx2 = Duration::from_micros(rx2_us as u64);
    let tmst = |delay: u32| rx.tmst.map(|t| t.wrapping_add(delay));
    if elapsed < rx1 {
        Some((
            tmst(rx1_us),
            rx.freq_hz,
            region::rx1_data_rate(rx.data_rate, 0),
        ))
    } else if elapsed < rx2 {
        Some((tmst(rx2_us), region::RX2_FREQUENCY_HZ, region::RX2_DATA_RATE))
    } else {
        None
    }
}

async fn send_pull_resp(
    ctx: &SpawnContext,
    ns: &Ns,
    gateway: &Eui,
    phy: &[u8],
    timing: (Option<u32>, u64, u8),
    what: String,
) -> Result<()> {
    let (pull, connection) = {
        let gws = ns.gateways.lock().await;
        let g = gws.get(gateway).context("the gateway is gone")?;
        (g.pull, g.connection)
    };
    let (addr, version) = pull.context("the gateway has sent no PULL_DATA, so it has no downlink path")?;
    let (tmst, freq_hz, dr) = timing;
    let txpk = Txpk {
        imme: tmst.is_none(),
        tmst,
        tmms: None,
        freq: region::mhz(freq_hz),
        rfch: 0,
        powe: Some(region::DOWNLINK_POWER_DBM),
        modu: "LORA".into(),
        datr: json!(region::data_rate_name(dr)?),
        codr: Some("4/5".into()),
        ipol: true,
        size: phy.len() as u32,
        data: semtech::b64_encode(phy),
        ncrc: Some(true),
    };
    let token: u16 = if version == 1 { 0 } else { rand::random() };
    let bytes = semtech::encode(&Packet::PullResp {
        version,
        token,
        txpk,
    })?;
    ns.socket.send_to(&bytes, addr).await?;
    {
        let mut tokens = ns.tx_tokens.lock().await;
        if tokens.len() >= TX_TOKENS {
            tokens.pop_front();
        }
        tokens.push_back((token, what));
    }
    ctx.state
        .update_connection_stats(ctx.server_id, connection, None, Some(bytes.len() as u64), None, Some(1))
        .await;
    Ok(())
}

async fn join(
    ctx: &SpawnContext,
    ns: &Ns,
    device: DeviceConfig,
    jr: mac::JoinRequest,
    app_key: Key,
    rx: Reception,
) {
    let label = device.label();
    let mut data = json!({
        "dev_eui": mac::eui_hex(&jr.dev_eui),
        "app_eui": mac::eui_hex(&jr.app_eui),
        "dev_nonce": jr.dev_nonce,
        "device": device.name,
    });
    if let (Value::Object(m), Value::Object(radio)) = (&mut data, rx.radio_fields()) {
        m.extend(radio);
    }
    let event = Event::new(&actions::JOIN_EVENT, data);
    let Some(answers) = ask(ctx, ns, &rx.gateway, &event, "join", &label).await else {
        return;
    };
    let accept = answers.iter().any(|(n, _)| n == actions::ACCEPT_JOIN);
    let reject = answers.iter().any(|(n, _)| n == actions::REJECT_JOIN);
    if reject || !accept {
        decision(
            ctx,
            "join",
            &label,
            if reject { "model_reject" } else { "model_silent" },
        );
        return;
    }
    let Some(timing) = window(
        &rx,
        region::JOIN_ACCEPT_DELAY1_US,
        region::JOIN_ACCEPT_DELAY2_US,
    ) else {
        decision(ctx, "join", &label, "fail_closed_too_late");
        return;
    };
    let dev_addr = {
        let sessions = ns.sessions.lock().await;
        loop {
            let candidate = ((ns.net_id & 0x7f) << 25) | (rand::random::<u32>() & 0x01ff_ffff);
            if !sessions.contains_key(&candidate) {
                break candidate;
            }
        }
    };
    let app_nonce = rand::random::<u32>() & 0x00ff_ffff;
    let ja = mac::JoinAccept {
        app_nonce,
        net_id: ns.net_id,
        dev_addr,
        rx1_dr_offset: 0,
        rx2_data_rate: region::RX2_DATA_RATE,
        rx_delay: (region::RECEIVE_DELAY1_US / 1_000_000) as u8,
        cf_list: None,
    };
    let phy = mac::encode_join_accept(&ja, &app_key);
    if let Err(e) = send_pull_resp(
        ctx,
        ns,
        &rx.gateway,
        &phy,
        timing,
        format!("the Join Accept for {label}"),
    )
    .await
    {
        Log::new(Some(&ctx.status_tx)).error(format!("LoRaWAN Join Accept for {label}: {e:#}"));
        decision(ctx, "join", &label, "fail_closed_no_downlink_path");
        return;
    }
    let (nwk, app) = mac::session_keys(&app_key, app_nonce, ns.net_id, jr.dev_nonce);
    {
        let mut sessions = ns.sessions.lock().await;
        // A device that joins again leaves its old session behind.
        sessions.retain(|_, s| s.dev_eui != Some(jr.dev_eui));
        sessions.insert(
            dev_addr,
            Session {
                dev_eui: Some(jr.dev_eui),
                name: device.name.clone(),
                nwk,
                app,
                fcnt_up: None,
                fcnt_down: 0,
                queue: VecDeque::new(),
                dev_status_req: false,
            },
        );
    }
    Log::new(Some(&ctx.status_tx)).info(format!(
        "LoRaWAN {label} joined as {}",
        mac::dev_addr_hex(dev_addr)
    ));
    decision(ctx, "join", &label, "model_accept");
}

struct Uplink {
    frame: mac::DataFrame,
    label: String,
    dev_eui: Option<Eui>,
    payload: Vec<u8>,
    mac_commands: Vec<Value>,
    full_fcnt: u32,
}

async fn data_uplink(ctx: &SpawnContext, ns: &Ns, up: Uplink, rx: Reception) {
    let label = up.label.clone();
    let (payload, encoding) = actions::payload_field(&up.payload);
    let link_check = up
        .mac_commands
        .iter()
        .any(|c| c["command"] == "link_check_req");
    let rx1_dr = region::rx1_data_rate(rx.data_rate, 0);
    // What the reply may carry: LinkCheckAns and a possible DevStatusReq come first.
    let fopts_reserved = if link_check { 3 } else { 0 } + 1;
    let mut data = json!({
        "dev_addr": mac::dev_addr_hex(up.frame.dev_addr),
        "dev_eui": actions::eui_field(up.dev_eui.as_ref()),
        "device": if up.label == mac::dev_addr_hex(up.frame.dev_addr) { Value::Null } else { json!(up.label) },
        "confirmed": up.frame.confirmed(),
        "f_cnt": up.full_fcnt,
        "f_port": up.frame.f_port,
        "payload": payload,
        "payload_encoding": encoding,
        "mac_commands": up.mac_commands,
        "ack": up.frame.ack,
        "max_downlink_payload": region::max_frm_payload(rx1_dr, fopts_reserved),
    });
    if let (Value::Object(m), Value::Object(radio)) = (&mut data, rx.radio_fields()) {
        m.extend(radio);
    }
    let event = Event::new(&actions::UPLINK_EVENT, data);
    let Some(answers) = ask(ctx, ns, &rx.gateway, &event, "uplink", &label).await else {
        return;
    };
    let mut verdict = if answers.is_empty() {
        "model_silent"
    } else {
        "model_ignore"
    };
    // Under the session lock: apply the answer and build the frame; the send happens after.
    let built = {
        let mut sessions = ns.sessions.lock().await;
        let Some(s) = sessions.get_mut(&up.frame.dev_addr) else {
            return;
        };
        for (name, v) in &answers {
            match name.as_str() {
                actions::SEND_DOWNLINK => {
                    let queued = (|| -> Result<QueuedDownlink> {
                        ensure!(
                            s.queue.len() < MAX_QUEUED_DOWNLINKS,
                            "{MAX_QUEUED_DOWNLINKS} downlinks already wait for this device"
                        );
                        Ok(QueuedDownlink {
                            f_port: actions::port_of(v)?,
                            payload: actions::payload_bytes(v)?,
                            confirmed: actions::confirmed_of(v)?,
                        })
                    })();
                    match queued {
                        Ok(q) => {
                            s.queue.push_back(q);
                            verdict = "model_answer";
                        }
                        Err(e) => {
                            Log::new(Some(&ctx.status_tx))
                                .error(format!("LoRaWAN downlink for {label} refused: {e:#}"));
                            decision(ctx, "uplink", &label, "fail_closed_invalid_reply");
                        }
                    }
                }
                actions::REQUEST_STATUS => s.dev_status_req = true,
                _ => {}
            }
        }
        build_downlink(ctx, s, &up, &rx, link_check, &label)
    };
    let Some(Built {
        phy,
        timing,
        fcnt,
        app,
        summary,
    }) = built
    else {
        decision(ctx, "uplink", &label, verdict);
        return;
    };
    match send_pull_resp(
        ctx,
        ns,
        &rx.gateway,
        &phy,
        timing,
        format!("downlink FCnt {fcnt} to {label}"),
    )
    .await
    {
        Ok(()) => {
            Log::new(Some(&ctx.status_tx))
                .info(format!("LoRaWAN downlink FCnt {fcnt} to {label}: {summary}"));
            decision(ctx, "uplink", &label, verdict);
        }
        Err(e) => {
            let mut sessions = ns.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&up.frame.dev_addr) {
                // Nothing was sent: the counter and the payload are still the device's next.
                if s.fcnt_down == fcnt.wrapping_add(1) {
                    s.fcnt_down = fcnt;
                }
                if let Some(a) = app {
                    s.queue.push_front(a);
                }
            }
            Log::new(Some(&ctx.status_tx)).error(format!("LoRaWAN downlink for {label}: {e:#}"));
            decision(ctx, "uplink", &label, "fail_closed_no_downlink_path");
        }
    }
}

struct Built {
    phy: Vec<u8>,
    timing: (Option<u32>, u64, u8),
    fcnt: u32,
    app: Option<QueuedDownlink>,
    summary: String,
}

/// The downlink that answers this uplink, if one is due and a receive window is still open:
/// takes the payload off the queue and reserves the downlink counter.
fn build_downlink(
    ctx: &SpawnContext,
    s: &mut Session,
    up: &Uplink,
    rx: &Reception,
    link_check: bool,
    label: &str,
) -> Option<Built> {
    // The network's own part of the answer, whatever the application said.
    let mut f_opts = Vec::new();
    if link_check {
        let margin = region::link_margin_db(rx.data_rate, rx.snr);
        let count = rx
            .gateways
            .load(std::sync::atomic::Ordering::Relaxed)
            .min(255) as u8;
        f_opts.extend(mac::link_check_ans(margin, count));
    }
    if s.dev_status_req {
        f_opts.push(mac::CID_DEV_STATUS);
    }
    if s.queue.is_empty() && f_opts.is_empty() && !up.frame.confirmed() {
        return None;
    }
    let Some(timing) = window(rx, region::RECEIVE_DELAY1_US, region::RECEIVE_DELAY2_US) else {
        Log::new(Some(&ctx.status_tx)).warn(format!(
            "LoRaWAN {label}: the answer missed RX1 and RX2; queued downlinks wait for the next uplink"
        ));
        return None;
    };
    let max = region::max_frm_payload(timing.2, f_opts.len());
    let app = match s.queue.front() {
        Some(q) if q.payload.len() <= max => s.queue.pop_front(),
        Some(q) => {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "LoRaWAN {label}: a {}-byte downlink does not fit DR{} ({max} bytes); it waits for a faster uplink",
                q.payload.len(),
                timing.2
            ));
            None
        }
        None => None,
    };
    if app.is_none() && f_opts.is_empty() && !up.frame.confirmed() {
        return None;
    }
    let confirmed = app.as_ref().is_some_and(|a| a.confirmed);
    let frame = mac::OutFrame {
        mtype: if confirmed {
            mac::MTYPE_CONFIRMED_DOWN
        } else {
            mac::MTYPE_UNCONFIRMED_DOWN
        },
        dev_addr: up.frame.dev_addr,
        adr: false,
        adr_ack_req: false,
        ack: up.frame.confirmed(),
        f_pending: !s.queue.is_empty(),
        f_cnt: s.fcnt_down,
        f_opts: &f_opts,
        f_port: app.as_ref().map(|a| a.f_port),
        payload: app
            .as_ref()
            .map(|a| a.payload.as_slice())
            .unwrap_or_default(),
    };
    let phy = match mac::encode_data(&frame, &s.nwk, &s.app) {
        Ok(p) => p,
        Err(e) => {
            Log::new(Some(&ctx.status_tx)).error(format!("LoRaWAN downlink for {label}: {e:#}"));
            if let Some(a) = app {
                s.queue.push_front(a);
            }
            return None;
        }
    };
    let summary = format!(
        "{} bytes on port {:?}{}{}",
        frame.payload.len(),
        frame.f_port,
        if frame.ack { ", ACK" } else { "" },
        if s.dev_status_req {
            ", DevStatusReq"
        } else {
            ""
        }
    );
    let fcnt = s.fcnt_down;
    s.fcnt_down = s.fcnt_down.wrapping_add(1);
    s.dev_status_req = false;
    Some(Built {
        phy,
        timing,
        fcnt,
        app,
        summary,
    })
}
