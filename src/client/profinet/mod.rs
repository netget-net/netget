//! PROFINET IO controller — NetGet as the PLC side: it finds devices with DCP, names and
//! addresses them, connects, exchanges cyclic data and reads and writes records.
//!
//! Three tasks, as in the OpenFlow switch: the session (it owns the link, the RPC socket, the
//! AR and every timer, so a slow model never delays a cyclic frame or an RPC answer), the model
//! dispatcher (one event at a time, its actions handed back to the session, the chain bounded
//! by [`MAX_FOLLOWUP_DEPTH`]), and per AR an output provider sending the output image every
//! cycle.
//!
//! The connect sequence is a small state machine in the session: Connect → each parameter
//! Write → PrmEnd → wait for the device's own ApplicationReady CControl request on this
//! controller's RPC endpoint, answer it Done → running. Every RPC call is retransmitted with
//! the same sequence number until it is answered or [`RPC_ATTEMPTS`] run out; any stage that
//! fails raises `profinet_connect_failed` naming the stage.
//!
//! Outputs start IOPS BAD with zero data and change only when the model (or an operator)
//! sets them. On an LLM failure nothing is sent.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::profinet::blocks::{
    self, block_type, control_command, iocr_type, ArBlockReq, ControlBlock, IocrApi, IocrBlockReq,
    RecordRequest,
};
use crate::server::profinet::dcp::{self, DiscoveredDevice, Pdu};
use crate::server::profinet::l2::{self, L2Tx};
use crate::server::profinet::rpc::{self, opnum, ptype, PnioStatus, Uuid};
use crate::server::profinet::rt::{self, CrLayout, EthFrame};
use crate::server::profinet::values::{self, SubmoduleSpec};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::ProfinetClientProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

type Instant = crate::utils::clock::Instant;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Devices remembered from Identify answers.
pub const MAX_DEVICES: usize = 64;
/// RPC retransmission interval and attempts.
pub const RPC_RETRY: Duration = Duration::from_secs(1);
pub const RPC_ATTEMPTS: u32 = 4;
/// How long the device has to send ApplicationReady after PrmEnd.
pub const APP_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a DCP Set has to be answered.
pub const DCP_SET_TIMEOUT: Duration = Duration::from_secs(3);
/// At most one `profinet_inputs_changed` per this interval, carrying the latest values.
pub const INPUT_EVENT_INTERVAL: Duration = Duration::from_millis(200);
/// Events waiting for the model.
const TURNS: usize = 64;
const TICK: Duration = Duration::from_millis(10);

struct Config {
    lab: bool,
    station_name: String,
    rpc_port: u16,
    identify: Duration,
}

impl Config {
    fn from(ctx: &ConnectContext) -> Result<Self> {
        let p = ctx.startup_params.as_ref();
        let lab = match p
            .map(|p| p.get_optional_string("transport"))
            .transpose()?
            .flatten()
            .as_deref()
        {
            None | Some("raw") => false,
            Some("udp") => true,
            Some(other) => bail!("transport is raw or udp, not {other:?}"),
        };
        let station_name = p
            .map(|p| p.get_optional_string("station_name"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| actions::DEFAULT_STATION_NAME.into());
        dcp::validate_station_name(&station_name)?;
        let rpc_port = match p
            .map(|p| p.get_optional_u64("rpc_port"))
            .transpose()?
            .flatten()
        {
            None => rpc::RPC_PORT,
            Some(v) => u16::try_from(v)
                .ok()
                .filter(|v| *v != 0)
                .context("rpc_port is 1-65535")?,
        };
        let identify = p
            .map(|p| p.get_optional_u64("identify_ms"))
            .transpose()?
            .flatten()
            .unwrap_or(actions::DEFAULT_IDENTIFY_MS);
        anyhow::ensure!(
            (100..=actions::MAX_IDENTIFY_MS).contains(&identify),
            "identify_ms must be 100-{}",
            actions::MAX_IDENTIFY_MS
        );
        Ok(Self {
            lab,
            station_name,
            rpc_port,
            identify: Duration::from_millis(identify),
        })
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let cfg = Config::from(&ctx)?;
    let (link, ip) = if cfg.lab {
        let peer: SocketAddr = ctx.remote_addr.parse().with_context(|| {
            format!(
                "with transport udp, remote_addr is the device's lab link HOST:PORT, got {:?}",
                ctx.remote_addr
            )
        })?;
        let IpAddr::V4(ip) = peer.ip() else {
            bail!("PROFINET IO is IPv4-only");
        };
        let mac = l2::lab_mac(0x8000_0000 | ctx.client_id.as_u32() ^ (std::process::id() << 8));
        (
            l2::open_udp(SocketAddr::new(peer.ip(), 0), Some(peer), mac).await?,
            ip,
        )
    } else {
        let link = l2::open_raw(ctx.remote_addr.trim())?;
        let ip = link.ipv4.map(|(ip, _)| ip).with_context(|| {
            format!(
                "{} has no IPv4 address; a PROFINET controller needs one for RPC",
                link.description
            )
        })?;
        (link, ip)
    };
    // The controller's RPC endpoint: where devices send ApplicationReady (34964 on a real
    // network; any port in the lab, where the device answers the Connect's source address).
    let rpc_bind = SocketAddr::new(IpAddr::V4(ip), if cfg.lab { 0 } else { rpc::RPC_PORT });
    let rpc_socket = Arc::new(
        UdpSocket::bind(rpc_bind)
            .await
            .with_context(|| format!("binding the controller's RPC endpoint on {rpc_bind}"))?,
    );
    let local = rpc_socket.local_addr()?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "PROFINET controller {} on {} (MAC {}, RPC {local})",
        cfg.station_name,
        link.description,
        dcp::format_mac(&link.mac)
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let dispatcher = ctx
        .state
        .spawn_client_task(ctx.client_id, run_turns(ctx.clone(), event_rx, internal_tx))
        .await;
    let session_ctx = ctx.clone();
    ctx.state
        .spawn_client_task(ctx.client_id, async move {
            let mut s = Session {
                ctx: session_ctx.clone(),
                tx: link.tx.clone(),
                mac: link.mac,
                rpc: rpc_socket,
                cfg,
                devices: Vec::new(),
                identify: None,
                dcp_set: None,
                call: None,
                ar: None,
                events: event_tx.clone(),
                next_xid: 1,
                record_seq: 0,
                activity: rpc::random_uuid(),
                seq: 0,
            };
            s.start_identify(None, 0);
            let reason = s.run(link, external, internal).await;
            s.release_quietly().await;
            Log::new(Some(&session_ctx.status_tx)).info(format!(
                "PROFINET controller {} stopped: {reason}",
                session_ctx.client_id
            ));
            drop(event_tx);
            drop(s);
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
    Ok(local)
}

struct IdentifyRun {
    xid: u32,
    until: Instant,
    depth: u32,
}

struct DcpSetRun {
    xid: u32,
    mac: [u8; 6],
    until: Instant,
    depth: u32,
}

/// Why an RPC call was made, and so what its answer does.
enum Purpose {
    Connect(Box<Plan>),
    Parameter(Box<Plan>),
    PrmEnd(Box<Plan>),
    Read { rec: RecordRequest },
    Write { index: u16 },
    Release,
}

struct Call {
    activity: Uuid,
    seq: u32,
    datagram: Vec<u8>,
    dest: SocketAddr,
    attempts: u32,
    last_sent: Instant,
    purpose: Purpose,
    depth: u32,
}

/// What a Connect is building, carried through the stages.
struct Plan {
    device: DiscoveredDevice,
    name: String,
    dest: SocketAddr,
    specs: Vec<SubmoduleSpec>,
    ar: ArBlockReq,
    input: CrLayout,
    output: CrLayout,
    input_frame_id: u16,
    output_frame_id: u16,
    send_clock_factor: u16,
    reduction_ratio: u16,
    watchdog_factor: u16,
    parameters: Vec<(u16, u16, u16, Vec<u8>)>,
    module_diff: Vec<Value>,
}

struct OutputImage {
    outputs: HashMap<(u16, u16), (Vec<u8>, bool)>,
    iocs_good: bool,
    running: bool,
}

struct ArRun {
    plan: Plan,
    running: bool,
    app_ready_deadline: Option<Instant>,
    image: Arc<Mutex<OutputImage>>,
    provider: tokio::task::AbortHandle,
    last_rx: Option<Instant>,
    current: HashMap<(u16, u16), (Vec<u8>, u8)>,
    changed: HashSet<(u16, u16)>,
    last_event: Option<Instant>,
    watchdog: Duration,
    started: Instant,
}

struct Session {
    ctx: ConnectContext,
    tx: L2Tx,
    mac: [u8; 6],
    rpc: Arc<UdpSocket>,
    cfg: Config,
    devices: Vec<DiscoveredDevice>,
    identify: Option<IdentifyRun>,
    dcp_set: Option<DcpSetRun>,
    call: Option<Call>,
    ar: Option<ArRun>,
    events: mpsc::Sender<(Event, u32)>,
    next_xid: u32,
    record_seq: u16,
    activity: Uuid,
    seq: u32,
}

fn device_json(d: &DiscoveredDevice) -> Value {
    let mut v = json!({"mac": dcp::format_mac(&d.mac)});
    if let Some(n) = &d.name_of_station {
        v["name_of_station"] = json!(n);
    }
    if let Some(t) = &d.type_of_station {
        v["type_of_station"] = json!(t);
    }
    if let Some(x) = d.vendor_id {
        v["vendor_id"] = json!(x);
    }
    if let Some(x) = d.device_id {
        v["device_id"] = json!(x);
    }
    if let Some(r) = d.role {
        v["role"] = json!(r);
    }
    if let Some(ip) = d.ip {
        v["ip"] = json!(ip.ip.to_string());
        v["netmask"] = json!(ip.netmask.to_string());
        v["gateway"] = json!(ip.gateway.to_string());
    }
    v
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
            self.log().warn(format!(
                "PROFINET {} not sent to the model: the queue is full decision=fail_closed_queue_full",
                event.id
            ));
        }
    }

    async fn run(
        &mut self,
        mut link: l2::L2Link,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> String {
        let rpc = self.rpc.clone();
        let mut buf = vec![0u8; 2048];
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                f = link.rx.recv() => match f {
                    Some(f) => self.on_frame(f),
                    None => return "the link closed".into(),
                },
                r = rpc.recv_from(&mut buf) => match r {
                    Ok((n, from)) => {
                        let d = buf[..n].to_vec();
                        self.on_rpc(&d, from).await;
                    }
                    Err(e) => self.log().warn(format!("PROFINET controller RPC receive failed: {e}")),
                },
                c = external.recv() => match c {
                    Some(c) => {
                        self.ctx.state.record_access_log(
                            AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                            "PROFINET", None, "injected_action", c.action.clone(), vec![],
                        ).await;
                        let action = c.action.clone();
                        let (outcome, stop) = self.perform(&action, 0).await;
                        crate::client::command_support::reply(c, Ok(outcome));
                        if let Some(r) = stop {
                            return r;
                        }
                    }
                    None => return "the client was stopped".into(),
                },
                a = internal.recv() => match a {
                    Some((action, depth)) => {
                        let (outcome, stop) = self.perform(&action, depth).await;
                        if let ClientSendOutcome::Rejected { error } = &outcome {
                            self.log().warn(format!(
                                "PROFINET controller: the model's {} was not carried out \
                                 decision=fail_closed_bad_action: {error}",
                                action["type"].as_str().unwrap_or("action")
                            ));
                        }
                        if let Some(r) = stop {
                            return r;
                        }
                    }
                    None => return "the client was stopped".into(),
                },
                _ = tick.tick() => self.on_tick().await,
            }
        }
    }

    // ------------------------------------------------------------------ actions

    async fn perform(&mut self, action: &Value, depth: u32) -> (ClientSendOutcome, Option<String>) {
        let name = match ProfinetClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                return (
                    ClientSendOutcome::Disconnected,
                    Some("disconnected by request".into()),
                )
            }
            Ok(ClientActionResult::Custom { name, .. }) => name,
            Ok(_) => {
                return (
                    ClientSendOutcome::Executed {
                        detail: "nothing to do".into(),
                    },
                    None,
                )
            }
            Err(e) => {
                return (
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                    None,
                )
            }
        };
        let r = match name.as_str() {
            actions::IDENTIFY => {
                let filter = action
                    .get("name_of_station")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.start_identify(filter.as_deref(), depth);
                Ok("identify sent".to_string())
            }
            actions::DCP_SET => self.dcp_set(action, depth),
            actions::CONNECT => self.connect_device(action, depth).await,
            actions::SET_OUTPUTS => self.set_outputs(action),
            actions::READ_RECORD => self.read_record(action, depth).await,
            actions::WRITE_RECORD => self.write_record(action, depth).await,
            actions::RELEASE => self.release(depth).await,
            other => Err(anyhow::anyhow!("unknown action {other}")),
        };
        match r {
            Ok(detail) => (ClientSendOutcome::Executed { detail }, None),
            Err(e) => (
                ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                },
                None,
            ),
        }
    }

    fn start_identify(&mut self, name: Option<&str>, depth: u32) {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        // A small ResponseDelayFactor: up to ~100 ms of spread across answering devices.
        let pdu = dcp::identify_request(xid, name, 10);
        if let Ok(bytes) = pdu.encode() {
            let _ = self.tx.send(rt::build_eth(
                dcp::MULTICAST_IDENTIFY,
                self.mac,
                None,
                &bytes,
            ));
        }
        if name.is_none() {
            self.devices.clear();
        }
        self.identify = Some(IdentifyRun {
            xid,
            until: Instant::now() + self.cfg.identify,
            depth,
        });
    }

    fn find_device(&self, v: &Value) -> Result<DiscoveredDevice> {
        if let Some(m) = v.get("mac").and_then(Value::as_str) {
            let mac = dcp::parse_mac(m)?;
            return Ok(self
                .devices
                .iter()
                .find(|d| d.mac == mac)
                .cloned()
                .unwrap_or(DiscoveredDevice {
                    mac,
                    ..Default::default()
                }));
        }
        let name = v
            .get("name_of_station")
            .and_then(Value::as_str)
            .context("name the device by mac or name_of_station")?;
        self.devices
            .iter()
            .find(|d| d.name_of_station.as_deref() == Some(name))
            .cloned()
            .with_context(|| format!("no device named {name:?} has answered an Identify; send profinet_identify first"))
    }

    fn dcp_set(&mut self, v: &Value, depth: u32) -> Result<String> {
        anyhow::ensure!(
            self.dcp_set.is_none(),
            "a DCP Set is already waiting for its answer"
        );
        let device = self.find_device(v)?;
        let permanent = v.get("permanent").and_then(Value::as_bool).unwrap_or(true);
        let mut blocks = vec![dcp::set_request_block(
            dcp::opt::CONTROL,
            dcp::sub::CONTROL_START,
            false,
            &[],
        )];
        if let Some(n) = v.get("new_name_of_station").and_then(Value::as_str) {
            blocks.push(dcp::set_request_block(
                dcp::opt::DEVICE,
                dcp::sub::DEVICE_NAME_OF_STATION,
                permanent,
                n.as_bytes(),
            ));
        }
        if let Some(ip) = v.get("ip").and_then(Value::as_str) {
            let parse = |k: &str, d: &str| -> Result<Ipv4Addr> {
                let t = v.get(k).and_then(Value::as_str).unwrap_or(d);
                t.parse()
                    .with_context(|| format!("{k} {t:?} is not an IPv4 address"))
            };
            let params = dcp::IpParameters {
                ip: ip
                    .parse()
                    .with_context(|| format!("ip {ip:?} is not an IPv4 address"))?,
                netmask: parse("netmask", "255.255.255.0")?,
                gateway: parse("gateway", "0.0.0.0")?,
            };
            params.validate()?;
            blocks.push(dcp::set_request_block(
                dcp::opt::IP,
                dcp::sub::IP_PARAMETER,
                permanent,
                &params.encode(),
            ));
        }
        if v.get("signal").and_then(Value::as_bool) == Some(true) {
            // SignalValue 0x0100: flash once.
            blocks.push(dcp::set_request_block(
                dcp::opt::CONTROL,
                dcp::sub::CONTROL_SIGNAL,
                false,
                &[0x01, 0x00],
            ));
        }
        blocks.push(dcp::set_request_block(
            dcp::opt::CONTROL,
            dcp::sub::CONTROL_STOP,
            false,
            &[],
        ));
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        let pdu = Pdu {
            frame_id: dcp::frame_id::GET_SET,
            service_id: dcp::service::SET,
            service_type: dcp::service_type::REQUEST,
            xid,
            response_delay: 0,
            blocks,
        };
        self.tx
            .send(rt::build_eth(device.mac, self.mac, None, &pdu.encode()?))?;
        self.dcp_set = Some(DcpSetRun {
            xid,
            mac: device.mac,
            until: Instant::now() + DCP_SET_TIMEOUT,
            depth,
        });
        Ok(format!("DCP Set sent to {}", dcp::format_mac(&device.mac)))
    }

    fn set_outputs(&mut self, v: &Value) -> Result<String> {
        let u = crate::server::profinet::actions::input_update(v)?;
        let ar = self.ar.as_ref().context("no AR: profinet_connect first")?;
        let spec = ar
            .plan
            .specs
            .iter()
            .find(|s| s.slot == u.slot && s.subslot == u.subslot)
            .with_context(|| format!("slot {}/{} is not in the AR", u.slot, u.subslot))?;
        anyhow::ensure!(
            !spec.outputs.is_empty(),
            "slot {}/{} has no output fields",
            u.slot,
            u.subslot
        );
        let mut image = ar.image.lock().expect("output image");
        let entry = image
            .outputs
            .get_mut(&(u.slot, u.subslot))
            .context("no output entry")?;
        let mut next = entry.0.clone();
        values::encode_into(&spec.outputs, &u.values, &mut next)?;
        *entry = (next, u.good);
        Ok(format!("outputs of {}/{} set", u.slot, u.subslot))
    }

    fn next_call(
        &mut self,
        op: u16,
        object: Uuid,
        body_blocks: &[u8],
    ) -> Result<(Uuid, u32, Vec<u8>)> {
        self.seq = self.seq.wrapping_add(1);
        let header = rpc::Header::request(object, rpc::IF_DEVICE, self.activity, self.seq, op);
        let body = rpc::ndr_request(rpc::MAX_BODY_LEN as u32, body_blocks);
        Ok((self.activity, self.seq, rpc::encode(&header, &body)?))
    }

    async fn send_call(
        &mut self,
        op: u16,
        object: Uuid,
        blocks: &[u8],
        dest: SocketAddr,
        purpose: Purpose,
        depth: u32,
    ) -> Result<()> {
        let (activity, seq, datagram) = self.next_call(op, object, blocks)?;
        self.rpc
            .send_to(&datagram, dest)
            .await
            .with_context(|| format!("sending {} to {dest}", opnum::name(op)))?;
        self.call = Some(Call {
            activity,
            seq,
            datagram,
            dest,
            attempts: 1,
            last_sent: Instant::now(),
            purpose,
            depth,
        });
        Ok(())
    }

    fn device_object(d: &DiscoveredDevice) -> Uuid {
        rpc::object_uuid(1, d.device_id.unwrap_or(0), d.vendor_id.unwrap_or(0))
    }

    async fn connect_device(&mut self, v: &Value, depth: u32) -> Result<String> {
        anyhow::ensure!(
            self.ar.is_none(),
            "an AR is already running; profinet_release first"
        );
        anyhow::ensure!(
            self.call.is_none(),
            "an RPC call is still waiting for its answer"
        );
        let device = self.find_device(v)?;
        let name = device.name_of_station.clone().unwrap_or_default();
        let ip = device
            .ip
            .map(|i| i.ip)
            .filter(|ip| !ip.is_unspecified())
            .with_context(|| {
                format!("device {name:?} reported no IP address; give it one with profinet_dcp_set")
            })?;
        let dest = SocketAddr::new(IpAddr::V4(ip), self.cfg.rpc_port);
        let specs = values::parse_layout(&v["submodules"])?;
        let cycle_ms = v
            .get("cycle_ms")
            .and_then(Value::as_u64)
            .unwrap_or(actions::DEFAULT_CYCLE_MS);
        anyhow::ensure!(
            cycle_ms >= 1 && rt::valid_reduction_ratio(cycle_ms as u16) && cycle_ms <= 512,
            "cycle_ms must be 1, 2, 4 … 512"
        );
        let watchdog_factor = v
            .get("watchdog_factor")
            .and_then(Value::as_u64)
            .unwrap_or(actions::DEFAULT_WATCHDOG_FACTOR);
        anyhow::ensure!(
            (3..=7680).contains(&watchdog_factor),
            "watchdog_factor must be 3-7680"
        );
        let mut parameters = Vec::new();
        if let Some(Value::Array(ps)) = v.get("parameters") {
            anyhow::ensure!(ps.len() <= 16, "at most 16 parameters");
            for (i, p) in ps.iter().enumerate() {
                let slot = p
                    .get("slot")
                    .and_then(Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok())
                    .with_context(|| format!("parameters[{i}].slot"))?;
                let subslot = p
                    .get("subslot")
                    .and_then(Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok())
                    .with_context(|| format!("parameters[{i}].subslot"))?;
                let index = actions::record_index(p.get("index"))?;
                let data = crate::server::profinet::actions::typed_fields_bytes(
                    p.get("fields")
                        .with_context(|| format!("parameters[{i}].fields"))?,
                )?;
                parameters.push((slot, subslot, index, data));
            }
        }
        let input = CrLayout::for_controller(&specs, true)?;
        let output = CrLayout::for_controller(&specs, false)?;
        let ar = ArBlockReq {
            ar_type: blocks::ar_type::IOC_AR_SINGLE,
            ar_uuid: rpc::random_uuid(),
            session_key: 1,
            initiator_mac: self.mac,
            initiator_object_uuid: rpc::object_uuid(1, 0x0001, 0x0000),
            ar_properties: 0x0000_0011,
            activity_timeout_factor: 600,
            initiator_udp_rt_port: dcp::ETHERTYPE_PROFINET,
            station_name: self.cfg.station_name.clone(),
        };
        let plan = Plan {
            device: device.clone(),
            name: name.clone(),
            dest,
            specs,
            ar,
            input,
            output,
            input_frame_id: 0xc001,
            output_frame_id: 0xffff,
            send_clock_factor: 32,
            reduction_ratio: cycle_ms as u16,
            watchdog_factor: watchdog_factor as u16,
            parameters,
            module_diff: Vec::new(),
        };
        let blocks = connect_blocks(&plan)?;
        self.activity = rpc::random_uuid();
        self.seq = 0;
        let object = Self::device_object(&device);
        self.send_call(
            opnum::CONNECT,
            object,
            &blocks,
            dest,
            Purpose::Connect(Box::new(plan)),
            depth,
        )
        .await?;
        Ok(format!("Connect sent to {name} at {dest}"))
    }

    async fn read_record(&mut self, v: &Value, depth: u32) -> Result<String> {
        anyhow::ensure!(
            self.call.is_none(),
            "an RPC call is still waiting for its answer"
        );
        let index = actions::record_index(v.get("index"))?;
        let slot = v.get("slot").and_then(Value::as_u64).unwrap_or(0) as u16;
        let subslot = v.get("subslot").and_then(Value::as_u64).unwrap_or(1) as u16;
        let implicit_target = v.get("name_of_station").and_then(Value::as_str);
        self.record_seq = self.record_seq.wrapping_add(1);
        let (device, ar_uuid, op) = match (&self.ar, implicit_target) {
            (Some(ar), None) => (ar.plan.device.clone(), ar.plan.ar.ar_uuid, opnum::READ),
            (_, Some(_)) | (None, None) => (self.find_device(v)?, [0u8; 16], opnum::READ_IMPLICIT),
        };
        let ip = device
            .ip
            .map(|i| i.ip)
            .context("the device reported no IP address")?;
        let rec = RecordRequest {
            write: false,
            seq: self.record_seq,
            ar_uuid,
            api: 0,
            slot,
            subslot,
            index,
            record_data_length: blocks::MAX_RECORD_LEN,
            target_ar_uuid: [0; 16],
        };
        if op == opnum::READ_IMPLICIT {
            self.activity = rpc::random_uuid();
            self.seq = 0;
        }
        let dest = SocketAddr::new(IpAddr::V4(ip), self.cfg.rpc_port);
        self.send_call(
            op,
            Self::device_object(&device),
            &rec.encode(),
            dest,
            Purpose::Read { rec },
            depth,
        )
        .await?;
        Ok(format!(
            "{} of {} sent",
            opnum::name(op),
            blocks::index::name(index)
        ))
    }

    async fn write_record(&mut self, v: &Value, depth: u32) -> Result<String> {
        anyhow::ensure!(
            self.call.is_none(),
            "an RPC call is still waiting for its answer"
        );
        let ar = self
            .ar
            .as_ref()
            .context("a record write needs an AR: profinet_connect first")?;
        let (index, data) = actions::write_record_bytes(v)?;
        let slot = v.get("slot").and_then(Value::as_u64).unwrap_or(0) as u16;
        let subslot = v.get("subslot").and_then(Value::as_u64).unwrap_or(1) as u16;
        self.record_seq = self.record_seq.wrapping_add(1);
        let rec = RecordRequest {
            write: true,
            seq: self.record_seq,
            ar_uuid: ar.plan.ar.ar_uuid,
            api: 0,
            slot,
            subslot,
            index,
            record_data_length: data.len() as u32,
            target_ar_uuid: [0; 16],
        };
        let mut b = rec.encode();
        b.extend_from_slice(&data);
        let (dest, object) = (ar.plan.dest, Self::device_object(&ar.plan.device));
        self.send_call(
            opnum::WRITE,
            object,
            &b,
            dest,
            Purpose::Write { index },
            depth,
        )
        .await?;
        Ok(format!("Write of {} sent", blocks::index::name(index)))
    }

    async fn release(&mut self, depth: u32) -> Result<String> {
        anyhow::ensure!(
            self.call.is_none(),
            "an RPC call is still waiting for its answer"
        );
        let ar = self.ar.as_ref().context("no AR to release")?;
        let block = ControlBlock {
            block_type: block_type::RELEASE_REQ,
            ar_uuid: ar.plan.ar.ar_uuid,
            session_key: ar.plan.ar.session_key,
            control_command: control_command::RELEASE,
            properties: 0,
        }
        .encode();
        let (dest, object) = (ar.plan.dest, Self::device_object(&ar.plan.device));
        self.send_call(
            opnum::RELEASE,
            object,
            &block,
            dest,
            Purpose::Release,
            depth,
        )
        .await?;
        Ok("Release sent".into())
    }

    async fn release_quietly(&mut self) {
        if self.ar.is_some() && self.call.is_none() {
            let _ = self.release(0).await;
        }
        if let Some(ar) = self.ar.take() {
            ar.provider.abort();
        }
    }

    fn close_ar(&mut self, reason: &str, depth: u32) {
        if let Some(ar) = self.ar.take() {
            ar.provider.abort();
            self.log().info(format!(
                "PROFINET AR with {} closed: {reason}",
                ar.plan.name
            ));
            self.emit(
                &actions::AR_CLOSED_EVENT,
                json!({"reason": reason, "name_of_station": ar.plan.name}),
                depth,
            );
        }
    }

    // ------------------------------------------------------------------ layer 2

    fn on_frame(&mut self, f: EthFrame) {
        let Some(fid) = rt::frame_id_of(&f.payload) else {
            return;
        };
        if dcp::is_dcp_frame_id(fid) {
            if f.dst != self.mac {
                return;
            }
            let Ok(pdu) = Pdu::parse(&f.payload) else {
                return;
            };
            match (pdu.frame_id, pdu.service_id) {
                (dcp::frame_id::IDENTIFY_RESPONSE, dcp::service::IDENTIFY) => {
                    self.log().debug(format!(
                        "PROFINET Identify answer from {} (xid {})",
                        dcp::format_mac(&f.src),
                        pdu.xid
                    ));
                    if self.identify.as_ref().is_some_and(|i| i.xid == pdu.xid) {
                        let d = DiscoveredDevice::from_blocks(f.src, &pdu.blocks);
                        if let Some(x) = self.devices.iter_mut().find(|x| x.mac == d.mac) {
                            *x = d;
                        } else if self.devices.len() < MAX_DEVICES {
                            self.devices.push(d);
                        }
                    }
                }
                (dcp::frame_id::GET_SET, dcp::service::SET) => {
                    let Some(run) = self.dcp_set.take_if(|r| r.xid == pdu.xid && r.mac == f.src)
                    else {
                        return;
                    };
                    let data = match dcp::parse_set_response(&pdu) {
                        Ok(results) => {
                            let list: Vec<Value> = results
                                .iter()
                                .filter(|((o, s), _)| *o != dcp::opt::CONTROL || *s == dcp::sub::CONTROL_SIGNAL)
                                .map(|((o, s), e)| {
                                    let name = match (*o, *s) {
                                        (dcp::opt::DEVICE, dcp::sub::DEVICE_NAME_OF_STATION) => "name_of_station".to_string(),
                                        (dcp::opt::IP, dcp::sub::IP_PARAMETER) => "ip".to_string(),
                                        (dcp::opt::CONTROL, dcp::sub::CONTROL_SIGNAL) => "signal".to_string(),
                                        (o, s) => format!("{o:#04x}/{s:#04x}"),
                                    };
                                    json!({"option": name, "ok": *e == dcp::block_error::OK, "error": dcp::block_error::name(*e)})
                                })
                                .collect();
                            json!({"mac": dcp::format_mac(&run.mac), "results": list})
                        }
                        Err(e) => {
                            json!({"mac": dcp::format_mac(&run.mac), "error": format!("{e:#}")})
                        }
                    };
                    self.emit(&actions::DCP_SET_RESULT_EVENT, data, run.depth + 1);
                }
                _ => {}
            }
            return;
        }
        let Some(ar) = &mut self.ar else {
            return;
        };
        if fid != ar.plan.input_frame_id || f.src != ar.plan.device.mac {
            return;
        }
        let Ok(frame) = rt::parse_rt(&f.payload, ar.plan.input.data_length) else {
            return;
        };
        ar.last_rx = Some(Instant::now());
        for o in &ar.plan.input.objects {
            let data = frame.c_sdu[o.offset..o.offset + o.len].to_vec();
            let iops = frame.c_sdu[o.iops_offset()];
            let key = (o.slot, o.subslot);
            if o.len == 0 && ar.current.contains_key(&key) && ar.current[&key].1 == iops {
                continue;
            }
            if ar.current.get(&key) != Some(&(data.clone(), iops)) {
                ar.current.insert(key, (data, iops));
                ar.changed.insert(key);
            }
        }
    }

    // ------------------------------------------------------------------ RPC

    async fn on_rpc(&mut self, d: &[u8], from: SocketAddr) {
        let Ok((hdr, body)) = rpc::parse(d) else {
            return;
        };
        let body = body.to_vec();
        if hdr.ptype == ptype::REQUEST && hdr.interface == rpc::IF_CONTROLLER {
            self.on_ccontrol(&hdr, &body, from).await;
            return;
        }
        if !matches!(hdr.ptype, ptype::RESPONSE | ptype::FAULT | ptype::REJECT) {
            return;
        }
        let Some(call) = self
            .call
            .take_if(|c| c.activity == hdr.activity && c.seq == hdr.seqnum)
        else {
            return;
        };
        let answer: Result<(PnioStatus, Vec<u8>)> = if hdr.ptype == ptype::RESPONSE {
            rpc::parse_ndr_response(&body, hdr.little_endian).map(|(s, b)| (s, b.to_vec()))
        } else {
            Err(anyhow::anyhow!(
                "the device answered with a DCE/RPC {} (status {:#010x})",
                if hdr.ptype == ptype::FAULT {
                    "FAULT"
                } else {
                    "REJECT"
                },
                body.get(..4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(0)
            ))
        };
        self.on_answer(call, answer).await;
    }

    async fn on_answer(&mut self, call: Call, answer: Result<(PnioStatus, Vec<u8>)>) {
        let depth = call.depth + 1;
        match call.purpose {
            Purpose::Connect(mut plan) => {
                let (status, blocks_data) = match answer {
                    Ok(x) => x,
                    Err(e) => {
                        return self.connect_failed(&plan, "connect", format!("{e:#}"), depth)
                    }
                };
                if !status.is_ok() {
                    return self.connect_failed(
                        &plan,
                        "connect",
                        format!("refused: PNIO status {}", status.describe()),
                        depth,
                    );
                }
                let parsed = blocks::split_blocks(&blocks_data);
                let Ok(raw) = parsed else {
                    return self.connect_failed(
                        &plan,
                        "connect",
                        "unreadable Connect response".into(),
                        depth,
                    );
                };
                let mut got_output = false;
                for b in &raw {
                    match b.block_type {
                        block_type::IOCR_RES => {
                            if let Ok(r) = blocks::IocrBlockRes::parse(b.body) {
                                if r.iocr_type == iocr_type::OUTPUT
                                    && rt::RT_CLASS_1_FRAME_IDS.contains(&r.frame_id)
                                {
                                    plan.output_frame_id = r.frame_id;
                                    got_output = true;
                                } else if r.iocr_type == iocr_type::INPUT
                                    && rt::RT_CLASS_1_FRAME_IDS.contains(&r.frame_id)
                                {
                                    plan.input_frame_id = r.frame_id;
                                }
                            }
                        }
                        block_type::MODULE_DIFF => {
                            if let Ok(diffs) = blocks::parse_module_diff(b.body) {
                                for d in diffs {
                                    for (subslot, ident, state) in d.submodules {
                                        plan.module_diff.push(json!({
                                            "slot": d.slot, "subslot": subslot,
                                            "module_state": blocks::module_state_name(d.module_state),
                                            "module_ident": format!("{:#010x}", d.module_ident),
                                            "submodule_ident": format!("{ident:#010x}"),
                                            "state": blocks::submodule_state::name(state),
                                        }));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if !got_output {
                    return self.connect_failed(
                        &plan,
                        "connect",
                        "the response assigned no output FrameID".into(),
                        depth,
                    );
                }
                // The provider starts now: the device's consumer expects data from here on.
                self.start_ar(*plan).await;
                self.next_stage(depth).await;
            }
            Purpose::Parameter(plan) => {
                let ok = matches!(&answer, Ok((s, _)) if s.is_ok());
                if !ok {
                    let why = match answer {
                        Ok((s, _)) => format!("refused: PNIO status {}", s.describe()),
                        Err(e) => format!("{e:#}"),
                    };
                    self.abandon_ar();
                    return self.connect_failed(&plan, "parameters", why, depth);
                }
                if let Some(ar) = &mut self.ar {
                    ar.plan.parameters = plan.parameters;
                }
                self.next_stage(depth).await;
            }
            Purpose::PrmEnd(plan) => {
                let ok = matches!(&answer, Ok((s, _)) if s.is_ok());
                if !ok {
                    let why = match answer {
                        Ok((s, _)) => format!("refused: PNIO status {}", s.describe()),
                        Err(e) => format!("{e:#}"),
                    };
                    self.abandon_ar();
                    return self.connect_failed(&plan, "prm_end", why, depth);
                }
                if let Some(ar) = &mut self.ar {
                    if !ar.running {
                        ar.app_ready_deadline = Some(Instant::now() + APP_READY_TIMEOUT);
                    }
                }
            }
            Purpose::Read { rec } => {
                let mut data = json!({
                    "slot": rec.slot, "subslot": rec.subslot, "index": rec.index,
                    "record": blocks::index::name(rec.index),
                });
                match answer.and_then(|(s, b)| {
                    if s.is_ok() {
                        blocks::parse_read_response(&b).map(|(_, d)| d)
                    } else {
                        Err(anyhow::anyhow!("PNIO status {}", s.describe()))
                    }
                }) {
                    Ok(record) => {
                        data["ok"] = json!(true);
                        data["length"] = json!(record.len());
                        describe_read(rec.index, &record, &mut data);
                    }
                    Err(e) => {
                        data["ok"] = json!(false);
                        data["error"] = json!(format!("{e:#}"));
                    }
                }
                self.emit(&actions::RECORD_READ_EVENT, data, depth);
            }
            Purpose::Write { index } => {
                let data = match answer {
                    Ok((s, _)) if s.is_ok() => json!({"index": index, "ok": true}),
                    Ok((s, _)) => {
                        json!({"index": index, "ok": false, "error": format!("PNIO status {}", s.describe())})
                    }
                    Err(e) => json!({"index": index, "ok": false, "error": format!("{e:#}")}),
                };
                self.emit(&actions::RECORD_WRITTEN_EVENT, data, depth);
            }
            Purpose::Release => {
                let why = match answer {
                    Ok((s, _)) if s.is_ok() => "released".to_string(),
                    Ok((s, _)) => format!("released (the device answered {})", s.describe()),
                    Err(e) => format!("released (no clean answer: {e:#})"),
                };
                self.close_ar(&why, depth);
            }
        }
    }

    fn connect_failed(&mut self, plan: &Plan, stage: &str, error: String, depth: u32) {
        self.log().warn(format!(
            "PROFINET Connect to {} failed at {stage}: {error}",
            plan.name
        ));
        self.emit(
            &actions::CONNECT_FAILED_EVENT,
            json!({"name_of_station": plan.name, "stage": stage, "error": error}),
            depth,
        );
    }

    fn abandon_ar(&mut self) {
        if let Some(ar) = self.ar.take() {
            ar.provider.abort();
        }
    }

    /// After Connect and after each parameter write: the next write, or PrmEnd.
    async fn next_stage(&mut self, depth: u32) {
        let Some(ar) = &mut self.ar else {
            return;
        };
        let plan_copy = |p: &Plan, parameters: Vec<(u16, u16, u16, Vec<u8>)>| Plan {
            device: p.device.clone(),
            name: p.name.clone(),
            dest: p.dest,
            specs: p.specs.clone(),
            ar: p.ar.clone(),
            input: p.input.clone(),
            output: p.output.clone(),
            input_frame_id: p.input_frame_id,
            output_frame_id: p.output_frame_id,
            send_clock_factor: p.send_clock_factor,
            reduction_ratio: p.reduction_ratio,
            watchdog_factor: p.watchdog_factor,
            parameters,
            module_diff: p.module_diff.clone(),
        };
        let object = Self::device_object(&ar.plan.device);
        let dest = ar.plan.dest;
        if let Some((slot, subslot, index, data)) = ar.plan.parameters.first().cloned() {
            let rest: Vec<_> = ar.plan.parameters[1..].to_vec();
            let carried = plan_copy(&ar.plan, rest);
            self.record_seq = self.record_seq.wrapping_add(1);
            let rec = RecordRequest {
                write: true,
                seq: self.record_seq,
                ar_uuid: carried.ar.ar_uuid,
                api: 0,
                slot,
                subslot,
                index,
                record_data_length: data.len() as u32,
                target_ar_uuid: [0; 16],
            };
            let mut b = rec.encode();
            b.extend_from_slice(&data);
            if let Err(e) = self
                .send_call(
                    opnum::WRITE,
                    object,
                    &b,
                    dest,
                    Purpose::Parameter(Box::new(carried)),
                    depth,
                )
                .await
            {
                self.log()
                    .warn(format!("PROFINET parameter write not sent: {e:#}"));
            }
            return;
        }
        let carried = plan_copy(&ar.plan, Vec::new());
        let block = ControlBlock {
            block_type: block_type::PRM_END_REQ,
            ar_uuid: carried.ar.ar_uuid,
            session_key: carried.ar.session_key,
            control_command: control_command::PRM_END,
            properties: 0,
        }
        .encode();
        if let Err(e) = self
            .send_call(
                opnum::CONTROL,
                object,
                &block,
                dest,
                Purpose::PrmEnd(Box::new(carried)),
                depth,
            )
            .await
        {
            self.log().warn(format!("PROFINET PrmEnd not sent: {e:#}"));
        }
    }

    async fn start_ar(&mut self, plan: Plan) {
        let image = Arc::new(Mutex::new(OutputImage {
            outputs: plan
                .specs
                .iter()
                .map(|s| ((s.slot, s.subslot), (vec![0; s.output_len()], false)))
                .collect(),
            iocs_good: false,
            running: false,
        }));
        let cycle = Duration::from_micros(rt::cycle_micros(
            plan.send_clock_factor,
            plan.reduction_ratio,
        ));
        let provider = Provider {
            tx: self.tx.clone(),
            src: self.mac,
            dst: plan.device.mac,
            frame_id: plan.output_frame_id,
            cycle,
            ticks: plan.send_clock_factor.wrapping_mul(plan.reduction_ratio),
            layout: plan.output.clone(),
            image: image.clone(),
        };
        let abort = self
            .ctx
            .state
            .spawn_client_task(self.ctx.client_id, provide(provider))
            .await;
        let watchdog = cycle * plan.watchdog_factor as u32;
        self.ar = Some(ArRun {
            plan,
            running: false,
            app_ready_deadline: None,
            image,
            provider: abort,
            last_rx: None,
            current: HashMap::new(),
            changed: HashSet::new(),
            last_event: None,
            watchdog,
            started: Instant::now(),
        });
    }

    async fn on_ccontrol(&mut self, hdr: &rpc::Header, body: &[u8], from: SocketAddr) {
        let reply = |status: PnioStatus, blocks: &[u8]| -> Option<Vec<u8>> {
            let h = hdr.response_to(ptype::RESPONSE, 0);
            rpc::encode(
                &h,
                &rpc::ndr_response(status, rpc::MAX_BODY_LEN as u32, blocks),
            )
            .ok()
        };
        let control = rpc::parse_ndr_request(body, hdr.little_endian)
            .ok()
            .and_then(|(_, b)| {
                blocks::split_blocks(b)
                    .ok()
                    .and_then(|v| v.first().copied())
            })
            .and_then(|b| ControlBlock::parse(&b).ok());
        let matches = |c: &ControlBlock| {
            self.ar.as_ref().is_some_and(|ar| {
                ar.plan.ar.ar_uuid == c.ar_uuid && ar.plan.ar.session_key == c.session_key
            })
        };
        let Some(c) = control.filter(|c| c.block_type == block_type::APP_READY_REQ && matches(c))
        else {
            let status = PnioStatus::new(
                rpc::error_code::CONTROL,
                rpc::error_decode::PNIO,
                rpc::connect_error::CONTROL_BLOCK,
                0,
            );
            if let Some(b) = reply(status, &[]) {
                let _ = self.rpc.send_to(&b, from).await;
            }
            return;
        };
        if let Some(b) = reply(PnioStatus::OK, &c.done().encode()) {
            let _ = self.rpc.send_to(&b, from).await;
        }
        let Some(ar) = &mut self.ar else {
            return;
        };
        if ar.running {
            return; // a retransmission
        }
        ar.running = true;
        ar.app_ready_deadline = None;
        ar.started = Instant::now();
        {
            let mut img = ar.image.lock().expect("output image");
            img.running = true;
            img.iocs_good = true;
        }
        let data = json!({
            "name_of_station": ar.plan.name,
            "ar_uuid": rpc::format_uuid(&ar.plan.ar.ar_uuid),
            "cycle_ms": rt::cycle_micros(ar.plan.send_clock_factor, ar.plan.reduction_ratio) as f64 / 1000.0,
            "module_diff": ar.plan.module_diff,
            "submodules": ar.plan.specs.iter().map(SubmoduleSpec::to_json).collect::<Vec<_>>(),
        });
        let name = ar.plan.name.clone();
        self.log()
            .info(format!("PROFINET AR with {name} is running"));
        self.emit(&actions::AR_ESTABLISHED_EVENT, data, 1);
    }

    // ------------------------------------------------------------------ the tick

    async fn on_tick(&mut self) {
        let now = Instant::now();
        if let Some(run) = self.identify.take_if(|r| now >= r.until) {
            let list: Vec<Value> = self.devices.iter().map(device_json).collect();
            self.log().info(format!(
                "PROFINET Identify: {} device(s) answered",
                list.len()
            ));
            self.emit(
                &actions::DEVICES_DISCOVERED_EVENT,
                json!({"devices": list}),
                run.depth + 1,
            );
        }
        if let Some(run) = self.dcp_set.take_if(|r| now >= r.until) {
            self.emit(
                &actions::DCP_SET_RESULT_EVENT,
                json!({"mac": dcp::format_mac(&run.mac), "error": "no answer within 3 s"}),
                run.depth + 1,
            );
        }
        let mut resend = None;
        let mut expired = None;
        if let Some(call) = &mut self.call {
            if now.duration_since(call.last_sent) >= RPC_RETRY {
                if call.attempts >= RPC_ATTEMPTS {
                    expired = self.call.take();
                } else {
                    call.attempts += 1;
                    call.last_sent = now;
                    resend = Some((call.datagram.clone(), call.dest));
                }
            }
        }
        if let Some((d, dest)) = resend {
            let _ = self.rpc.send_to(&d, dest).await;
        }
        if let Some(call) = expired {
            let what = match &call.purpose {
                Purpose::Connect(_) => "Connect",
                Purpose::Parameter(_) => "parameter Write",
                Purpose::PrmEnd(_) => "PrmEnd",
                Purpose::Read { .. } => "Read",
                Purpose::Write { .. } => "Write",
                Purpose::Release => "Release",
            };
            let err = anyhow::anyhow!("no answer to {what} after {RPC_ATTEMPTS} attempts");
            if matches!(call.purpose, Purpose::Parameter(_) | Purpose::PrmEnd(_)) {
                self.abandon_ar();
            }
            self.on_answer(call, Err(err)).await;
        }
        let mut close = None;
        let mut event = None;
        let mut no_app_ready = None;
        if let Some(ar) = &mut self.ar {
            if ar.app_ready_deadline.is_some_and(|d| now >= d) {
                no_app_ready = Some(ar.plan.name.clone());
            } else if ar.running {
                match ar.last_rx {
                    Some(last) if now.duration_since(last) > ar.watchdog => {
                        close = Some(format!("watchdog: no input frame for {:?}", ar.watchdog));
                    }
                    None if now.duration_since(ar.started)
                        > ar.watchdog.max(Duration::from_secs(5)) =>
                    {
                        close = Some("watchdog: the device never sent input data".to_string());
                    }
                    _ => {}
                }
                if close.is_none()
                    && !ar.changed.is_empty()
                    && ar
                        .last_event
                        .is_none_or(|t| now.duration_since(t) >= INPUT_EVENT_INTERVAL)
                {
                    let mut keys: Vec<(u16, u16)> = ar.changed.drain().collect();
                    keys.sort();
                    let list: Vec<Value> = keys
                        .iter()
                        .filter_map(|k| {
                            let (data, iops) = ar.current.get(k)?;
                            let fields = ar
                                .plan
                                .specs
                                .iter()
                                .find(|s| (s.slot, s.subslot) == *k)
                                .map(|s| s.inputs.clone())
                                .unwrap_or_default();
                            Some(json!({
                                "slot": k.0, "subslot": k.1,
                                "iops": if iops & 0x80 != 0 { "good" } else { "bad" },
                                "values": Value::Object(values::decode(&fields, data)),
                            }))
                        })
                        .collect();
                    ar.last_event = Some(now);
                    event = Some(json!({"inputs": list}));
                }
            }
        }
        if let Some(plan_name) = no_app_ready {
            self.abandon_ar();
            self.log().warn(format!(
                "PROFINET Connect to {plan_name} failed: no ApplicationReady"
            ));
            self.emit(
                &actions::CONNECT_FAILED_EVENT,
                json!({"name_of_station": plan_name, "stage": "application_ready",
                       "error": format!("the device sent no ApplicationReady within {APP_READY_TIMEOUT:?}")}),
                1,
            );
            return;
        }
        if let Some(data) = event {
            self.emit(&actions::INPUTS_CHANGED_EVENT, data, 1);
        }
        if let Some(reason) = close {
            self.close_ar(&reason, 1);
        }
    }
}

/// The Connect request's blocks for a plan.
fn connect_blocks(plan: &Plan) -> Result<Vec<u8>> {
    let mut out = plan.ar.encode();
    for (kind, layout, frame_id, reference) in [
        (iocr_type::INPUT, &plan.input, plan.input_frame_id, 1u16),
        (iocr_type::OUTPUT, &plan.output, plan.output_frame_id, 2u16),
    ] {
        let (io_data, iocs) = layout.descriptors();
        out.extend(
            IocrBlockReq {
                iocr_type: kind,
                iocr_reference: reference,
                lt: dcp::ETHERTYPE_PROFINET,
                properties: blocks::RT_CLASS_1,
                data_length: layout.data_length as u16,
                frame_id,
                send_clock_factor: plan.send_clock_factor,
                reduction_ratio: plan.reduction_ratio,
                phase: 1,
                sequence: 0,
                frame_send_offset: 0xffff_ffff,
                watchdog_factor: plan.watchdog_factor,
                data_hold_factor: plan.watchdog_factor,
                tag_header: 0xc000,
                multicast_mac: [0; 6],
                apis: vec![IocrApi {
                    api: 0,
                    io_data,
                    iocs,
                }],
            }
            .encode(),
        );
    }
    out.extend(
        blocks::AlarmCrBlockReq {
            alarm_cr_type: 1,
            lt: dcp::ETHERTYPE_PROFINET,
            properties: 0,
            rta_timeout_factor: 100,
            rta_retries: 3,
            local_alarm_reference: 1,
            max_alarm_data_length: 200,
            tag_header_high: 0xc000,
            tag_header_low: 0xa000,
        }
        .encode(),
    );
    let mut slots: Vec<u16> = plan.specs.iter().map(|s| s.slot).collect();
    slots.sort();
    slots.dedup();
    let expected: Vec<blocks::ExpectedSubmodule> =
        plan.specs.iter().map(SubmoduleSpec::to_expected).collect();
    for slot in slots {
        let subs: Vec<&blocks::ExpectedSubmodule> =
            expected.iter().filter(|e| e.slot == slot).collect();
        out.extend(blocks::encode_expected_slot(&subs)?);
    }
    anyhow::ensure!(
        out.len() + rpc::NDR_HEADER_LEN <= rpc::MAX_BODY_LEN,
        "this layout's Connect is {} octets, more than one unfragmented RPC datagram carries",
        out.len()
    );
    Ok(out)
}

/// Decode a record read into the event, without ever handing over bytes.
fn describe_read(index: u16, record: &[u8], data: &mut Value) {
    match index {
        blocks::index::IM0 => {
            if let Ok(im0) = blocks::Im0::parse(record) {
                let supported: Vec<u16> = (1..16)
                    .filter(|n| im0.im_supported & (1 << n) != 0)
                    .collect();
                data["im0"] = json!({
                    "vendor_id": im0.vendor_id,
                    "order_id": im0.order_id,
                    "serial_number": im0.serial_number,
                    "hardware_revision": im0.hardware_revision,
                    "software_revision": im0.software_revision_text(),
                    "revision_counter": im0.revision_counter,
                    "profile_id": im0.profile_id,
                    "profile_specific_type": im0.profile_specific_type,
                    "im_version": format!("{}.{}", im0.im_version.0, im0.im_version.1),
                    "im_supported": supported,
                });
            }
        }
        blocks::index::IM1 | blocks::index::IM2 | blocks::index::IM3 => {
            if let Ok(t) = blocks::ImText::parse(record) {
                data["decoded"] = match t {
                    blocks::ImText::Im1 {
                        tag_function,
                        tag_location,
                    } => json!({"tag_function": tag_function, "tag_location": tag_location}),
                    blocks::ImText::Im2 { installation_date } => {
                        json!({"installation_date": installation_date})
                    }
                    blocks::ImText::Im3 { descriptor } => json!({"descriptor": descriptor}),
                };
            }
        }
        _ => {
            let mut m = Map::new();
            match record.len() {
                1 => {
                    m.insert("u8".into(), json!(record[0]));
                }
                2 => {
                    m.insert(
                        "u16".into(),
                        json!(u16::from_be_bytes([record[0], record[1]])),
                    );
                }
                4 => {
                    let b = [record[0], record[1], record[2], record[3]];
                    m.insert("u32".into(), json!(u32::from_be_bytes(b)));
                    m.insert("i32".into(), json!(i32::from_be_bytes(b)));
                }
                _ => {}
            }
            if !record.is_empty() && record.iter().all(|c| (0x20..0x7f).contains(c)) {
                m.insert("text".into(), json!(String::from_utf8_lossy(record)));
            }
            if !m.is_empty() {
                data["decoded"] = Value::Object(m);
            }
        }
    }
}

struct Provider {
    tx: L2Tx,
    src: [u8; 6],
    dst: [u8; 6],
    frame_id: u16,
    cycle: Duration,
    ticks: u16,
    layout: CrLayout,
    image: Arc<Mutex<OutputImage>>,
}

/// Send the output image every cycle until aborted.
async fn provide(p: Provider) {
    let mut interval = tokio::time::interval(p.cycle);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut counter: u16 = 0;
    loop {
        interval.tick().await;
        let mut c_sdu = vec![0u8; p.layout.data_length];
        let status = {
            let img = p.image.lock().expect("output image");
            for o in &p.layout.objects {
                let mut iops = rt::IOXS_BAD;
                if let Some((data, good)) = img.outputs.get(&(o.slot, o.subslot)) {
                    let n = o.len.min(data.len());
                    c_sdu[o.offset..o.offset + n].copy_from_slice(&data[..n]);
                    if *good {
                        iops = rt::IOXS_GOOD;
                    }
                }
                c_sdu[o.iops_offset()] = iops;
            }
            let iocs = if img.iocs_good {
                rt::IOXS_GOOD
            } else {
                rt::IOXS_BAD
            };
            for c in &p.layout.iocs {
                c_sdu[c.offset] = iocs;
            }
            if img.running {
                rt::data_status::GOOD
            } else {
                rt::data_status::STOP
            }
        };
        counter = counter.wrapping_add(p.ticks);
        let frame = rt::build_eth(
            p.dst,
            p.src,
            Some(0xc000),
            &rt::build_rt(p.frame_id, &c_sdu, counter, status),
        );
        let _ = p.tx.send(frame);
    }
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = ProfinetClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "PROFINET controller {} not asking the model about {}: {depth} turns deep decision=followup_depth",
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
                if result.actions.is_empty() {
                    tracing::debug!(
                        "PROFINET controller {}: {} answered with nothing decision=model_silent",
                        ctx.client_id,
                        event.id()
                    );
                }
                for action in result.actions {
                    if internal.send((action, depth)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "PROFINET controller {}: {} not answered; nothing sent, outputs unchanged decision={tag}: {e}",
                    ctx.client_id,
                    event.id()
                ))
            }
        }
    }
}
