//! The model-facing network both host dialects share: the devices behind the co-processor,
//! who joins when the host opens the network, how a device answers what the host sends it
//! (from its description, or by asking the model), and what the dashboard or MCP injects.
//!
//! Everything here speaks in [`Up`] — what the network tells the host — and never in a
//! dialect's frames: the EZSP session turns an `Up` into `incomingMessageHandler`,
//! `childJoinHandler` and `trustCenterJoinHandler` callbacks, the Z-Stack session into
//! `AF_INCOMING_MSG`, the `ZDO_*_RSP`/`ZDO_MSG_CB_INCOMING` indications, `ZDO_TC_DEV_IND` and
//! `ZDO_LEAVE_IND`. Only the host link differs.
use super::actions;
use super::device::{self, Device, ZclOutcome, ZclRequest};
use super::ezsp::ApsFrame;
use super::ncp::{self, Nvram};
use super::{ask, Deferred, Shared};
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::AccessLogOwner;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// What the network tells the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Up {
    /// A frame from a device, or from the coordinator's own ZDO, to the host.
    Incoming {
        broadcast: bool,
        aps: ApsFrame,
        nwk: u16,
        ieee: u64,
        payload: Vec<u8>,
    },
    /// An end device joined (`joining`) or left the coordinator's child table.
    Child {
        index: u8,
        joining: bool,
        nwk: u16,
        ieee: u64,
        node_type: u8,
    },
    /// The trust center admitted a device (`joined`) or saw it leave.
    TrustCenter { nwk: u16, ieee: u64, joined: bool },
}

/// What the network needs to know about the host link at the moment it acts.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// The co-processor's network is up.
    pub up: bool,
    /// The host opened the network for joining.
    pub permit_open: bool,
    /// The host endpoint device-originated frames go to.
    pub host_endpoint: u8,
    /// End devices the coordinator takes as children.
    pub max_children: usize,
    /// The coordinator as ZDO describes it: the endpoints the host registered.
    pub endpoints: Vec<device::Endpoint>,
    pub manufacturer_code: u16,
}

impl View {
    /// The coordinator as the host sees it through ZDO.
    pub fn coordinator(&self, nv: &Nvram) -> Device {
        Device {
            name: "coordinator".into(),
            ieee: nv.eui64,
            nwk: ncp::COORDINATOR_NWK,
            kind: device::Kind::Router,
            manufacturer_code: self.manufacturer_code,
            mains_powered: true,
            endpoints: self.endpoints.clone(),
            zcl_tsn: 0,
            aps_counter: 0,
        }
    }

    /// The first Home Automation endpoint the host registered, else its first, else 1.
    pub fn host_endpoint_of(endpoints: &[device::Endpoint]) -> u8 {
        endpoints
            .iter()
            .find(|e| e.profile == device::PROFILE_HA)
            .or_else(|| endpoints.first())
            .map(|e| e.id)
            .unwrap_or(1)
    }
}

/// One host session's view of the network: the shared co-processor state, the connection,
/// the channel model answers come back on, and what is waiting to go to the host.
pub struct Net {
    pub shared: Arc<Shared>,
    pub id: ConnectionId,
    pub deferred: mpsc::Sender<Deferred>,
    pub out: Vec<Up>,
}

impl Net {
    pub fn new(shared: Arc<Shared>, id: ConnectionId, deferred: mpsc::Sender<Deferred>) -> Self {
        Self {
            shared,
            id,
            deferred,
            out: Vec::new(),
        }
    }

    /// What is waiting for the host, oldest first.
    pub fn drain(&mut self) -> Vec<Up> {
        std::mem::take(&mut self.out)
    }

    /// A unicast the host sent: the coordinator's own ZDO, a joined device's ZDO, or a ZCL
    /// frame its description answers or the model is asked about. `false` when nobody with
    /// that address is in the network (the host's delivery fails).
    pub async fn unicast(&mut self, view: &View, nwk: u16, aps: ApsFrame, message: &[u8]) -> bool {
        if nwk == ncp::COORDINATOR_NWK {
            // The coordinator's own stack answers ZDO addressed to it, from the endpoints the
            // host registered; anything else to itself is acknowledged and goes nowhere.
            if aps.profile_id == device::PROFILE_ZDO {
                let reply = {
                    let nv = self.shared.nv();
                    let coordinator = view.coordinator(&nv);
                    coordinator_zdo(&coordinator, view, aps.cluster_id, message)
                        .map(|(c, p)| from_device(&coordinator, &aps, c, 0, &p))
                };
                if let Some(up) = reply {
                    self.out.push(up);
                }
            }
            return true;
        }
        let found = {
            let nv = self.shared.nv();
            nv.joined_by_nwk(nwk).map(|i| nv.joined[i].clone())
        };
        let Some(dev) = found else {
            return false;
        };
        if aps.profile_id == device::PROFILE_ZDO {
            if let Some(r) = device::zdo(&dev, aps.cluster_id, message, false) {
                self.out
                    .push(from_device(&dev, &aps, r.cluster, 0, &r.payload));
                self.record(
                    &dev,
                    "zigbee_zdo_from_description",
                    json!({"cluster": format!("0x{:04x}", aps.cluster_id)}),
                    "description",
                )
                .await;
                if r.leave_after {
                    self.leave(dev.ieee);
                }
            }
            return true;
        }
        match device::zcl(&dev, aps.destination_endpoint, aps.cluster_id, message) {
            ZclOutcome::Nothing => {}
            ZclOutcome::Reply(frame) => {
                let up = {
                    let nv = self.shared.nv();
                    let Some(i) = nv.joined_by_ieee(dev.ieee) else {
                        return true;
                    };
                    from_device(
                        &nv.joined[i],
                        &aps,
                        aps.cluster_id,
                        aps.destination_endpoint,
                        &frame,
                    )
                };
                self.out.push(up);
                self.record(
                    &dev,
                    "zigbee_zcl_from_description",
                    json!({"cluster": device::cluster_name(aps.cluster_id), "endpoint": aps.destination_endpoint}),
                    "description",
                )
                .await;
            }
            ZclOutcome::Ask(request) => {
                self.ask_zcl(&dev, request, aps.source_endpoint, aps.profile_id)
                    .await
            }
        }
        true
    }

    /// A ZDO broadcast the host sent: every joined device that answers it does.
    pub fn broadcast_zdo(&mut self, aps: &ApsFrame, message: &[u8]) {
        let nv = self.shared.nv();
        for d in nv.joined.iter() {
            if let Some(r) = device::zdo(d, aps.cluster_id, message, true) {
                self.out.push(from_device(d, aps, r.cluster, 0, &r.payload));
            }
        }
    }

    async fn record(&self, dev: &Device, kind: &str, request: Value, answered_by: &str) {
        self.shared
            .ctx
            .state
            .record_access_log_only(
                AccessLogOwner::Server(self.shared.ctx.server_id.as_u32()),
                "Zigbee",
                Some(self.id.as_u32()),
                kind,
                json!({"device": dev.name, "request": request}),
                vec![json!({"answered_by": answered_by})],
            )
            .await;
    }

    /// The host opened the network: ask the model who joins.
    pub async fn ask_permit(&mut self, secs: u8) {
        let event = {
            let nv = self.shared.nv();
            let (channel, pan) = nv
                .network
                .as_ref()
                .map(|n| (n.params.radio_channel, n.params.pan_id))
                .unwrap_or((0, 0));
            Event::new(
                &actions::PERMIT_EVENT,
                json!({
                    "duration_secs": secs,
                    "waiting_devices": nv.waiting.iter().map(Device::summary).collect::<Vec<_>>(),
                    "joined_devices": nv.joined.iter().map(|d| d.name.clone()).collect::<Vec<_>>(),
                    "channel": channel,
                    "pan_id": format!("0x{pan:04x}"),
                }),
            )
        };
        let shared = self.shared.clone();
        let tx = self.deferred.clone();
        let id = self.id;
        let state = shared.ctx.state.clone();
        let server_id = shared.ctx.server_id;
        state
            .spawn_server_task(server_id, async move {
                let answers = ask(
                    &shared,
                    id,
                    &event,
                    &[actions::JOIN_DEVICE, actions::IGNORE],
                )
                .await;
                let _ = tx.send(Deferred::Permit { answers }).await;
            })
            .await;
    }

    async fn ask_zcl(
        &mut self,
        dev: &Device,
        request: ZclRequest,
        host_endpoint: u8,
        profile: u16,
    ) {
        let kind = match request.kind {
            device::RequestKind::ClusterCommand => "cluster_command",
            device::RequestKind::WriteAttributes { .. } => "write_attributes",
            device::RequestKind::ManufacturerGlobal => "manufacturer_global",
        };
        let command = if request.header.cluster_specific() {
            device::command_name(request.cluster, request.header.command)
        } else {
            format!("0x{:02x}", request.header.command)
        };
        let event = Event::new(
            &actions::ZCL_EVENT,
            json!({
                "device": dev.name,
                "ieee": device::eui_display(dev.ieee),
                "nwk": format!("0x{:04x}", dev.nwk),
                "endpoint": request.endpoint,
                "cluster": device::cluster_name(request.cluster),
                "kind": kind,
                "command": command,
                "command_id": request.header.command,
                "manufacturer_code": request.header.manufacturer,
                "default_response_disabled": request.header.default_response_disabled(),
                "fields": request.fields,
                "payload": hex::encode(&request.payload),
                "payload_encoding": "hex",
                "current_attributes": dev.cluster_values(request.endpoint, request.cluster),
            }),
        );
        let shared = self.shared.clone();
        let tx = self.deferred.clone();
        let id = self.id;
        let ieee = dev.ieee;
        let state = shared.ctx.state.clone();
        let server_id = shared.ctx.server_id;
        state
            .spawn_server_task(server_id, async move {
                let answers = ask(
                    &shared,
                    id,
                    &event,
                    &[
                        actions::DEFAULT_RESPONSE,
                        actions::SET_ATTRIBUTES,
                        actions::CLUSTER_RESPONSE,
                        actions::NO_RESPONSE,
                    ],
                )
                .await;
                let _ = tx
                    .send(Deferred::Zcl {
                        ieee,
                        request,
                        host_endpoint,
                        profile,
                        answers,
                    })
                    .await;
            })
            .await;
    }

    /// A model answer came back: the devices that join, or the device's reply.
    pub fn apply_deferred(&mut self, view: &View, d: Deferred) {
        match d {
            Deferred::Permit { answers } => match answers {
                Err(f) => self
                    .shared
                    .outcome("permit_joining", "-", f.decision(), &f.detail()),
                Ok(list) => {
                    let mut joined = Vec::new();
                    let mut why = None;
                    for a in list
                        .iter()
                        .filter(|a| a["type"] == actions::JOIN_DEVICE)
                        .take(actions::MAX_JOINS_PER_ANSWER)
                    {
                        match self.join(view, &a["device"]) {
                            Ok(name) => joined.push(name),
                            Err(e) => why = Some(e.to_string()),
                        }
                    }
                    match (joined.is_empty(), why) {
                        (_, Some(why)) => self.shared.outcome(
                            "permit_joining",
                            &joined.join(","),
                            "fail_closed_invalid_reply",
                            &why,
                        ),
                        (true, None) => self.shared.outcome(
                            "permit_joining",
                            "-",
                            "model_reject",
                            "no device joins",
                        ),
                        (false, None) => self.shared.outcome(
                            "permit_joining",
                            &joined.join(","),
                            "model_answer",
                            "joined",
                        ),
                    }
                }
            },
            Deferred::Zcl {
                ieee,
                request,
                host_endpoint,
                profile,
                answers,
            } => {
                let (ups, decision, detail, name) = {
                    let mut nv = self.shared.nv();
                    let Some(i) = nv.joined_by_ieee(ieee) else {
                        return;
                    };
                    let dev = &mut nv.joined[i];
                    let name = dev.name.clone();
                    let (ups, decision, detail) = match answers {
                        Ok(list) => {
                            match zcl_answer(dev, &request, host_endpoint, profile, &list) {
                                Ok(ups) => (ups, "model_answer", String::new()),
                                Err(e) => (
                                    zcl_failure(dev, &request, host_endpoint, profile),
                                    "fail_closed_invalid_reply",
                                    e.to_string(),
                                ),
                            }
                        }
                        Err(f) => (
                            zcl_failure(dev, &request, host_endpoint, profile),
                            f.decision(),
                            f.detail(),
                        ),
                    };
                    (ups, decision, detail, name)
                };
                let op = format!(
                    "zcl cluster={} command=0x{:02x}",
                    device::cluster_name(request.cluster),
                    request.header.command
                );
                self.shared.outcome(&op, &name, decision, &detail);
                self.out.extend(ups);
            }
        }
    }

    /// Make a device join: a described one by name or IEEE, or a new description.
    pub fn join(&mut self, view: &View, which: &Value) -> Result<String> {
        ensure!(view.up, "the network is not up");
        ensure!(view.permit_open, "the network is not open for joining");
        let mut nv = self.shared.nv();
        let dev = match which {
            Value::String(s) => {
                let s = s.trim();
                let ieee = device::parse_eui(s).ok();
                if let Some(d) = nv
                    .joined
                    .iter()
                    .find(|d| d.name == s || Some(d.ieee) == ieee)
                {
                    bail!("{} is already in the network", d.name);
                }
                let i = nv
                    .waiting
                    .iter()
                    .position(|d| d.name == s || Some(d.ieee) == ieee)
                    .with_context(|| format!("no described device is called {s}"))?;
                nv.waiting.remove(i)
            }
            Value::Object(_) => {
                let taken = nv.nwks_in_use();
                let d = device::parse_device(which, &taken)?;
                ensure!(
                    nv.joined_by_ieee(d.ieee).is_none(),
                    "{} is already in the network",
                    device::eui_display(d.ieee)
                );
                ensure!(
                    nv.joined.len() + nv.waiting.len() < device::MAX_DEVICES,
                    "the network holds at most {} devices",
                    device::MAX_DEVICES
                );
                nv.waiting.retain(|w| w.ieee != d.ieee);
                d
            }
            _ => bail!("device is a name, an IEEE address or a description"),
        };
        let mut dev = dev;
        if dev.kind.is_child() && ncp::child_count(&nv) >= view.max_children {
            let name = dev.name.clone();
            nv.waiting.push(dev);
            bail!("the coordinator's child table is full; {name} cannot join it");
        }
        if nv.joined.iter().any(|d| d.nwk == dev.nwk) {
            let taken = nv.nwks_in_use();
            dev.nwk = (1..0xFFF8u16)
                .find(|n| !taken.contains(n))
                .unwrap_or(0x0001);
        }
        let name = dev.name.clone();
        if dev.kind.is_child() {
            let index = ncp::child_count(&nv) as u8;
            self.out.push(Up::Child {
                index,
                joining: true,
                nwk: dev.nwk,
                ieee: dev.ieee,
                node_type: dev.kind.ember_node_type(),
            });
        }
        self.out.push(Up::TrustCenter {
            nwk: dev.nwk,
            ieee: dev.ieee,
            joined: true,
        });
        let tsn = dev.next_zcl_tsn();
        let announce = device::device_announce(&dev, tsn);
        let aps = ApsFrame {
            profile_id: device::PROFILE_ZDO,
            cluster_id: 0x0013,
            source_endpoint: 0,
            destination_endpoint: 0,
            options: 0,
            group_id: 0,
            sequence: dev.next_aps(),
        };
        self.out.push(Up::Incoming {
            broadcast: true,
            aps,
            nwk: dev.nwk,
            ieee: dev.ieee,
            payload: announce,
        });
        nv.joined.push(dev);
        Ok(name)
    }

    /// A device leaves: the trust center (and, for a child, the child table) tells the host.
    pub fn leave(&mut self, ieee: u64) {
        let mut nv = self.shared.nv();
        let ups = leave(&mut nv, ieee);
        self.out.extend(ups);
    }

    /// An action injected through the dashboard or MCP `send_to_peer`.
    pub async fn injected(&mut self, view: &View, c: ClientCommand) {
        let action = c.action.clone();
        let outcome = match actions::check(&action) {
            Err(e) => ClientSendOutcome::Rejected {
                error: e.to_string(),
            },
            Ok(()) => match self.run_injected(view, &action) {
                Ok(detail) => ClientSendOutcome::Executed { detail },
                Err(e) => ClientSendOutcome::Rejected {
                    error: e.to_string(),
                },
            },
        };
        self.shared
            .ctx
            .state
            .record_access_log(
                AccessLogOwner::Server(self.shared.ctx.server_id.as_u32()),
                "Zigbee",
                Some(self.id.as_u32()),
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or(Value::Null)],
            )
            .await;
        crate::client::command_support::reply(c, Ok(outcome));
    }

    fn run_injected(&mut self, view: &View, action: &Value) -> Result<String> {
        let kind = action["type"].as_str().unwrap_or_default();
        match kind {
            actions::JOIN_DEVICE => {
                let name = self.join(view, &action["device"])?;
                Ok(format!("{name} joined"))
            }
            actions::LEAVE_DEVICE => {
                let (ieee, name) = {
                    let nv = self.shared.nv();
                    let i = find_joined(&nv, actions::name_of(action)?)?;
                    (nv.joined[i].ieee, nv.joined[i].name.clone())
                };
                self.leave(ieee);
                Ok(format!("{name} left"))
            }
            actions::REPORT_ATTRIBUTES | actions::SEND_COMMAND => {
                ensure!(view.up, "the network is not up");
                let host_ep = view.host_endpoint;
                let mut nv = self.shared.nv();
                let i = find_joined(&nv, actions::name_of(action)?)?;
                let ep = actions::endpoint_of(action)?;
                let dev = &mut nv.joined[i];
                let profile = dev
                    .endpoint(ep)
                    .map(|e| e.profile)
                    .with_context(|| format!("{} has no endpoint {ep}", dev.name))?;
                let up = if kind == actions::REPORT_ATTRIBUTES {
                    let list = action["attributes"].as_array().cloned().unwrap_or_default();
                    let mut by_cluster: BTreeMap<u16, Vec<Value>> = BTreeMap::new();
                    for a in list {
                        by_cluster
                            .entry(device::parse_cluster(&a["cluster"])?)
                            .or_default()
                            .push(a);
                    }
                    ensure!(
                        by_cluster.len() == 1,
                        "one report carries one cluster's attributes"
                    );
                    let (cluster, list) = by_cluster.into_iter().next().unwrap_or_default();
                    let written = device::apply_attributes(dev, ep, Some(cluster), &list)?;
                    let tsn = dev.next_zcl_tsn();
                    let records: Vec<(u16, device::Attribute)> =
                        written.into_iter().map(|(_, a, v)| (a, v)).collect();
                    let frame = device::report_frame(tsn, &records);
                    originate(dev, ep, host_ep, profile, cluster, &frame)
                } else {
                    let cluster = device::parse_cluster(&action["cluster"])?;
                    let command = device::parse_command(cluster, &action["command"])?;
                    let payload = actions::hex_payload(action)?;
                    let e = dev.endpoint(ep).context("endpoint")?;
                    ensure!(
                        e.out_clusters.contains(&cluster) || e.in_clusters.contains(&cluster),
                        "endpoint {ep} has no {} cluster",
                        device::cluster_name(cluster)
                    );
                    let tsn = dev.next_zcl_tsn();
                    let frame = device::command_frame(tsn, command, &payload);
                    originate(dev, ep, host_ep, profile, cluster, &frame)
                };
                let name = dev.name.clone();
                drop(nv);
                self.out.push(up);
                Ok(format!("{name}: {kind}"))
            }
            _ => bail!("{kind} is answered to an event, not sent on its own"),
        }
    }
}

fn find_joined(nv: &Nvram, which: &str) -> Result<usize> {
    let ieee = device::parse_eui(which).ok();
    nv.joined
        .iter()
        .position(|d| d.name == which || Some(d.ieee) == ieee)
        .with_context(|| format!("no device called {which} is in the network"))
}

/// A device leaves: the trust center (and, for a child, the child table) tells the host.
pub fn leave(nv: &mut Nvram, ieee: u64) -> Vec<Up> {
    let Some(i) = nv.joined_by_ieee(ieee) else {
        return Vec::new();
    };
    let child_index = nv
        .joined
        .iter()
        .filter(|d| d.kind.is_child())
        .position(|d| d.ieee == ieee);
    let dev = nv.joined.remove(i);
    let mut ups = Vec::new();
    if let Some(index) = child_index {
        ups.push(Up::Child {
            index: index as u8,
            joining: false,
            nwk: dev.nwk,
            ieee: dev.ieee,
            node_type: dev.kind.ember_node_type(),
        });
    }
    ups.push(Up::TrustCenter {
        nwk: dev.nwk,
        ieee: dev.ieee,
        joined: false,
    });
    nv.waiting.push(dev);
    ups
}

/// A frame a device sends in answer to the host: from the endpoint addressed back to the one
/// that asked, on the profile and response cluster given.
fn from_device(dev: &Device, req: &ApsFrame, cluster: u16, src_ep: u8, payload: &[u8]) -> Up {
    Up::Incoming {
        broadcast: false,
        aps: ApsFrame {
            profile_id: req.profile_id,
            cluster_id: cluster,
            source_endpoint: src_ep,
            destination_endpoint: req.source_endpoint,
            options: 0,
            group_id: 0,
            sequence: dev.aps_counter.wrapping_add(1),
        },
        nwk: dev.nwk,
        ieee: dev.ieee,
        payload: payload.to_vec(),
    }
}

/// A frame a device originates (a report, a button press) to the host's endpoint.
fn originate(
    dev: &mut Device,
    ep: u8,
    host_ep: u8,
    profile: u16,
    cluster: u16,
    frame: &[u8],
) -> Up {
    Up::Incoming {
        broadcast: false,
        aps: ApsFrame {
            profile_id: profile,
            cluster_id: cluster,
            source_endpoint: ep,
            destination_endpoint: host_ep,
            options: 0,
            group_id: 0,
            sequence: dev.next_aps(),
        },
        nwk: dev.nwk,
        ieee: dev.ieee,
        payload: frame.to_vec(),
    }
}

/// The coordinator's own ZDO answers.
pub fn coordinator_zdo(
    coordinator: &Device,
    view: &View,
    cluster: u16,
    message: &[u8],
) -> Option<(u16, Vec<u8>)> {
    if cluster == 0x0002 {
        let tsn = *message.first()?;
        let mut p = vec![tsn, device::zdo_status::SUCCESS];
        p.extend_from_slice(&ncp::COORDINATOR_NWK.to_le_bytes());
        p.extend(ncp::coordinator_node_descriptor(view.manufacturer_code));
        return Some((0x8002, p));
    }
    if cluster == 0x0038 {
        return energy_scan(message);
    }
    device::zdo(coordinator, cluster, message, false).map(|r| (r.cluster, r.payload))
}

/// `Mgmt_NWK_Update_req` to the coordinator asking for an energy scan (scan duration 0–5):
/// `Mgmt_NWK_Update_notify` with one energy value per scanned channel. There is no radio, so
/// every channel reads clear (0). A channel change (0xFE) or manager update (0xFF) has no
/// answer, as the specification says.
fn energy_scan(message: &[u8]) -> Option<(u16, Vec<u8>)> {
    if message.len() < 6 {
        return None;
    }
    let tsn = message[0];
    let mask = u32::from_le_bytes([message[1], message[2], message[3], message[4]]) & 0x07FF_F800;
    if message[5] > 5 {
        return None;
    }
    let mut p = vec![tsn, device::zdo_status::SUCCESS];
    p.extend_from_slice(&mask.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // total transmissions
    p.extend_from_slice(&0u16.to_le_bytes()); // transmission failures
    let n = mask.count_ones() as usize;
    p.push(n as u8);
    p.extend(std::iter::repeat_n(0u8, n));
    Some((0x8038, p))
}

/// The device's reply when the model gave nothing usable: the APS acknowledgement went out
/// already; the application answers FAILURE, as a device whose application rejected the
/// command does. A write with no response stays silent.
fn zcl_failure(dev: &mut Device, req: &ZclRequest, host_ep: u8, profile: u16) -> Vec<Up> {
    if matches!(
        req.kind,
        device::RequestKind::WriteAttributes {
            no_response: true,
            ..
        }
    ) {
        return Vec::new();
    }
    let frame = device::reply_frame(
        &req.header,
        true,
        0x0B,
        &[req.header.command, device::zcl_status::FAILURE],
    );
    vec![reply_from(dev, req, host_ep, profile, &frame)]
}

fn reply_from(dev: &mut Device, req: &ZclRequest, host_ep: u8, profile: u16, frame: &[u8]) -> Up {
    Up::Incoming {
        broadcast: false,
        aps: ApsFrame {
            profile_id: profile,
            cluster_id: req.cluster,
            source_endpoint: req.endpoint,
            destination_endpoint: host_ep,
            options: 0,
            group_id: 0,
            sequence: dev.next_aps(),
        },
        nwk: dev.nwk,
        ieee: dev.ieee,
        payload: frame.to_vec(),
    }
}

/// Turn the model's answer to a ZCL request into the device's frames. Every action is
/// checked before any state changes, so a refused answer changes nothing.
fn zcl_answer(
    dev: &mut Device,
    req: &ZclRequest,
    host_ep: u8,
    profile: u16,
    answers: &[Value],
) -> Result<Vec<Up>> {
    let mut status: Option<u8> = None;
    let mut sets: Vec<(&Value, bool)> = Vec::new();
    let mut cluster_response: Option<(u8, Vec<u8>)> = None;
    let mut silent = false;
    for a in answers {
        match a["type"].as_str().unwrap_or_default() {
            actions::DEFAULT_RESPONSE => {
                ensure!(status.is_none(), "two statuses for one request");
                status = Some(device::zcl_status::parse(&a["status"])?);
            }
            actions::SET_ATTRIBUTES => {
                sets.push((a, a["report"].as_bool().unwrap_or(false)));
            }
            actions::CLUSTER_RESPONSE => {
                ensure!(
                    cluster_response.is_none(),
                    "two cluster responses for one request"
                );
                ensure!(
                    req.kind == device::RequestKind::ClusterCommand,
                    "a cluster response answers a cluster command"
                );
                cluster_response = Some((
                    a["command_id"].as_u64().unwrap_or(0) as u8,
                    actions::hex_payload(a)?,
                ));
            }
            actions::NO_RESPONSE => silent = true,
            other => bail!("{other} does not answer a ZCL request"),
        }
    }
    ensure!(
        !(silent && (status.is_some() || cluster_response.is_some())),
        "zigbee_no_response with a response"
    );
    // Plan the attribute changes on a copy, so an invalid one leaves the device untouched.
    let mut trial = dev.clone();
    let mut reports: Vec<(u16, Vec<(u16, device::Attribute)>)> = Vec::new();
    for (a, report) in &sets {
        let list = a["attributes"].as_array().cloned().unwrap_or_default();
        let written = device::apply_attributes(&mut trial, req.endpoint, Some(req.cluster), &list)?;
        if *report {
            let mut by_cluster: BTreeMap<u16, Vec<(u16, device::Attribute)>> = BTreeMap::new();
            for (c, id, v) in written {
                by_cluster.entry(c).or_default().push((id, v));
            }
            reports.extend(by_cluster);
        }
    }
    let mut frames: Vec<(u16, Vec<u8>)> = Vec::new();
    match req.kind {
        device::RequestKind::WriteAttributes { no_response, .. } => {
            let st = status.unwrap_or(device::zcl_status::SUCCESS);
            if st == device::zcl_status::SUCCESS {
                // The host's own values, now the device's.
                let mut rest = req.payload.as_slice();
                let ep = trial
                    .endpoint_mut(req.endpoint)
                    .context("the endpoint is gone")?;
                while rest.len() >= 3 {
                    let attr = u16::from_le_bytes([rest[0], rest[1]]);
                    let Some((v, used)) = device::Attribute::decode(rest[2], &rest[3..]) else {
                        break;
                    };
                    ep.attributes.insert((req.cluster, attr), v);
                    rest = &rest[3 + used..];
                }
            }
            if !no_response && !silent {
                let payload = if st == device::zcl_status::SUCCESS {
                    vec![st]
                } else {
                    let mut p = Vec::new();
                    let mut rest = req.payload.as_slice();
                    while rest.len() >= 3 {
                        p.push(st);
                        p.extend_from_slice(&rest[..2]);
                        let Some((_, used)) = device::Attribute::decode(rest[2], &rest[3..]) else {
                            break;
                        };
                        rest = &rest[3 + used..];
                    }
                    p
                };
                frames.push((
                    req.cluster,
                    device::reply_frame(&req.header, true, 0x04, &payload),
                ));
            }
        }
        _ => {
            if !silent {
                if let Some((cmd, payload)) = &cluster_response {
                    frames.push((
                        req.cluster,
                        device::reply_frame(&req.header, false, *cmd, payload),
                    ));
                }
                let st = status.unwrap_or(device::zcl_status::SUCCESS);
                if cluster_response.is_none() || status.is_some() {
                    if let Some(f) = device::default_response(&req.header, st) {
                        frames.push((req.cluster, f));
                    }
                }
            }
        }
    }
    *dev = trial;
    let mut ups = Vec::new();
    for (cluster, frame) in frames {
        let mut r = req.clone();
        r.cluster = cluster;
        ups.push(reply_from(dev, &r, host_ep, profile, &frame));
    }
    for (cluster, records) in reports {
        let tsn = dev.next_zcl_tsn();
        let frame = device::report_frame(tsn, &records);
        ups.push(originate(
            dev,
            req.endpoint,
            host_ep,
            profile,
            cluster,
            &frame,
        ));
    }
    Ok(ups)
}
