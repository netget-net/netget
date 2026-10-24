//! One host's session with the Z-Stack co-processor: MT frames in, SRSPs and indications out,
//! and the shared network (`network.rs`) behind it.
//!
//! MT has no link layer: an SREQ is answered by its SRSP before anything else is written, and
//! the indications it caused (`AF_DATA_CONFIRM`, `ZDO_*_RSP`, `AF_INCOMING_MSG`) follow in the
//! order the firmware raises them. A frame with a bad FCS, or an SOF whose length byte is not a
//! frame's, is dropped without a word, as Z-Stack's NPI drops it.
use super::mt::{self, Deframed, Frame};
use super::network::{Net, View};
use super::znp::{self, Dst, Effect};
use super::{device, Deferred, Shared, IDLE_TIMEOUT, READ_CHUNK, WRITE_TIMEOUT};
use crate::logging::emit::Log;
use crate::server::connection::ConnectionId;
use crate::state::client_handles::ClientCommand;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// End devices the coordinator takes as children (Z-Stack's `NWK_MAX_DEVICE_LIST`).
pub const MAX_CHILDREN: usize = 50;
/// Dropped frames described in the log before the rest are only counted.
const JUNK_LOGGED: u64 = 8;

/// What the link saw that was not a frame.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub frames: u64,
    pub bad_fcs: u64,
    pub too_long: u64,
    pub skipped_bytes: u64,
    pub written_frames: u64,
}

pub struct Session {
    net: Net,
    deframer: mt::Deframer,
    ram: znp::Ram,
    permit_until: Option<tokio::time::Instant>,
    /// Every (type, subsystem, command) the host sent, with how many times.
    census: BTreeMap<(u8, u8, u8), u64>,
    counters: Counters,
    /// Said once that the host speaks another dialect.
    warned_dialect: bool,
    out: Vec<u8>,
}

impl Session {
    pub fn new(shared: Arc<Shared>, id: ConnectionId, deferred: mpsc::Sender<Deferred>) -> Self {
        Self {
            net: Net::new(shared, id, deferred),
            deframer: mt::Deframer::new(),
            ram: znp::Ram::new(),
            permit_until: None,
            census: BTreeMap::new(),
            counters: Counters::default(),
            warned_dialect: false,
            out: Vec::new(),
        }
    }

    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.net.shared.ctx.status_tx))
    }

    fn view(&self) -> View {
        let endpoints = self.ram.coordinator_endpoints();
        View {
            up: self.ram.up(),
            permit_open: self.ram.permit_secs > 0,
            host_endpoint: View::host_endpoint_of(&endpoints),
            max_children: MAX_CHILDREN,
            endpoints,
            manufacturer_code: 0x0000,
        }
    }

    fn write(&mut self, f: &Frame) {
        self.counters.written_frames += 1;
        self.out.extend(f.encode());
    }

    /// Write what the network said, as Z-Stack indications.
    fn flush_net(&mut self) {
        for up in self.net.drain() {
            for f in znp::up_frames(&mut self.ram, &up) {
                self.write(&f);
            }
        }
    }

    pub async fn run(
        &mut self,
        stream: TcpStream,
        mut deferred: mpsc::Receiver<Deferred>,
        mut commands: mpsc::Receiver<ClientCommand>,
    ) -> Result<()> {
        let (mut rd, mut wr) = stream.into_split();
        let mut buf = vec![0u8; READ_CHUNK];
        let mut idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
        loop {
            let mut wake = idle_until;
            if let Some(p) = self.permit_until {
                wake = wake.min(p);
            }
            tokio::select! {
                read = rd.read(&mut buf) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }
                    idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
                    let (server_id, id) = (self.net.shared.ctx.server_id, self.net.id);
                    self.net
                        .shared
                        .ctx
                        .state
                        .update_connection_stats(server_id, id, Some(n as u64), None, Some(1), None)
                        .await;
                    self.notice_dialect(&buf[..n]);
                    let mut units = Vec::new();
                    self.deframer.push(&buf[..n], &mut units);
                    for u in units {
                        self.unit(u).await;
                    }
                }
                Some(d) = deferred.recv() => {
                    let view = self.view();
                    self.net.apply_deferred(&view, d);
                    self.flush_net();
                }
                Some(c) = commands.recv() => {
                    let view = self.view();
                    self.net.injected(&view, c).await;
                    self.flush_net();
                }
                _ = tokio::time::sleep_until(wake) => {
                    let now = tokio::time::Instant::now();
                    if now >= idle_until {
                        bail!("no frame from the host for {}s", IDLE_TIMEOUT.as_secs());
                    }
                    if self.permit_until.is_some_and(|p| now >= p) {
                        self.permit_until = None;
                        self.ram.permit_secs = 0;
                    }
                }
            }
            if !self.out.is_empty() {
                let bytes = std::mem::take(&mut self.out);
                tokio::time::timeout(WRITE_TIMEOUT, wr.write_all(&bytes))
                    .await
                    .context("the host stopped reading")??;
                let (server_id, id) = (self.net.shared.ctx.server_id, self.net.id);
                self.net
                    .shared
                    .ctx
                    .state
                    .update_connection_stats(
                        server_id,
                        id,
                        None,
                        Some(bytes.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
            }
        }
    }

    /// A host that opens with ASH (EZSP's RST, its flag byte) is talking to the wrong
    /// firmware: say so once, rather than leave it to time out in silence.
    fn notice_dialect(&mut self, bytes: &[u8]) {
        if self.warned_dialect || self.counters.frames > 0 || bytes.contains(&mt::SOF) {
            return;
        }
        if bytes.contains(&0x7E) && bytes.contains(&0x1A) {
            self.warned_dialect = true;
            self.log().warn(format!(
                "Zigbee host connection {}: the host is speaking ASH/EZSP; this co-processor runs Z-Stack and speaks MT (dialect znp)",
                self.net.id
            ));
        }
    }

    pub fn closed(&self) {
        let census: Vec<String> = self
            .census
            .iter()
            .map(|((k, sub, id), n)| match znp::name(*sub, *id) {
                Some(name) if *k == mt::kind::SREQ || *k == mt::kind::AREQ => {
                    format!("{name}×{n}")
                }
                _ => format!("unknown 0x{:02x}{:02x}×{n}", (k << 5) | sub, id),
            })
            .collect();
        let c = self.counters;
        self.log().info(format!(
            "Zigbee host connection {} closed; MT commands: {}; MT frames={} bad_fcs={} too_long={} skipped_bytes={} written={}",
            self.net.id,
            census.join(" "),
            c.frames,
            c.bad_fcs,
            c.too_long,
            c.skipped_bytes,
            c.written_frames
        ));
    }

    async fn unit(&mut self, u: Deframed) {
        match u {
            Deframed::Frame(f) => {
                self.counters.frames += 1;
                self.frame(f).await;
            }
            // Junk is counted always and described only the first few times: a stream of it
            // must not become a stream of log lines.
            Deframed::BadFcs { cmd0, cmd1 } => {
                self.counters.bad_fcs += 1;
                if self.counters.bad_fcs > JUNK_LOGGED {
                    return;
                }
                self.log().debug(format!(
                    "Zigbee host connection {}: MT frame 0x{cmd0:02x}{cmd1:02x} with a bad FCS dropped",
                    self.net.id
                ));
            }
            Deframed::TooLong(len) => {
                self.counters.too_long += 1;
                if self.counters.too_long > JUNK_LOGGED {
                    return;
                }
                self.log().debug(format!(
                    "Zigbee host connection {}: an MT length of {len} (more than {}) is not a frame; skipped",
                    self.net.id,
                    mt::MAX_DATA
                ));
            }
            Deframed::Skipped(n) => self.counters.skipped_bytes += n as u64,
        }
    }

    async fn frame(&mut self, f: Frame) {
        let key = (f.kind, f.subsystem, f.id);
        if self.census.len() < 256 || self.census.contains_key(&key) {
            *self.census.entry(key).or_insert(0) += 1;
        }
        let handled = {
            let mut flash = self.net.shared.flash();
            let mut nv = self.net.shared.nv();
            znp::handle(&mut self.ram, &mut flash, &mut nv, &f)
        };
        match handled.name {
            Some(name) => self
                .log()
                .trace(format!("Zigbee MT {name} data={}", hex::encode(&f.data))),
            None => self.log().debug(format!(
                "Zigbee MT 0x{:02x}{:02x} is not a command this firmware has; {}",
                f.cmd0(),
                f.id,
                if f.kind == mt::kind::SREQ {
                    "answered with an RPC error"
                } else {
                    "ignored"
                }
            )),
        }
        if let Some(r) = &handled.response {
            self.write(r);
        }
        for a in &handled.areqs {
            self.write(a);
        }
        for e in handled.effects {
            self.effect(e).await;
        }
    }

    async fn effect(&mut self, e: Effect) {
        match e {
            Effect::Reset => {
                self.permit_until = None;
                self.log().debug(format!(
                    "Zigbee host connection {}: SYS_RESET_REQ, answered SYS_RESET_IND",
                    self.net.id
                ));
            }
            Effect::Started { formed } => {
                let line = {
                    let nv = self.net.shared.nv();
                    nv.network.as_ref().map(|n| {
                        format!(
                            "Zigbee Z-Stack {} network: channel {} PAN 0x{:04x} extended PAN {}",
                            if formed { "formed a" } else { "started on its" },
                            n.params.radio_channel,
                            n.params.pan_id,
                            device::eui_display(u64::from_le_bytes(n.params.extended_pan_id))
                        )
                    })
                };
                if let Some(line) = line {
                    self.log().info(line);
                }
            }
            Effect::Permit(secs) => {
                if secs == 0 {
                    self.permit_until = None;
                    return;
                }
                self.permit_until = (secs != 255)
                    .then(|| tokio::time::Instant::now() + Duration::from_secs(secs as u64));
                self.net.ask_permit(secs).await;
                self.flush_net();
            }
            Effect::Data {
                dst,
                aps,
                message,
                confirm,
            } => {
                let view = self.view();
                match dst {
                    Dst::Nwk(nwk) => {
                        let delivered = self.net.unicast(&view, nwk, aps, &message).await;
                        if let Some((ep, tsn)) = confirm {
                            let c = znp::confirm(delivered, ep, tsn);
                            self.write(&c);
                        }
                    }
                    Dst::Broadcast(_) => {
                        if aps.profile_id == device::PROFILE_ZDO {
                            self.net.broadcast_zdo(&aps, &message);
                        }
                        if let Some((ep, tsn)) = confirm {
                            self.write(&znp::confirm(true, ep, tsn));
                        }
                    }
                    Dst::Group(_) => {
                        // Multicasts are sent and reach no simulated device.
                        if let Some((ep, tsn)) = confirm {
                            self.write(&znp::confirm(true, ep, tsn));
                        }
                    }
                }
                self.flush_net();
            }
        }
    }
}
