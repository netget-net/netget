//! An NVMe/TCP host: queues (one TCP connection each, ICReq/ICResp, then a Connect), the
//! controller bring-up a host owes (CAP, CC.EN, CSTS.RDY, Identify, Number of Queues), one I/O
//! queue, commands with in-capsule data, R2T-solicited H2CData and C2HData, keep-alive, the
//! discovery log, and an orderly shutdown (CC.SHN, then close). No model here: `super` decides
//! what to run and reports what came back. The PDU and NVMe code is the target's
//! (`src/server/nvme_tcp/pdu.rs`, `src/server/nvme_tcp/nvme.rs`).
use crate::server::nvme_tcp::nvme::{
    self, admin, cns, fctype, feature, prop, sgl, ControllerInfo, Cqe, DiscoveryEntry,
    NamespaceInfo, Sqe, Status,
};
use crate::server::nvme_tcp::pdu::{self, flag, kind, Digests, Limits, Pdu};
use anyhow::{bail, ensure, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Connecting a queue's TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Each answer the target owes: the ICResp, and every command's completion.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// The rest of a PDU once its first byte arrived.
pub const PDU_DEADLINE: Duration = Duration::from_secs(30);
/// The most data one C2HData PDU may carry, and one command may bring back.
pub const MAX_DATA: usize = 1024 * 1024;
/// Discovery log entries this host reads.
pub const MAX_DISCOVERY_ENTRIES: u64 = 1024;
/// The admin queue's size (0's based): 32 entries.
pub const ADMIN_SQSIZE: u16 = 31;
/// The I/O queue's size (0's based), at most the target's MQES.
pub const IO_SQSIZE: u16 = 31;
/// In-capsule data every controller takes on its admin queue (NVMe/TCP requires 8 KiB).
pub const ADMIN_IN_CAPSULE: usize = 8192;
/// How long CSTS.RDY (or shutdown complete) may take, at most.
pub const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// What the operator configured.
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub hostnqn: String,
    pub hostid: [u8; 16],
    /// Ask for header and data digests, and require the target to enable them.
    pub digests: bool,
    pub kato_ms: u32,
}

/// One queue: a TCP connection past ICReq/ICResp.
pub struct QueueConn {
    pub qid: u16,
    pub digests: Digests,
    /// The target's alignment for data we send (CPDA) and its MAXH2CDATA.
    pub cpda: u8,
    pub maxh2cdata: usize,
    /// In-capsule data the target takes on this queue (8 KiB on an admin queue; IOCCSZ on an
    /// I/O queue, which the opener sets before Connect).
    pub in_capsule: usize,
    writer: OwnedWriteHalf,
    pdus: mpsc::Receiver<std::result::Result<Pdu, String>>,
    reader: tokio::task::AbortHandle,
    /// The PDU reader, for the caller to register with the client's tasks.
    pub reader_task: Option<tokio::task::JoinHandle<()>>,
    next_cid: u16,
}

impl Drop for QueueConn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// A command's completion and the data it brought back.
#[derive(Clone, Debug)]
pub struct Completion {
    pub cqe: Cqe,
    pub data: Vec<u8>,
}

impl Completion {
    pub fn status(&self) -> Status {
        self.cqe.status()
    }
}

fn host_limits(digests: Digests) -> Limits {
    Limits {
        accepted: Limits::types(&[
            kind::CAPSULE_RESP,
            kind::C2H_DATA,
            kind::R2T,
            kind::C2H_TERM_REQ,
        ]),
        digests,
        max_capsule_data: 0,
        max_data_pdu: MAX_DATA,
    }
}

impl QueueConn {
    /// Connect a TCP connection and exchange ICReq/ICResp.
    pub async fn open(addr: SocketAddr, qid: u16, config: &HostConfig) -> Result<Self> {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .with_context(|| format!("connecting to {addr} timed out"))?
            .with_context(|| format!("connecting to {addr}"))?;
        let _ = stream.set_nodelay(true);
        let mut ic = Pdu::new(kind::IC_REQ);
        ic.set_u16(8, 0); // PFV
        ic.header[10] = 0; // HPDA
        ic.header[11] = if config.digests { 0x03 } else { 0 };
        ic.set_u32(12, 0); // MAXR2T: one R2T at a time
        stream.write_all(&ic.encode(Digests::default(), 0)).await?;
        let limits = Limits {
            accepted: Limits::types(&[kind::IC_RESP, kind::C2H_TERM_REQ]),
            digests: Digests::default(),
            max_capsule_data: 0,
            max_data_pdu: 0,
        };
        let resp = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            pdu::read_pdu(&mut stream, &limits, PDU_DEADLINE),
        )
        .await
        .context("no ICResp within 30 s")?
        .map_err(|e| anyhow::anyhow!("reading the ICResp: {e}"))?;
        if resp.kind() == kind::C2H_TERM_REQ {
            bail!(
                "the target refused the ICReq with C2HTermReq: {} (FEI {})",
                pdu::fes::name(resp.u16_at(8)),
                resp.u32_at(10)
            );
        }
        ensure!(resp.u16_at(8) == 0, "ICResp PFV {}", resp.u16_at(8));
        let cpda = resp.u8_at(10);
        ensure!(cpda <= 31, "ICResp CPDA {cpda} (0 to 31)");
        let dgst = resp.u8_at(11);
        let digests = Digests {
            header: dgst & 1 != 0,
            data: dgst & 2 != 0,
        };
        ensure!(
            dgst & !0x03 == 0 && (config.digests || dgst == 0),
            "the target enabled digests this host did not ask for (DGST {dgst:#04x})"
        );
        ensure!(
            !config.digests || (digests.header && digests.data),
            "the target did not enable the header and data digests this host requires \
             (DGST {dgst:#04x})"
        );
        let maxh2cdata = resp.u32_at(12) as usize;
        ensure!(
            maxh2cdata >= 4096,
            "ICResp MAXH2CDATA {maxh2cdata} (at least 4096)"
        );
        let (mut r, w) = stream.into_split();
        let (tx, rx) = mpsc::channel(64);
        let limits = host_limits(digests);
        let reader = tokio::spawn(async move {
            loop {
                let item = pdu::read_pdu(&mut r, &limits, PDU_DEADLINE)
                    .await
                    .map_err(|e| e.to_string());
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    return;
                }
            }
        });
        let abort = reader.abort_handle();
        Ok(Self {
            qid,
            digests,
            cpda,
            maxh2cdata: maxh2cdata.min(MAX_DATA),
            in_capsule: if qid == 0 { ADMIN_IN_CAPSULE } else { 0 },
            writer: w,
            pdus: rx,
            reader: abort,
            reader_task: Some(reader),
            next_cid: 0,
        })
    }

    async fn send(&mut self, p: &Pdu) -> Result<()> {
        self.writer
            .write_all(&p.encode(self.digests, self.cpda))
            .await
            .context("writing to the target")
    }

    async fn next(&mut self) -> Result<Pdu> {
        let p = tokio::time::timeout(RESPONSE_TIMEOUT, self.pdus.recv())
            .await
            .context("the target did not answer within 30 s")?
            .context("the target closed the connection")?
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if p.kind() == kind::C2H_TERM_REQ {
            bail!(
                "the target ended the queue with C2HTermReq: {} (FEI {})",
                pdu::fes::name(p.u16_at(8)),
                p.u32_at(10)
            );
        }
        Ok(p)
    }

    /// The next PDU while no command is outstanding: anything at all ends the queue.
    pub async fn unsolicited(&mut self) -> Option<std::result::Result<Pdu, String>> {
        self.pdus.recv().await
    }

    /// Run one command: `out` is data to send (in the capsule when it fits, else as the target
    /// asks with R2T), `in_len` the data expected back.
    pub async fn exec(
        &mut self,
        mut sqe: Sqe,
        out: Option<&[u8]>,
        in_len: usize,
    ) -> Result<Completion> {
        ensure!(in_len <= MAX_DATA, "a command bringing back {in_len} bytes");
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        sqe.set_u16(2, cid);
        let mut capsule = Pdu::new(kind::CAPSULE_CMD);
        match out {
            Some(d) if d.len() <= self.in_capsule => {
                sqe.set_sgl(0, d.len() as u32, sgl::IN_CAPSULE);
                capsule.data = d.to_vec();
            }
            Some(d) => sqe.set_sgl(0, d.len() as u32, sgl::TRANSPORT),
            None => sqe.set_sgl(0, in_len as u32, sgl::TRANSPORT),
        }
        capsule.header[8..72].copy_from_slice(&sqe.0);
        self.send(&capsule).await?;
        let mut data: Vec<u8> = Vec::new();
        let mut sent_by_r2t = 0usize;
        loop {
            let p = self.next().await?;
            match p.kind() {
                kind::CAPSULE_RESP => {
                    let cqe = Cqe::decode(&p.header[8..24]).context("a short completion")?;
                    ensure!(
                        cqe.cid == cid,
                        "a completion for command {} while {cid} was outstanding",
                        cqe.cid
                    );
                    return Ok(Completion { cqe, data });
                }
                kind::C2H_DATA => {
                    let (cccid, datao, datal) =
                        (p.u16_at(8), p.u32_at(12) as usize, p.u32_at(16) as usize);
                    ensure!(cccid == cid, "C2HData for command {cccid}, not {cid}");
                    ensure!(
                        datal == p.data.len(),
                        "C2HData DATAL {datal} on a PDU carrying {} bytes",
                        p.data.len()
                    );
                    ensure!(
                        datao == data.len() && datao + datal <= in_len,
                        "C2HData at offset {datao} for {datal} bytes, where {} of {in_len} \
                         had arrived",
                        data.len()
                    );
                    data.extend_from_slice(&p.data);
                    if p.flags() & flag::SUCCESS != 0 {
                        ensure!(
                            p.flags() & flag::LAST_PDU != 0,
                            "SUCCESS on a C2HData that is not the last"
                        );
                        return Ok(Completion {
                            cqe: Cqe {
                                dw0: 0,
                                dw1: 0,
                                sqhd: 0xFFFF,
                                sqid: self.qid,
                                cid,
                                status: 0,
                            },
                            data,
                        });
                    }
                }
                kind::R2T => {
                    let (cccid, ttag, r2to, r2tl) = (
                        p.u16_at(8),
                        p.u16_at(10),
                        p.u32_at(12) as usize,
                        p.u32_at(16) as usize,
                    );
                    let d = out.context("an R2T for a command with no data to send")?;
                    ensure!(cccid == cid, "R2T for command {cccid}, not {cid}");
                    ensure!(
                        r2tl > 0 && r2to.checked_add(r2tl).is_some_and(|e| e <= d.len()),
                        "R2T for {r2tl} bytes at {r2to} of a {}-byte transfer",
                        d.len()
                    );
                    let mut at = r2to;
                    while at < r2to + r2tl {
                        let n = (r2to + r2tl - at).min(self.maxh2cdata);
                        let mut h = Pdu::new(kind::H2C_DATA);
                        h.set_u16(8, cid);
                        h.set_u16(10, ttag);
                        h.set_u32(12, at as u32);
                        h.set_u32(16, n as u32);
                        if at + n == r2to + r2tl {
                            h.set_flags(flag::LAST_PDU);
                        }
                        h.data = d[at..at + n].to_vec();
                        self.send(&h).await?;
                        at += n;
                    }
                    sent_by_r2t += r2tl;
                    ensure!(
                        sent_by_r2t <= d.len() * 2,
                        "the target asked for the same data again and again"
                    );
                }
                other => bail!("an unexpected {}", kind::name(other)),
            }
        }
    }

    /// Connect this queue to a controller.
    pub async fn connect(
        &mut self,
        config: &HostConfig,
        subnqn: &str,
        cntlid: u16,
        sqsize: u16,
    ) -> Result<Completion> {
        let mut sqe = Sqe::new(admin::FABRICS, 0);
        sqe.0[4] = fctype::CONNECT;
        sqe.set_u16(nvme::connect::QID as usize, self.qid);
        sqe.set_u16(nvme::connect::SQSIZE as usize, sqsize);
        if self.qid == 0 {
            sqe.set_u32(nvme::connect::KATO as usize, config.kato_ms);
        }
        let data = nvme::connect_data(&config.hostid, cntlid, subnqn, &config.hostnqn);
        // The Connect data fits the 8 KiB every NVMe/TCP controller takes in capsule on an
        // admin queue; on an I/O queue it goes in capsule when IOCCSZ allows, else by R2T.
        self.exec(sqe, Some(&data), 0).await
    }

    pub async fn property_get(&mut self, offset: u32, eight: bool) -> Result<u64> {
        let mut sqe = Sqe::new(admin::FABRICS, 0);
        sqe.0[4] = fctype::PROPERTY_GET;
        sqe.0[40] = eight as u8;
        sqe.set_u32(44, offset);
        let c = self.exec(sqe, None, 0).await?;
        ensure!(
            c.status().is_success(),
            "Property Get {offset:#x}: {}",
            c.status().describe()
        );
        Ok(if eight {
            c.cqe.result64()
        } else {
            c.cqe.dw0 as u64
        })
    }

    pub async fn property_set(&mut self, offset: u32, value: u32) -> Result<()> {
        let mut sqe = Sqe::new(admin::FABRICS, 0);
        sqe.0[4] = fctype::PROPERTY_SET;
        sqe.set_u32(44, offset);
        sqe.set_u64(48, value as u64);
        let c = self.exec(sqe, None, 0).await?;
        ensure!(
            c.status().is_success(),
            "Property Set {offset:#x}: {}",
            c.status().describe()
        );
        Ok(())
    }

    pub async fn identify(&mut self, c: u8, nsid: u32) -> Result<Completion> {
        let mut sqe = Sqe::new(admin::IDENTIFY, 0);
        sqe.set_nsid(nsid);
        sqe.set_cdw(10, c as u32);
        self.exec(sqe, None, nvme::IDENTIFY_LEN).await
    }

    pub async fn get_log_page(
        &mut self,
        lid: u8,
        nsid: u32,
        offset: u64,
        len: usize,
    ) -> Result<Completion> {
        ensure!(len >= 4 && len % 4 == 0, "a log page read of {len} bytes");
        let numd = (len / 4 - 1) as u32;
        let mut sqe = Sqe::new(admin::GET_LOG_PAGE, 0);
        sqe.set_nsid(nsid);
        sqe.set_cdw(10, lid as u32 | (numd & 0xFFFF) << 16);
        sqe.set_cdw(11, numd >> 16);
        sqe.set_cdw(12, offset as u32);
        sqe.set_cdw(13, (offset >> 32) as u32);
        self.exec(sqe, None, len).await
    }

    pub async fn keep_alive(&mut self) -> Result<Status> {
        let c = self.exec(Sqe::new(admin::KEEP_ALIVE, 0), None, 0).await?;
        Ok(c.status())
    }
}

/// The admin queue's bring-up after Connect: CAP and VS, CC.EN, CSTS.RDY, Identify
/// Controller. Returns (CAP, VS, the controller).
pub async fn enable(q: &mut QueueConn, cntlid: u16) -> Result<(u64, u32, ControllerInfo)> {
    let cap = q.property_get(prop::CAP, true).await?;
    let vs = q.property_get(prop::VS, false).await? as u32;
    // CC: EN, the NVM command set, 4 KiB pages, 64-byte SQ and 16-byte CQ entries.
    q.property_set(prop::CC, 1 | 6 << 16 | 4 << 20).await?;
    let to = Duration::from_millis(((cap >> 24) & 0xFF).max(1) * 500).min(READY_TIMEOUT);
    let started = tokio::time::Instant::now();
    loop {
        let csts = q.property_get(prop::CSTS, false).await?;
        ensure!(
            csts & 2 == 0,
            "the controller reports a fatal status (CSTS.CFS)"
        );
        if csts & 1 != 0 {
            break;
        }
        ensure!(
            started.elapsed() < to,
            "the controller did not become ready within {} ms",
            to.as_millis()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let c = q.identify(cns::CONTROLLER, 0).await?;
    ensure!(
        c.status().is_success(),
        "Identify Controller: {}",
        c.status().describe()
    );
    let info = ControllerInfo::decode(&c.data).context("a short Identify Controller")?;
    ensure!(
        info.cntlid == cntlid,
        "Identify reports controller {} where Connect gave {cntlid}",
        info.cntlid
    );
    Ok((cap, vs, info))
}

/// Shut the controller down: CC.SHN normal, then wait for CSTS.SHST complete.
pub async fn shutdown(q: &mut QueueConn) -> Result<()> {
    let cc = q.property_get(prop::CC, false).await? as u32;
    q.property_set(prop::CC, (cc & !(3 << 14)) | 1 << 14)
        .await?;
    let started = tokio::time::Instant::now();
    loop {
        let csts = q.property_get(prop::CSTS, false).await?;
        if (csts >> 2) & 3 == 2 {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "the controller did not report shutdown complete within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Why a Connect was refused, as a person reads it.
pub fn connect_refusal(c: &Cqe) -> String {
    let s = c.status();
    let mut text = s.describe();
    if s.sct == 1 && s.sc == 0x82 {
        let offset = c.dw0 & 0xFFFF;
        let in_data = c.dw0 & (1 << 16) != 0;
        let field = match (in_data, offset as u16) {
            (true, nvme::connect::DATA_HOSTID) => "HOSTID",
            (true, nvme::connect::DATA_CNTLID) => "CNTLID",
            (true, nvme::connect::DATA_SUBNQN) => "SUBNQN",
            (true, nvme::connect::DATA_HOSTNQN) => "HOSTNQN",
            (false, nvme::connect::QID) => "QID",
            (false, nvme::connect::SQSIZE) => "SQSIZE",
            (false, nvme::connect::RECFMT) => "RECFMT",
            (false, nvme::connect::KATO) => "KATO",
            _ => "",
        };
        if !field.is_empty() {
            text = format!("{text} ({field})");
        } else {
            text = format!(
                "{text} (byte {offset} of the {})",
                if in_data { "data" } else { "command" }
            );
        }
    }
    text
}

/// What a discovery controller listed.
#[derive(Clone, Debug)]
pub struct DiscoveryLog {
    pub generation: u64,
    pub entries: Vec<DiscoveryEntry>,
}

/// The largest transfer a controller takes, from MDTS and CAP.MPSMIN.
pub fn max_transfer(cap: u64, mdts: u8) -> usize {
    let page = 4096usize << ((cap >> 48) & 0xF);
    if mdts == 0 || mdts > 20 {
        MAX_DATA
    } else {
        (page << mdts).min(MAX_DATA)
    }
}

/// Read the whole discovery log, in pieces the controller takes, and check that its
/// generation did not change while it was read.
pub async fn read_discovery_log(
    q: &mut QueueConn,
    cap: u64,
    info: &ControllerInfo,
) -> Result<DiscoveryLog> {
    let chunk = max_transfer(cap, info.mdts).min(64 * 1024);
    for _ in 0..3 {
        let c = q
            .get_log_page(nvme::log::DISCOVERY, 0, 0, nvme::DISCOVERY_RECORD_LEN)
            .await?;
        ensure!(
            c.status().is_success(),
            "Get Log Page (discovery): {}",
            c.status().describe()
        );
        let (generation, records, _) =
            nvme::discovery_header(&c.data).context("a short discovery log header")?;
        ensure!(
            records <= MAX_DISCOVERY_ENTRIES,
            "the discovery log claims {records} records (this host reads at most {MAX_DISCOVERY_ENTRIES})"
        );
        let total = nvme::DISCOVERY_RECORD_LEN * (1 + records as usize);
        let mut page = c.data;
        while page.len() < total {
            let len = (total - page.len()).min(chunk);
            let c = q
                .get_log_page(nvme::log::DISCOVERY, 0, page.len() as u64, len)
                .await?;
            ensure!(
                c.status().is_success(),
                "Get Log Page (discovery) at {}: {}",
                page.len(),
                c.status().describe()
            );
            ensure!(c.data.len() == len, "a short discovery log read");
            page.extend_from_slice(&c.data);
        }
        let again = q.get_log_page(nvme::log::DISCOVERY, 0, 0, 16).await?;
        let same = again.status().is_success()
            && nvme::discovery_header(&{
                let mut h = again.data.clone();
                h.resize(18, 0);
                h
            })
            .is_some_and(|(g, _, _)| g == generation);
        if same {
            let entries = page[nvme::DISCOVERY_RECORD_LEN..total]
                .chunks_exact(nvme::DISCOVERY_RECORD_LEN)
                .filter_map(DiscoveryEntry::decode)
                .collect();
            return Ok(DiscoveryLog {
                generation,
                entries,
            });
        }
    }
    bail!("the discovery log kept changing while it was read")
}

/// An I/O command's SQE.
pub fn rw_sqe(opcode: u8, nsid: u32, slba: u64, blocks: u32) -> Sqe {
    let mut s = Sqe::new(opcode, 0);
    s.set_nsid(nsid);
    s.set_u64(40, slba);
    s.set_cdw(12, (blocks - 1) & 0xFFFF);
    s
}

/// Identify Namespace, decoded.
pub async fn identify_namespace(
    q: &mut QueueConn,
    nsid: u32,
) -> Result<(Status, Option<NamespaceInfo>)> {
    let c = q.identify(cns::NAMESPACE, nsid).await?;
    if !c.status().is_success() {
        return Ok((c.status(), None));
    }
    Ok((c.status(), NamespaceInfo::decode(&c.data)))
}

/// Set Features — Number of Queues: ask for `n` I/O queues; the number granted.
pub async fn set_queue_count(q: &mut QueueConn, n: u16) -> Result<u16> {
    let mut sqe = Sqe::new(admin::SET_FEATURES, 0);
    sqe.set_cdw(10, feature::NUMBER_OF_QUEUES as u32);
    let v = (n - 1) as u32;
    sqe.set_cdw(11, v | v << 16);
    let c = q.exec(sqe, None, 0).await?;
    ensure!(
        c.status().is_success(),
        "Set Features (number of queues): {}",
        c.status().describe()
    );
    let (nsqa, ncqa) = (c.cqe.dw0 & 0xFFFF, c.cqe.dw0 >> 16);
    Ok((nsqa.min(ncqa) + 1).min(u16::MAX as u32) as u16)
}
