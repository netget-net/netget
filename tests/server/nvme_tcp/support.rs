//! Shared harness for the NVMe/TCP target suites: an in-process target with a python policy
//! playing the model (the LLM endpoint is unreachable, so an event the policy does not cover
//! exercises the fail-closed path), and a raw host that writes every PDU from literal offsets
//! of the NVMe/TCP and NVMe over Fabrics specifications rather than through NetGet's encoder.
//! It computes CRC32C itself, checks the target's digests on everything it reads, and records
//! every byte each way, in order, for the pcap oracle.
#![allow(dead_code)]

use crate::helpers::pcap_oracle::PcapOracle;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const DISK0: &str = "nqn.2026-10.net.netget:disk0";
pub const BACKUP: &str = "nqn.2026-10.net.netget:backup";
pub const DISCOVERY: &str = "nqn.2014-08.org.nvmexpress.discovery";
pub const HOST: &str = "nqn.2026-10.org.example:raw-host";
pub const HOSTID: [u8; 16] = [
    0x6c, 0x3a, 0x8f, 0x04, 0x1f, 0x3e, 0x4b, 0x0e, 0x9f, 0x43, 0x2d, 0x1c, 0x0a, 0x6b, 0x7e, 0x55,
];

/// The model: disk0 has a writable namespace 1 (1 MiB, text at 0, a fill at 4096, a medium
/// error at 512 KiB) and a read-only namespace 2 (2 MiB of 4096-byte blocks); the denied host is
/// refused; two subsystems are answered silently and invalidly, any other is not found; the
/// discovery log lists disk0 here and backup at another address.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='nvme_tcp_discovery':
  a=[{'type':'nvme_tcp_discovery_entries','subsystems':[{'nqn':'nqn.2026-10.net.netget:disk0'},{'nqn':'nqn.2026-10.net.netget:backup','address':'192.0.2.7:4420'}]}]
elif e['host_nqn'].endswith(':denied'):
  a=[{'type':'nvme_tcp_reject_connect','reason':'invalid_host'}]
elif e['subsystem_nqn']=='nqn.2026-10.net.netget:disk0':
  a=[{'type':'nvme_tcp_accept_connect','model':'NETGET-BOOT','serial':'SER0001','namespaces':[
    {'nsid':1,'size':1048576,'writable':True,
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}],
     'errors':[{'offset':524288,'length':4096,'error':'medium_error'}]},
    {'nsid':2,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]}]}]
elif e['subsystem_nqn']=='nqn.2026-10.net.netget:silent':
  a=[]
elif e['subsystem_nqn']=='nqn.2026-10.net.netget:invalid':
  a=[{'type':'nvme_tcp_accept_connect','namespaces':[{'nsid':1,'size':0}]}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

pub fn policy(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    /// Every status line the target wrote, kept for [`Started::logs`].
    status: std::sync::Arc<std::sync::Mutex<(mpsc::UnboundedReceiver<String>, Vec<String>)>>,
}

impl Started {
    /// The target's status lines so far (its `decision=` lines among them).
    pub fn logs(&self) -> Vec<String> {
        let mut s = self.status.lock().unwrap();
        while let Ok(line) = s.0.try_recv() {
            s.1.push(line);
        }
        s.1.clone()
    }

    /// The `operation=commands` lines: what each queue received, by command name.
    pub fn commands(&self) -> Vec<String> {
        self.logs()
            .into_iter()
            .filter(|l| l.contains("operation=commands"))
            .collect()
    }
}

/// Start the NVMe/TCP target on loopback with an unreachable model, so only `handlers` answer.
pub async fn start(handlers: Option<Vec<Value>>, params: Option<Value>) -> Started {
    start_on("127.0.0.1", 0, handlers, params).await
}

pub async fn start_on(
    host: &str,
    port: u16,
    handlers: Option<Vec<Value>>,
    params: Option<Value>,
) -> Started {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "nvme_tcp".into(),
        port: Some(port),
        host: Some(host.into()),
        instruction: Some("Be a storage array".into()),
        event_handlers: handlers,
        startup_params: params,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting nvme_tcp: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("nvme_tcp failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server started");
    Started {
        state,
        id,
        port,
        status: std::sync::Arc::new(std::sync::Mutex::new((rx, Vec::new()))),
    }
}

/// What the model was shown, per event type, oldest first.
pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

// ------------------------------------------------------------------- raw PDUs

/// CRC32C, computed here bit by bit from the Castagnoli polynomial (reflected 0x82F63B78) so
/// the digest the target checks is not NetGet's own computation.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// PDU types.
pub const ICREQ: u8 = 0x00;
pub const ICRESP: u8 = 0x01;
pub const H2C_TERM: u8 = 0x02;
pub const C2H_TERM: u8 = 0x03;
pub const CMD: u8 = 0x04;
pub const RESP: u8 = 0x05;
pub const H2C_DATA: u8 = 0x06;
pub const C2H_DATA: u8 = 0x07;
pub const R2T: u8 = 0x09;

/// A received PDU: the whole header (HLEN bytes) and the data.
#[derive(Debug, Clone)]
pub struct Got {
    pub header: Vec<u8>,
    pub data: Vec<u8>,
}

impl Got {
    pub fn kind(&self) -> u8 {
        self.header[0]
    }
    pub fn flags(&self) -> u8 {
        self.header[1]
    }
    /// A CapsuleResp's completion: (DW0, DW1, SQHD, SQID, CID, status field).
    pub fn cqe(&self) -> Cqe {
        assert_eq!(self.kind(), RESP, "a CapsuleResp: {self:?}");
        let h = &self.header;
        Cqe {
            dw0: le32(h, 8),
            dw1: le32(h, 12),
            sqhd: le16(h, 16),
            sqid: le16(h, 18),
            cid: le16(h, 20),
            status: le16(h, 22),
        }
    }
    /// A C2HTermReq's (FES, FEI).
    pub fn term(&self) -> (u16, u32) {
        assert_eq!(self.kind(), C2H_TERM, "a C2HTermReq: {self:?}");
        (le16(&self.header, 8), le32(&self.header, 10))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cqe {
    pub dw0: u32,
    pub dw1: u32,
    pub sqhd: u16,
    pub sqid: u16,
    pub cid: u16,
    pub status: u16,
}

impl Cqe {
    /// (status code type, status code), DNR and phase stripped.
    pub fn sc(&self) -> (u8, u8) {
        (((self.status >> 9) & 7) as u8, (self.status >> 1) as u8)
    }
    pub fn dnr(&self) -> bool {
        self.status & 0x8000 != 0
    }
    pub fn ok(&self) -> bool {
        self.sc() == (0, 0)
    }
}

/// Status pairs (SCT, SC).
pub const SUCCESS: (u8, u8) = (0, 0x00);
pub const INVALID_OPCODE: (u8, u8) = (0, 0x01);
pub const INVALID_FIELD: (u8, u8) = (0, 0x02);
pub const CID_CONFLICT: (u8, u8) = (0, 0x03);
pub const INTERNAL_ERROR: (u8, u8) = (0, 0x06);
pub const INVALID_NAMESPACE: (u8, u8) = (0, 0x0B);
pub const SEQUENCE_ERROR: (u8, u8) = (0, 0x0C);
pub const SGL_LENGTH_INVALID: (u8, u8) = (0, 0x0F);
pub const SGL_TYPE_INVALID: (u8, u8) = (0, 0x11);
pub const WRITE_PROTECTED: (u8, u8) = (0, 0x20);
pub const TRANSIENT_TRANSPORT: (u8, u8) = (0, 0x22);
pub const LBA_OUT_OF_RANGE: (u8, u8) = (0, 0x80);
pub const AER_LIMIT: (u8, u8) = (1, 0x05);
pub const INVALID_LOG_PAGE: (u8, u8) = (1, 0x09);
pub const CONNECT_FORMAT: (u8, u8) = (1, 0x80);
pub const CONNECT_BUSY: (u8, u8) = (1, 0x81);
pub const CONNECT_INVALID_PARAMS: (u8, u8) = (1, 0x82);
pub const CONNECT_INVALID_HOST: (u8, u8) = (1, 0x84);
pub const WRITE_FAULT: (u8, u8) = (2, 0x80);
pub const UNRECOVERED_READ: (u8, u8) = (2, 0x81);

/// One direction's bytes of the conversation, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
}

/// A 64-byte submission queue entry, built from the specification's offsets.
#[derive(Clone)]
pub struct Sqe(pub [u8; 64]);

impl Sqe {
    pub fn new(opcode: u8, nsid: u32) -> Self {
        let mut b = [0u8; 64];
        b[0] = opcode;
        b[1] = 0x40; // PSDT: SGL
        b[4..8].copy_from_slice(&nsid.to_le_bytes());
        Self(b)
    }
    pub fn fabrics(fctype: u8) -> Self {
        let mut s = Self::new(0x7F, 0);
        s.0[4] = fctype;
        s
    }
    pub fn cdw(mut self, n: usize, v: u32) -> Self {
        self.0[n * 4..n * 4 + 4].copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u16_at(mut self, at: usize, v: u16) -> Self {
        self.0[at..at + 2].copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32_at(mut self, at: usize, v: u32) -> Self {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64_at(mut self, at: usize, v: u64) -> Self {
        self.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
        self
    }
    /// SGL1: Transport SGL Data Block (data by C2HData or R2T).
    pub fn transport(self, len: u32) -> Self {
        let mut s = self.u64_at(24, 0).u32_at(32, len);
        s.0[39] = 0x5A;
        s
    }
    /// SGL1: Data Block, offset subtype (data in the capsule).
    pub fn in_capsule(self, len: u32) -> Self {
        let mut s = self.u64_at(24, 0).u32_at(32, len);
        s.0[39] = 0x01;
        s
    }
    /// Read/Write/Write Zeroes range.
    pub fn range(self, slba: u64, blocks: u32) -> Self {
        self.u64_at(40, slba).cdw(12, blocks - 1)
    }
}

/// Connect data: HOSTID, CNTLID, SUBNQN, HOSTNQN at 0, 16, 256 and 512.
pub fn connect_data(hostid: &[u8; 16], cntlid: u16, subnqn: &str, hostnqn: &str) -> Vec<u8> {
    let mut d = vec![0u8; 1024];
    d[0..16].copy_from_slice(hostid);
    d[16..18].copy_from_slice(&cntlid.to_le_bytes());
    d[256..256 + subnqn.len()].copy_from_slice(subnqn.as_bytes());
    d[512..512 + hostnqn.len()].copy_from_slice(hostnqn.as_bytes());
    d
}

/// A raw host over one TCP connection (one queue). Every byte it writes and reads is kept in
/// order, for the pcap oracle.
pub struct Raw {
    pub s: TcpStream,
    pub transcript: Vec<(Dir, Vec<u8>)>,
    pub hdgst: bool,
    pub ddgst: bool,
    pub cid: u16,
    pub maxh2cdata: u32,
}

impl Raw {
    pub async fn connect(port: u16) -> Raw {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        Raw {
            s,
            transcript: Vec::new(),
            hdgst: false,
            ddgst: false,
            cid: 0,
            maxh2cdata: 0,
        }
    }

    pub fn next_cid(&mut self) -> u16 {
        self.cid = self.cid.wrapping_add(1);
        self.cid
    }

    fn record(&mut self, dir: Dir, bytes: &[u8]) {
        match self.transcript.last_mut() {
            Some((d, b)) if *d == dir => b.extend_from_slice(bytes),
            _ => self.transcript.push((dir, bytes.to_vec())),
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        self.record(Dir::Out, bytes);
        self.s.write_all(bytes).await.unwrap();
    }

    /// A PDU from its type, flags and the PDU-specific header (after the 8-byte common
    /// header), with the data at PDO = HLEN (+ header digest), and the digests in force for
    /// types that carry them.
    pub fn frame(&self, kind: u8, flags: u8, psh: &[u8], data: &[u8]) -> Vec<u8> {
        let hlen = 8 + psh.len();
        let digested = !matches!(kind, ICREQ | ICRESP | H2C_TERM | C2H_TERM);
        let hd = self.hdgst && digested;
        let dd = self.ddgst && digested && !data.is_empty();
        let mut flags = flags;
        if hd {
            flags |= 0x01;
        }
        if dd {
            flags |= 0x02;
        }
        let after = hlen + if hd { 4 } else { 0 };
        let pdo = if data.is_empty() || !digested && kind != CMD {
            0
        } else {
            after
        };
        let plen = after + data.len() + if dd { 4 } else { 0 };
        let mut out = vec![kind, flags, hlen as u8, pdo as u8];
        out.extend((plen as u32).to_le_bytes());
        out.extend(psh);
        if hd {
            let d = crc32c(&out[..hlen]);
            out.extend(d.to_le_bytes());
        }
        out.extend(data);
        if dd {
            out.extend(crc32c(data).to_le_bytes());
        }
        out
    }

    pub async fn send(&mut self, kind: u8, flags: u8, psh: &[u8], data: &[u8]) {
        let b = self.frame(kind, flags, psh, data);
        self.write(&b).await;
    }

    /// The next PDU within `wait`, or `None` when the target closed or said nothing.
    pub async fn recv_within(&mut self, wait: Duration) -> Option<Got> {
        let (hd, dd) = (self.hdgst, self.ddgst);
        let read = async {
            let mut ch = [0u8; 8];
            self.s.read_exact(&mut ch).await.ok()?;
            let (kind, flags, hlen, pdo) = (ch[0], ch[1], ch[2] as usize, ch[3] as usize);
            let plen = le32(&ch, 4) as usize;
            assert!(hlen >= 8 && plen >= hlen, "a sane header: {ch:?}");
            let mut raw = ch.to_vec();
            let mut rest = vec![0u8; hlen - 8];
            self.s.read_exact(&mut rest).await.ok()?;
            raw.extend(&rest);
            let header = raw.clone();
            let digested = !matches!(kind, ICREQ | ICRESP | H2C_TERM | C2H_TERM);
            let mut at = hlen;
            if digested {
                assert_eq!(
                    flags & 0x01 != 0,
                    hd,
                    "HDGSTF on a {kind:#x} matches what was negotiated"
                );
            }
            if hd && digested {
                let mut d = [0u8; 4];
                self.s.read_exact(&mut d).await.ok()?;
                assert_eq!(
                    u32::from_le_bytes(d),
                    crc32c(&header),
                    "the target's header digest"
                );
                raw.extend(d);
                at += 4;
            }
            let mut data = Vec::new();
            if plen > at {
                let start = if pdo == 0 { at } else { pdo };
                assert!(start >= at, "PDO {pdo} inside the header");
                let mut pad = vec![0u8; start - at];
                self.s.read_exact(&mut pad).await.ok()?;
                raw.extend(&pad);
                let ddgst = digested && dd;
                if digested {
                    assert_eq!(flags & 0x02 != 0, dd, "DDGSTF matches what was negotiated");
                }
                let len = plen - start - if ddgst { 4 } else { 0 };
                data = vec![0u8; len];
                self.s.read_exact(&mut data).await.ok()?;
                raw.extend(&data);
                if ddgst {
                    let mut d = [0u8; 4];
                    self.s.read_exact(&mut d).await.ok()?;
                    assert_eq!(
                        u32::from_le_bytes(d),
                        crc32c(&data),
                        "the target's data digest"
                    );
                    raw.extend(d);
                }
            }
            Some((Got { header, data }, raw))
        };
        match tokio::time::timeout(wait, read).await {
            Ok(Some((got, raw))) => {
                self.record(Dir::In, &raw);
                Some(got)
            }
            _ => None,
        }
    }

    pub async fn recv(&mut self) -> Got {
        self.recv_within(Duration::from_secs(15))
            .await
            .expect("the target answered")
    }

    /// Whether the target closed the connection (read EOF) within 10 s.
    pub async fn closed(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(10), self.s.read(&mut b)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    /// ICReq: PFV 0, HPDA, DGST, MAXR2T 0. Returns the ICResp and turns on the digests it
    /// enabled.
    pub async fn icreq(&mut self, hpda: u8, digests: u8) -> Got {
        let mut psh = vec![0u8; 120];
        psh[2] = hpda;
        psh[3] = digests;
        self.send(ICREQ, 0, &psh, &[]).await;
        let r = self.recv().await;
        assert_eq!(r.kind(), ICRESP, "an ICResp: {r:?}");
        assert_eq!(le32(&r.header, 4), 128, "ICResp PLEN");
        self.hdgst = r.header[11] & 1 != 0;
        self.ddgst = r.header[11] & 2 != 0;
        self.maxh2cdata = le32(&r.header, 12);
        r
    }

    /// Send a command capsule; `cid` is filled in.
    pub async fn capsule(&mut self, sqe: &Sqe, data: &[u8]) -> u16 {
        let cid = self.next_cid();
        let mut s = sqe.0;
        s[2..4].copy_from_slice(&cid.to_le_bytes());
        self.send(CMD, 0, &s, data).await;
        cid
    }

    /// A command and everything it brings back: (C2HData bytes, completion). A last C2HData
    /// carrying SUCCESS stands in for the completion (status 0, SQHD 0xffff).
    pub async fn cmd(&mut self, sqe: &Sqe, data: &[u8]) -> (Vec<u8>, Cqe) {
        let cid = self.capsule(sqe, data).await;
        let mut got = Vec::new();
        loop {
            let g = self.recv().await;
            match g.kind() {
                C2H_DATA => {
                    assert_eq!(le16(&g.header, 8), cid, "C2HData for this command");
                    assert_eq!(le32(&g.header, 12) as usize, got.len(), "DATAO in order");
                    assert_eq!(le32(&g.header, 16) as usize, g.data.len(), "DATAL");
                    got.extend(&g.data);
                    if g.flags() & 0x08 != 0 {
                        assert!(g.flags() & 0x04 != 0, "SUCCESS only on the last PDU");
                        return (
                            got,
                            Cqe {
                                dw0: 0,
                                dw1: 0,
                                sqhd: 0xFFFF,
                                sqid: 0,
                                cid,
                                status: 0,
                            },
                        );
                    }
                }
                RESP => {
                    let c = g.cqe();
                    assert_eq!(c.cid, cid, "a completion for this command");
                    return (got, c);
                }
                other => panic!("unexpected PDU type {other:#x}: {g:?}"),
            }
        }
    }

    /// A Connect: QID, SQSIZE, CATTR, KATO in the command; the 1024-byte data in the capsule.
    pub async fn connect_queue(
        &mut self,
        qid: u16,
        sqsize: u16,
        kato: u32,
        cattr: u8,
        data: &[u8],
    ) -> Cqe {
        let mut sqe = Sqe::fabrics(0x01)
            .u16_at(42, qid)
            .u16_at(44, sqsize)
            .u32_at(48, kato)
            .in_capsule(data.len() as u32);
        sqe.0[46] = cattr;
        self.cmd(&sqe, data).await.1
    }

    pub async fn prop_get(&mut self, offset: u32, eight: bool) -> Cqe {
        let mut sqe = Sqe::fabrics(0x04).u32_at(44, offset);
        sqe.0[40] = eight as u8;
        self.cmd(&sqe, &[]).await.1
    }

    pub async fn prop_set(&mut self, offset: u32, value: u32) -> Cqe {
        let sqe = Sqe::fabrics(0x00)
            .u32_at(44, offset)
            .u64_at(48, value as u64);
        self.cmd(&sqe, &[]).await.1
    }

    /// ICReq, admin Connect for `subnqn` as `hostnqn`, CC.EN and CSTS.RDY. Returns the CNTLID.
    pub async fn admin_session(&mut self, subnqn: &str, hostnqn: &str, kato: u32) -> u16 {
        self.icreq(0, 0).await;
        let c = self
            .connect_queue(
                0,
                31,
                kato,
                0,
                &connect_data(&HOSTID, 0xFFFF, subnqn, hostnqn),
            )
            .await;
        assert!(c.ok(), "admin Connect: {c:?}");
        let cntlid = (c.dw0 & 0xFFFF) as u16;
        self.enable().await;
        cntlid
    }

    /// CC.EN with 64-byte SQ and 16-byte CQ entries; then CSTS.RDY.
    pub async fn enable(&mut self) {
        let c = self.prop_set(0x14, 1 | 6 << 16 | 4 << 20).await;
        assert!(c.ok(), "Property Set CC: {c:?}");
        let c = self.prop_get(0x1C, false).await;
        assert_eq!(c.dw0 & 3, 1, "CSTS.RDY, no CFS: {c:?}");
    }

    /// ICReq and an I/O queue Connect to an existing controller.
    pub async fn io_session(&mut self, qid: u16, cntlid: u16, subnqn: &str) -> Cqe {
        self.icreq(0, 0).await;
        self.connect_queue(qid, 31, 0, 0, &connect_data(&HOSTID, cntlid, subnqn, HOST))
            .await
    }

    /// An admin session (ICReq, Connect, CC.EN) as another host; the CNTLID.
    pub async fn admin_session_as(
        &mut self,
        subnqn: &str,
        hostnqn: &str,
        hostid: &[u8; 16],
    ) -> u16 {
        self.icreq(0, 0).await;
        let c = self
            .connect_queue(0, 31, 0, 0, &connect_data(hostid, 0xFFFF, subnqn, hostnqn))
            .await;
        assert!(c.ok(), "admin Connect: {c:?}");
        self.enable().await;
        (c.dw0 & 0xFFFF) as u16
    }

    /// ICReq and an I/O queue Connect as another host.
    pub async fn io_session_as(
        &mut self,
        cntlid: u16,
        subnqn: &str,
        hostnqn: &str,
        hostid: &[u8; 16],
    ) -> Cqe {
        self.icreq(0, 0).await;
        self.connect_queue(1, 31, 0, 0, &connect_data(hostid, cntlid, subnqn, hostnqn))
            .await
    }

    pub async fn identify(&mut self, cns: u8, nsid: u32) -> (Vec<u8>, Cqe) {
        let sqe = Sqe::new(0x06, nsid).cdw(10, cns as u32).transport(4096);
        self.cmd(&sqe, &[]).await
    }

    pub async fn get_log(&mut self, lid: u8, offset: u64, len: u32) -> (Vec<u8>, Cqe) {
        let numd = len / 4 - 1;
        let sqe = Sqe::new(0x02, 0xFFFF_FFFF)
            .cdw(10, lid as u32 | (numd & 0xFFFF) << 16)
            .cdw(11, numd >> 16)
            .u64_at(48, offset)
            .transport(len);
        self.cmd(&sqe, &[]).await
    }

    pub async fn read(&mut self, nsid: u32, slba: u64, blocks: u32, bs: u32) -> (Vec<u8>, Cqe) {
        let sqe = Sqe::new(0x02, nsid)
            .range(slba, blocks)
            .transport(blocks * bs);
        self.cmd(&sqe, &[]).await
    }

    /// A Write with its data in the capsule.
    pub async fn write_in_capsule(&mut self, nsid: u32, slba: u64, data: &[u8], bs: u32) -> Cqe {
        let blocks = data.len() as u32 / bs;
        let sqe = Sqe::new(0x01, nsid)
            .range(slba, blocks)
            .in_capsule(data.len() as u32);
        self.cmd(&sqe, data).await.1
    }

    /// A Write whose data the target asks for with R2T, answered in H2CData PDUs of `chunk`
    /// bytes. Returns the R2Ts seen (offset, length) and the completion.
    pub async fn write_solicited(
        &mut self,
        nsid: u32,
        slba: u64,
        data: &[u8],
        bs: u32,
        chunk: usize,
    ) -> (Vec<(u32, u32)>, Cqe) {
        let blocks = data.len() as u32 / bs;
        let sqe = Sqe::new(0x01, nsid)
            .range(slba, blocks)
            .transport(data.len() as u32);
        let cid = self.capsule(&sqe, &[]).await;
        let mut r2ts = Vec::new();
        loop {
            let g = self.recv().await;
            match g.kind() {
                R2T => {
                    assert_eq!(le16(&g.header, 8), cid, "R2T for this command");
                    let (ttag, off, len) = (
                        le16(&g.header, 10),
                        le32(&g.header, 12),
                        le32(&g.header, 16),
                    );
                    assert!(
                        len <= self.maxh2cdata,
                        "R2TL {len} within MAXH2CDATA {}",
                        self.maxh2cdata
                    );
                    r2ts.push((off, len));
                    let mut at = off as usize;
                    let end = (off + len) as usize;
                    while at < end {
                        let n = chunk.min(end - at);
                        let last = at + n == end;
                        let mut psh = vec![0u8; 16];
                        psh[0..2].copy_from_slice(&cid.to_le_bytes());
                        psh[2..4].copy_from_slice(&ttag.to_le_bytes());
                        psh[4..8].copy_from_slice(&(at as u32).to_le_bytes());
                        psh[8..12].copy_from_slice(&(n as u32).to_le_bytes());
                        self.send(
                            H2C_DATA,
                            if last { 0x04 } else { 0 },
                            &psh,
                            &data[at..at + n],
                        )
                        .await;
                        at += n;
                    }
                }
                RESP => {
                    let c = g.cqe();
                    assert_eq!(c.cid, cid);
                    return (r2ts, c);
                }
                other => panic!("unexpected PDU type {other:#x}: {g:?}"),
            }
        }
    }

    /// An H2CData PDU for (cccid, ttag, offset) carrying `data`.
    pub async fn h2c(&mut self, cccid: u16, ttag: u16, offset: u32, data: &[u8], last: bool) {
        let mut psh = vec![0u8; 16];
        psh[0..2].copy_from_slice(&cccid.to_le_bytes());
        psh[2..4].copy_from_slice(&ttag.to_le_bytes());
        psh[4..8].copy_from_slice(&offset.to_le_bytes());
        psh[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.send(H2C_DATA, if last { 0x04 } else { 0 }, &psh, data)
            .await;
    }

    /// The conversation for tshark, in the order it happened.
    pub fn oracle(&self) -> PcapOracle {
        let mut o = PcapOracle::tcp("nvme_tcp");
        for (dir, bytes) in &self.transcript {
            o = match dir {
                Dir::Out => o.to_server(bytes),
                Dir::In => o.from_server(bytes),
            };
        }
        o
    }
}

// --------------------------------------------------------- DH-HMAC-CHAP (raw)
//
// Written from the NVMe Base specification's DH-HMAC-CHAP section for these tests: the HMAC
// comes straight from the `hmac`/`sha2` crates, the CRC-32 is computed bit by bit, the DH group
// prime is copied from RFC 7919 here, and nothing is taken from `netget::server::nvme_tcp::auth`.

/// AUTH-ID values and failure explanations.
pub const NEGOTIATE: u8 = 0x00;
pub const CHALLENGE: u8 = 0x01;
pub const REPLY: u8 = 0x02;
pub const SUCCESS1: u8 = 0x03;
pub const SUCCESS2: u8 = 0x04;
pub const FAILURE2: u8 = 0xF0;
pub const FAILURE1: u8 = 0xF1;
pub const AUTH_FAILED: u8 = 0x01;
pub const HASH_UNUSABLE: u8 = 0x04;
pub const DHGROUP_UNUSABLE: u8 = 0x05;
pub const INCORRECT_PAYLOAD: u8 = 0x06;
pub const INCORRECT_MESSAGE: u8 = 0x07;
pub const AUTHENTICATION_REQUIRED: (u8, u8) = (1, 0x91);
pub const RESERVATION_CONFLICT: (u8, u8) = (0, 0x83);
pub const HOST_ID_INCONSISTENT: (u8, u8) = (0, 0x18);
pub const COMPARE_FAILURE: (u8, u8) = (2, 0x85);
pub const SIZE_LIMIT: (u8, u8) = (1, 0x83);

/// RFC 7919 ffdhe2048, generator 2.
pub const FFDHE2048_P: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

/// CRC-32 (IEEE, reflected 0xEDB88320), bit by bit.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A `DHHC-1:<hh>:<base64 of key ‖ CRC-32 LE>:` secret.
pub fn dhhc1(key: &[u8], transform: u8) -> String {
    use base64::Engine;
    let mut raw = key.to_vec();
    raw.extend(crc32(key).to_le_bytes());
    format!(
        "DHHC-1:{transform:02}:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// The digest length of hash 1 (SHA-256), 2 (SHA-384) or 3 (SHA-512).
pub fn hash_len(id: u8) -> usize {
    match id {
        1 => 32,
        2 => 48,
        _ => 64,
    }
}

pub fn digest(id: u8, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match id {
        1 => sha2::Sha256::digest(data).to_vec(),
        2 => sha2::Sha384::digest(data).to_vec(),
        _ => sha2::Sha512::digest(data).to_vec(),
    }
}

pub fn hmac(id: u8, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).unwrap();
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match id {
        1 => run!(sha2::Sha256),
        2 => run!(sha2::Sha384),
        _ => run!(sha2::Sha512),
    }
}

/// A secret's key transformed for use: HMAC(key, NQN ‖ "NVMe-over-Fabrics") with the secret's
/// own hash, or the key itself for hash 0.
pub fn transform(key: &[u8], transform: u8, nqn: &str) -> Vec<u8> {
    if transform == 0 {
        key.to_vec()
    } else {
        hmac(transform, key, &[nqn.as_bytes(), b"NVMe-over-Fabrics"])
    }
}

/// HMAC(K, C ‖ S ‖ T_ID ‖ SC_C ‖ label ‖ first NQN ‖ 00h ‖ second NQN), C augmented with the
/// session key when one is given.
#[allow(clippy::too_many_arguments)]
pub fn chap_response(
    hash: u8,
    key: &[u8],
    challenge: &[u8],
    session: Option<&[u8]>,
    seq: u32,
    tid: u16,
    label: &[u8],
    first: &str,
    second: &str,
) -> Vec<u8> {
    let c = match session {
        Some(sk) => hmac(hash, sk, &[challenge]),
        None => challenge.to_vec(),
    };
    hmac(
        hash,
        key,
        &[
            &c,
            &seq.to_le_bytes(),
            &tid.to_le_bytes(),
            &[0],
            label,
            first.as_bytes(),
            &[0],
            second.as_bytes(),
        ],
    )
}

/// AUTH_Negotiate: one DH-HMAC-CHAP descriptor offering `hashes` and `groups`.
pub fn negotiate(tid: u16, hashes: &[u8], groups: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 72];
    b[1] = NEGOTIATE;
    b[4..6].copy_from_slice(&tid.to_le_bytes());
    b[7] = 1; // NAPD
    b[8] = 1; // AUTHID: DH-HMAC-CHAP
    b[10] = hashes.len() as u8;
    b[11] = groups.len() as u8;
    b[12..12 + hashes.len()].copy_from_slice(hashes);
    b[42..42 + groups.len()].copy_from_slice(groups);
    b
}

/// DH-HMAC-CHAP_Reply.
pub fn reply(tid: u16, rval: &[u8], c2: Option<&[u8]>, s2: u32, dhv: &[u8]) -> Vec<u8> {
    let hl = rval.len();
    let mut b = vec![0u8; 16 + 2 * hl + dhv.len()];
    b[0] = 1;
    b[1] = REPLY;
    b[4..6].copy_from_slice(&tid.to_le_bytes());
    b[6] = hl as u8;
    b[8] = c2.is_some() as u8;
    b[10..12].copy_from_slice(&(dhv.len() as u16).to_le_bytes());
    b[12..16].copy_from_slice(&s2.to_le_bytes());
    b[16..16 + hl].copy_from_slice(rval);
    if let Some(c) = c2 {
        b[16 + hl..16 + 2 * hl].copy_from_slice(c);
    }
    b[16 + 2 * hl..].copy_from_slice(dhv);
    b
}

/// An Authentication Send (0x05) or Receive (0x06): SECP E9h, SPSP0/1 01h, TL/AL.
pub fn auth_sqe(fctype: u8, len: u32) -> Sqe {
    let mut s = Sqe::fabrics(fctype).u32_at(44, len);
    s.0[41] = 1;
    s.0[42] = 1;
    s.0[43] = 0xE9;
    s
}

impl Raw {
    /// Authentication Send with the message in the capsule.
    pub async fn auth_send(&mut self, msg: &[u8]) -> Cqe {
        let sqe = auth_sqe(0x05, msg.len() as u32).in_capsule(msg.len() as u32);
        self.cmd(&sqe, msg).await.1
    }

    /// Authentication Receive of `al` bytes.
    pub async fn auth_receive(&mut self, al: u32) -> (Vec<u8>, Cqe) {
        let sqe = auth_sqe(0x06, al).transport(al);
        self.cmd(&sqe, &[]).await
    }

    /// An Authentication Receive expected to be refused: its status.
    pub async fn auth_receive_sc(&mut self, al: u32) -> (u8, u8) {
        let (d, c) = self.auth_receive(al).await;
        assert!(d.is_empty(), "a refused receive returns no data");
        c.sc()
    }
}

/// A field tshark reads, across every packet, as one list.
pub fn tshark_values(raw: &Raw, field: &str) -> Vec<String> {
    raw.oracle()
        .fields(&[field])
        .unwrap_or_else(|e| panic!("tshark field {field}: {e}"))
        .into_iter()
        .flat_map(|r| {
            r.into_iter()
                .flat_map(|c| {
                    c.split(',')
                        .map(|v| v.trim().to_string())
                        .collect::<Vec<_>>()
                })
                .filter(|c| !c.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A number as tshark prints it: decimal, or hex with 0x.
pub fn number(v: &str) -> Option<u64> {
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Text of a space-padded ASCII field.
pub fn ascii(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_end_matches([' ', '\0'])
        .to_string()
}
