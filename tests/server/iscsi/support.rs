//! Shared harness for the iSCSI target suites: an in-process target with a python policy
//! playing the model (the LLM endpoint is unreachable, so an event the policy does not cover
//! exercises the fail-closed path), and a raw initiator that writes every PDU from literal
//! offsets of RFC 7143 §11 rather than through NetGet's encoder. It records every byte each
//! way, for the pcap oracle.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const DISK0: &str = "iqn.2026-10.net.netget:disk0";
pub const INITIATOR: &str = "iqn.2026-10.org.example:raw-initiator";

/// The model: disk0 has a writable LUN 0 (1 MiB, text at 0, a fill at 4096, a medium error at
/// 512 KiB) and a read-only LUN 1 (2 MiB of 4096-byte blocks); the denied initiator is refused;
/// three targets answer silently, invalidly, or not at all (falling through to the
/// unreachable model).
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='iscsi_discovery':
  a=[{'type':'iscsi_send_targets','targets':[{'name':'iqn.2026-10.net.netget:disk0'},{'name':'iqn.2026-10.net.netget:backup','addresses':['192.0.2.7:3260']}]}]
elif t=='iscsi_task_management':
  n=e['initiator_name']
  if n.endswith(':refuses-resets'):
    a=[{'type':'iscsi_refuse_reset','response':'unauthorized'}]
  elif n.endswith(':silent-resets'):
    a=[]
  elif n.endswith(':invalid-resets'):
    a=[{'type':'iscsi_refuse_reset','response':'maybe'}]
  elif n.endswith(':wrong-resets'):
    a=[{'type':'iscsi_send_targets','targets':[]}]
  else:
    a=[{'type':'iscsi_allow_reset'}]
elif e['initiator_name'].endswith(':denied'):
  a=[{'type':'iscsi_reject_login','reason':'unauthorized'}]
elif e['target_name']=='iqn.2026-10.net.netget:disk0':
  a=[{'type':'iscsi_accept_login','alias':'netget disk','luns':[
    {'lun':0,'size':1048576,'writable':True,'product':'BOOT-DISK','serial':'SER0001',
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}],
     'errors':[{'offset':524288,'length':4096,'error':'medium_error'}]},
    {'lun':1,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]}]}]
elif e['target_name']=='iqn.2026-10.net.netget:silent':
  a=[]
elif e['target_name']=='iqn.2026-10.net.netget:invalid':
  a=[{'type':'iscsi_accept_login','luns':[{'lun':0,'size':0}]}]
else:
  a=[{'type':'iscsi_reject_login','reason':'not_found'}]
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
}

/// Start the iSCSI target on loopback with an unreachable model, so only `handlers` answer.
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
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "iscsi".into(),
        port: Some(port),
        host: Some(host.into()),
        instruction: Some("Be a storage array".into()),
        event_handlers: handlers,
        startup_params: params,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting iscsi: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("iscsi failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server started");
    Started { state, id, port }
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

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

/// A received PDU: the 48-byte header and the data segment (unpadded).
#[derive(Debug, Clone)]
pub struct Got {
    pub bhs: Vec<u8>,
    pub data: Vec<u8>,
}

impl Got {
    pub fn opcode(&self) -> u8 {
        self.bhs[0] & 0x3F
    }
    pub fn flags(&self) -> u8 {
        self.bhs[1]
    }
    pub fn itt(&self) -> u32 {
        be32(&self.bhs, 16)
    }
    pub fn u32(&self, at: usize) -> u32 {
        be32(&self.bhs, at)
    }
    /// Login status class and detail.
    pub fn login_status(&self) -> u16 {
        u16::from_be_bytes([self.bhs[36], self.bhs[37]])
    }
    pub fn text(&self) -> Vec<(String, String)> {
        keys(&self.data)
    }
    /// The SCSI status byte of a SCSI Response or a status-carrying Data-In.
    pub fn status(&self) -> u8 {
        self.bhs[3]
    }
    /// Fixed-format sense out of a SCSI Response's data segment: (key, asc, ascq).
    pub fn sense(&self) -> Option<(u8, u8, u8)> {
        if self.data.len() < 2 + 14 {
            return None;
        }
        let s = &self.data[2..];
        Some((s[2] & 0x0F, s[12], s[13]))
    }
}

pub fn keys(data: &[u8]) -> Vec<(String, String)> {
    data.split(|b| *b == 0)
        .filter(|k| !k.is_empty())
        .map(|kv| {
            let s = String::from_utf8_lossy(kv).into_owned();
            let (k, v) = s.split_once('=').unwrap_or((&s, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

pub fn key<'a>(pairs: &'a [(String, String)], k: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

pub fn text(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in pairs {
        out.extend(k.as_bytes());
        out.push(b'=');
        out.extend(v.as_bytes());
        out.push(0);
    }
    out
}

/// A raw initiator over one TCP connection. Every byte it writes and reads is kept, for the
/// pcap oracle.
pub struct Raw {
    pub s: TcpStream,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub header_digest: bool,
    pub data_digest: bool,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub itt: u32,
    /// The initiator port and connection a login names: InitiatorName, ISID (offset 8), TSIH
    /// (14: 0 for a new session, the session's to add a connection to it) and CID (20).
    pub initiator: String,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub cid: u16,
}

pub const ISID: [u8; 6] = [0x80, 0x12, 0x34, 0x56, 0x78, 0x9a];

impl Raw {
    pub async fn connect(port: u16) -> Raw {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        Raw {
            s,
            sent: Vec::new(),
            received: Vec::new(),
            header_digest: false,
            data_digest: false,
            cmd_sn: 1,
            exp_stat_sn: 0,
            itt: 0x100,
            initiator: INITIATOR.into(),
            isid: ISID,
            tsih: 0,
            cid: 0,
        }
    }

    /// Another connection of `session`'s session (same initiator port and TSIH), with `cid`.
    /// CmdSN carries on from the session's; StatSN is this connection's own.
    pub async fn join(port: u16, session: &Raw, cid: u16) -> Raw {
        let mut r = Raw::connect(port).await;
        r.initiator = session.initiator.clone();
        r.isid = session.isid;
        r.tsih = session.tsih;
        r.cid = cid;
        r.cmd_sn = session.cmd_sn;
        r.itt = session.itt + 0x1000 * cid as u32;
        r
    }

    pub fn next_itt(&mut self) -> u32 {
        self.itt += 1;
        self.itt
    }

    /// A PDU as bytes: `bhs` with its lengths filled in, then data padded, with the digests
    /// in force.
    pub fn frame(&self, mut bhs: [u8; 48], data: &[u8]) -> Vec<u8> {
        let len = data.len() as u32;
        bhs[5] = (len >> 16) as u8;
        bhs[6] = (len >> 8) as u8;
        bhs[7] = len as u8;
        let mut out = bhs.to_vec();
        if self.header_digest {
            out.extend(crc32c(&bhs).to_le_bytes());
        }
        if !data.is_empty() {
            let mut d = data.to_vec();
            while !d.len().is_multiple_of(4) {
                d.push(0);
            }
            out.extend(&d);
            if self.data_digest {
                out.extend(crc32c(&d).to_le_bytes());
            }
        }
        out
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        self.sent.extend(bytes);
        self.s.write_all(bytes).await.unwrap();
    }

    pub async fn send(&mut self, bhs: [u8; 48], data: &[u8]) {
        let b = self.frame(bhs, data);
        self.write(&b).await;
    }

    /// The next PDU within `secs` seconds, or `None` when the target closed or said nothing.
    pub async fn recv_within(&mut self, wait: Duration) -> Option<Got> {
        let read = async {
            let mut bhs = vec![0u8; 48];
            self.s.read_exact(&mut bhs).await.ok()?;
            let ahs = bhs[4] as usize * 4;
            let dsl = ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | bhs[7] as usize;
            let mut raw = bhs.clone();
            let mut rest = vec![0u8; ahs];
            self.s.read_exact(&mut rest).await.ok()?;
            raw.extend(&rest);
            if self.header_digest {
                let mut d = [0u8; 4];
                self.s.read_exact(&mut d).await.ok()?;
                let mut covered = bhs.clone();
                covered.extend(&rest);
                assert_eq!(
                    u32::from_le_bytes(d),
                    crc32c(&covered),
                    "the target's header digest is wrong"
                );
                raw.extend(d);
            }
            let padded = dsl.div_ceil(4) * 4;
            let mut data = vec![0u8; padded];
            if dsl > 0 {
                self.s.read_exact(&mut data).await.ok()?;
                raw.extend(&data);
                if self.data_digest {
                    let mut d = [0u8; 4];
                    self.s.read_exact(&mut d).await.ok()?;
                    assert_eq!(
                        u32::from_le_bytes(d),
                        crc32c(&data),
                        "the target's data digest is wrong"
                    );
                    raw.extend(d);
                }
            }
            data.truncate(dsl);
            Some((Got { bhs, data }, raw))
        };
        match tokio::time::timeout(wait, read).await {
            Ok(Some((got, raw))) => {
                self.received.extend(raw);
                // Track StatSN from every status-bearing PDU.
                let op = got.opcode();
                if matches!(op, 0x21 | 0x22 | 0x23 | 0x24 | 0x26 | 0x3f)
                    || (op == 0x20 && got.itt() != 0xffff_ffff)
                    || (op == 0x25 && got.flags() & 0x01 != 0)
                {
                    self.exp_stat_sn = got.u32(24).wrapping_add(1);
                }
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

    /// A Login Request: CSG and, when transiting, NSG; ITT, CmdSN, ExpStatSN as offsets 16,
    /// 24, 28; ISID at 8.
    pub fn login_bhs(&self, csg: u8, transit: Option<u8>, cont: bool) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = 0x43; // I bit + Login Request
        b[1] = (csg << 2) | if cont { 0x40 } else { 0 };
        if let Some(nsg) = transit {
            b[1] |= 0x80 | nsg;
        }
        b[8..14].copy_from_slice(&self.isid);
        b[14..16].copy_from_slice(&self.tsih.to_be_bytes());
        b[16..20].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        b[20..22].copy_from_slice(&self.cid.to_be_bytes());
        b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        b
    }

    pub async fn login_step(
        &mut self,
        csg: u8,
        transit: Option<u8>,
        pairs: &[(&str, &str)],
    ) -> Got {
        let b = self.login_bhs(csg, transit, false);
        let data = text(pairs);
        // Login PDUs never carry digests.
        let (h, d) = (self.header_digest, self.data_digest);
        self.header_digest = false;
        self.data_digest = false;
        self.send(b, &data).await;
        let got = self.recv().await;
        self.header_digest = h;
        self.data_digest = d;
        assert_eq!(got.opcode(), 0x23, "a Login Response");
        got
    }

    /// A complete login without authentication: security (AuthMethod=None) then operational
    /// with `ops`, to full feature phase. Returns the final response.
    pub async fn login(&mut self, kind: &str, target: Option<&str>, ops: &[(&str, &str)]) -> Got {
        let initiator = self.initiator.clone();
        let mut first: Vec<(&str, &str)> =
            vec![("InitiatorName", &initiator), ("SessionType", kind)];
        if let Some(t) = target {
            first.push(("TargetName", t));
        }
        first.push(("AuthMethod", "None"));
        let r = self.login_step(0, Some(1), &first).await;
        assert_eq!(r.login_status(), 0, "security stage: {:?}", r.text());
        assert_eq!(r.flags() & 0x83, 0x81, "transit to operational");
        self.finish_operational(ops).await
    }

    pub async fn finish_operational(&mut self, ops: &[(&str, &str)]) -> Got {
        let r = self.login_step(1, Some(3), ops).await;
        assert_eq!(r.login_status(), 0, "operational stage: {:?}", r.text());
        assert_eq!(r.flags() & 0x83, 0x83, "transit to full feature phase");
        let t = r.text();
        self.header_digest = key(&t, "HeaderDigest") == Some("CRC32C");
        self.data_digest = key(&t, "DataDigest") == Some("CRC32C");
        self.tsih = u16::from_be_bytes([r.bhs[14], r.bhs[15]]);
        r
    }

    /// A SCSI Command PDU: flags (F/R/W), LUN, ITT, EDTL, CmdSN, CDB.
    pub fn scsi_bhs(&mut self, flags: u8, lun: u8, edtl: u32, cdb: &[u8]) -> ([u8; 48], u32) {
        let itt = self.next_itt();
        let mut b = [0u8; 48];
        b[0] = 0x01;
        b[1] = flags | 0x01; // ATTR simple
        b[9] = lun;
        b[16..20].copy_from_slice(&itt.to_be_bytes());
        b[20..24].copy_from_slice(&edtl.to_be_bytes());
        b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        self.cmd_sn += 1;
        b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        b[32..32 + cdb.len()].copy_from_slice(cdb);
        (b, itt)
    }

    /// Run a read-type command: its Data-In bytes and the final status PDU.
    pub async fn read_cmd(&mut self, lun: u8, edtl: u32, cdb: &[u8]) -> (Vec<u8>, Got) {
        let (b, itt) = self.scsi_bhs(0xC0, lun, edtl, cdb);
        self.send(b, &[]).await;
        let mut data = Vec::new();
        let mut data_sn = 0;
        loop {
            let g = self.recv().await;
            assert_eq!(g.itt(), itt, "an answer to this command: {g:?}");
            match g.opcode() {
                0x25 => {
                    assert_eq!(g.u32(36), data_sn, "DataSN in order");
                    assert_eq!(g.u32(40) as usize, data.len(), "buffer offset in order");
                    data_sn += 1;
                    data.extend(&g.data);
                    if g.flags() & 0x01 != 0 {
                        return (data, g);
                    }
                }
                0x21 => return (data, g),
                other => panic!("unexpected opcode 0x{other:02x}"),
            }
        }
    }

    /// TEST UNIT READY.
    pub async fn tur(&mut self, lun: u8) -> Got {
        let (b, _) = self.scsi_bhs(0x80, lun, 0, &[0u8; 6]);
        self.send(b, &[]).await;
        self.recv().await
    }

    /// An immediate Task Management Function Request (RFC 7143 §11.5): function, LUN,
    /// Referenced Task Tag (0xffffffff when none), RefCmdSN and ExpDataSN. Returns its ITT.
    pub async fn send_tmf(
        &mut self,
        function: u8,
        lun: u8,
        referenced: u32,
        ref_cmd_sn: u32,
        exp_data_sn: u32,
    ) -> u32 {
        let itt = self.next_itt();
        let mut b = [0u8; 48];
        b[0] = 0x42; // I + Task Management Function Request
        b[1] = 0x80 | function;
        b[9] = lun;
        b[16..20].copy_from_slice(&itt.to_be_bytes());
        b[20..24].copy_from_slice(&referenced.to_be_bytes());
        b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        b[32..36].copy_from_slice(&ref_cmd_sn.to_be_bytes());
        b[36..40].copy_from_slice(&exp_data_sn.to_be_bytes());
        self.send(b, &[]).await;
        itt
    }

    /// A task management function and its response code.
    pub async fn tmf(&mut self, function: u8, lun: u8) -> u8 {
        let itt = self
            .send_tmf(function, lun, 0xffff_ffff, self.cmd_sn, 0)
            .await;
        let g = self.recv().await;
        assert_eq!((g.opcode(), g.itt()), (0x22, itt), "a TMF Response: {g:?}");
        g.bhs[2]
    }

    /// A SNACK Request (RFC 7143 §11.16): type, ITT, Target Transfer Tag or SNACK Tag,
    /// BegRun, RunLength. `exp_stat_sn` is what it acknowledges.
    pub async fn send_snack(
        &mut self,
        kind: u8,
        lun: u8,
        itt: u32,
        tag: u32,
        beg_run: u32,
        run_length: u32,
        exp_stat_sn: u32,
    ) {
        let mut b = [0u8; 48];
        b[0] = 0x10;
        b[1] = 0x80 | kind;
        b[9] = lun;
        b[16..20].copy_from_slice(&itt.to_be_bytes());
        b[20..24].copy_from_slice(&tag.to_be_bytes());
        b[28..32].copy_from_slice(&exp_stat_sn.to_be_bytes());
        b[40..44].copy_from_slice(&beg_run.to_be_bytes());
        b[44..48].copy_from_slice(&run_length.to_be_bytes());
        self.send(b, &[]).await;
    }

    /// A Logout Request with a reason (0 session, 1 connection, 2 recovery) for a CID.
    pub async fn logout_cid(&mut self, reason: u8, cid: u16) -> Got {
        let mut b = [0u8; 48];
        b[0] = 0x46;
        b[1] = 0x80 | reason;
        let itt = self.next_itt();
        b[16..20].copy_from_slice(&itt.to_be_bytes());
        b[20..22].copy_from_slice(&cid.to_be_bytes());
        b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        self.send(b, &[]).await;
        let g = self.recv().await;
        assert_eq!(g.opcode(), 0x26, "a Logout Response: {g:?}");
        g
    }

    /// A Data-Out PDU: ITT, TTT, DataSN, buffer offset, F bit.
    pub fn data_out_bhs(
        &self,
        itt: u32,
        ttt: u32,
        data_sn: u32,
        offset: u32,
        last: bool,
    ) -> [u8; 48] {
        let mut d = [0u8; 48];
        d[0] = 0x05;
        d[1] = if last { 0x80 } else { 0 };
        d[16..20].copy_from_slice(&itt.to_be_bytes());
        d[20..24].copy_from_slice(&ttt.to_be_bytes());
        d[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        d[36..40].copy_from_slice(&data_sn.to_be_bytes());
        d[40..44].copy_from_slice(&offset.to_be_bytes());
        d
    }

    /// A Logout Request (close the session) and its response.
    pub async fn logout(&mut self) -> Got {
        let mut b = [0u8; 48];
        b[0] = 0x46;
        b[1] = 0x80;
        let itt = self.next_itt();
        b[16..20].copy_from_slice(&itt.to_be_bytes());
        b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        self.send(b, &[]).await;
        let g = self.recv().await;
        assert_eq!(g.opcode(), 0x26, "a Logout Response");
        g
    }

    /// A Text Request carrying `pairs`, and the whole answer (following continuations).
    pub async fn text_request(&mut self, pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        let itt = self.next_itt();
        let mut ttt = 0xffff_ffffu32;
        let mut payload = text(pairs);
        let mut answer = Vec::new();
        loop {
            let mut b = [0u8; 48];
            b[0] = 0x44; // I + Text Request
            b[1] = 0x80;
            b[16..20].copy_from_slice(&itt.to_be_bytes());
            b[20..24].copy_from_slice(&ttt.to_be_bytes());
            b[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
            b[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
            self.send(b, &std::mem::take(&mut payload)).await;
            let g = self.recv().await;
            assert_eq!(g.opcode(), 0x24, "a Text Response: {g:?}");
            answer.extend(&g.data);
            if g.flags() & 0x40 == 0 {
                assert_eq!(g.u32(20), 0xffff_ffff, "a final text response has no TTT");
                return keys(&answer);
            }
            ttt = g.u32(20);
        }
    }
}

/// READ(10) CDB.
pub fn read10(lba: u32, blocks: u16) -> Vec<u8> {
    let mut c = vec![0x28, 0];
    c.extend(lba.to_be_bytes());
    c.push(0);
    c.extend(blocks.to_be_bytes());
    c.push(0);
    c
}

/// WRITE(10) CDB.
pub fn write10(lba: u32, blocks: u16) -> Vec<u8> {
    let mut c = read10(lba, blocks);
    c[0] = 0x2A;
    c
}

pub fn json_value(v: &Value) -> String {
    v.to_string()
}
