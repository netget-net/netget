//! An iSCSI initiator session (RFC 7143): login (with CHAP, and mutual CHAP when configured),
//! text-key negotiation, discovery, SCSI commands with Data-In, immediate, unsolicited and
//! R2T-solicited Data-Out, NOP-In answers and logout. No model here: `super` decides what to
//! run and reports what came back.
use crate::server::iscsi::chap::{self, Credential};
use crate::server::iscsi::pdu::{self, login_status, op, stage, Digests, Pdu, RESERVED_TAG};
use crate::server::iscsi::text::{self, DigestPreference, Params};
use crate::server::scsi_common::{self as scsi, Sense};
use anyhow::{bail, ensure, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Connecting to the target.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Each answer the target owes, during login and after.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// The rest of a PDU once its first byte arrived.
pub const PDU_DEADLINE: Duration = Duration::from_secs(30);
/// Login round trips before giving up on a target that never lets the login finish.
pub const MAX_LOGIN_ROUNDS: usize = 16;
/// What this initiator accepts in one data segment (declared in every login).
pub const OUR_MAX_RECV_DATA_SEGMENT: u32 = 262_144;
/// Bytes one SCSI command may bring back.
pub const MAX_COMMAND_BYTES: usize = 16 * 1024 * 1024;
/// Text (SendTargets) one exchange may bring back, across continuation PDUs.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Normal,
    Discovery,
}

/// What the operator configured for logging in.
#[derive(Clone, Debug)]
pub struct LoginConfig {
    pub initiator_name: String,
    pub chap: Option<Credential>,
    /// The target must prove this secret too (mutual CHAP), under this name if given.
    pub mutual: Option<Credential>,
    pub digests: DigestPreference,
}

/// How a login ended.
#[derive(Clone, Debug)]
pub struct LoginOutcome {
    pub status: u16,
    pub target_alias: Option<String>,
    pub tsih: u16,
    pub params: Params,
}

/// What a SCSI command came back with.
#[derive(Clone, Debug, Default)]
pub struct CommandOutcome {
    pub status: u8,
    pub sense: Option<Sense>,
    pub data: Vec<u8>,
    /// Residual: (overflow, underflow) counts.
    pub overflow: u32,
    pub underflow: u32,
}

pub struct Session {
    pub kind: Kind,
    pub target: String,
    pub params: Params,
    pub digests: Digests,
    pub tsih: u16,
    pub alias: Option<String>,
    writer: OwnedWriteHalf,
    pdus: mpsc::Receiver<std::result::Result<Pdu, String>>,
    reader: tokio::task::AbortHandle,
    /// The PDU reader, for the caller to register with the client's tasks.
    pub reader_task: Option<tokio::task::JoinHandle<()>>,
    cmd_sn: u32,
    exp_stat_sn: u32,
    next_itt: u32,
    /// The last SCSI command sent: (ITT, CmdSN), what an ABORT TASK names by default.
    pub last_task: Option<(u32, u32)>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

fn login_pdu(
    isid: &[u8; 6],
    itt: u32,
    cmd_sn: u32,
    exp_stat_sn: u32,
    csg: u8,
    transit: Option<u8>,
    pairs: &[(String, String)],
) -> Pdu {
    let mut p = Pdu::new(op::LOGIN_REQUEST);
    p.set_immediate();
    let mut flags = (csg << 2) & 0x0C;
    if let Some(nsg) = transit {
        flags |= 0x80 | (nsg & 0x03);
    }
    p.set_flags(flags);
    p.bhs[2] = 0; // version-max
    p.bhs[3] = 0; // version-min
    p.bhs[8..14].copy_from_slice(isid);
    p.set_itt(itt);
    p.set_u32(24, cmd_sn);
    p.set_u32(28, exp_stat_sn);
    p.data = text::encode(pairs);
    p
}

/// An ISID of the random type (RFC 7143 §11.12.5): T bits 10, then random.
fn random_isid() -> [u8; 6] {
    let mut isid: [u8; 6] = rand::random();
    isid[0] = 0x80 | (isid[0] & 0x3F);
    isid
}

impl Session {
    /// Connect and log in. `Err` is a transport or protocol failure; a target that refuses
    /// answers `Ok` with its status in the outcome and no session.
    pub async fn login(
        addr: SocketAddr,
        kind: Kind,
        target: &str,
        config: &LoginConfig,
    ) -> Result<(LoginOutcome, Option<Session>)> {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .with_context(|| format!("connecting to {addr} timed out"))?
            .with_context(|| format!("connecting to {addr}"))?;
        let _ = stream.set_nodelay(true);
        let isid = random_isid();
        let itt = 0u32;
        let cmd_sn: u32 = 1;
        let mut exp_stat_sn: u32 = 0;
        let mut params = Params {
            our_max_recv_data_segment: OUR_MAX_RECV_DATA_SEGMENT,
            ..Params::default()
        };
        let mut alias = None;

        let mut first: Vec<(String, String)> = vec![
            ("InitiatorName".into(), config.initiator_name.clone()),
            (
                "SessionType".into(),
                match kind {
                    Kind::Normal => "Normal",
                    Kind::Discovery => "Discovery",
                }
                .into(),
            ),
        ];
        if kind == Kind::Normal {
            first.push(("TargetName".into(), target.into()));
        }
        first.push((
            "AuthMethod".into(),
            if config.chap.is_some() {
                "CHAP,None"
            } else {
                "None"
            }
            .into(),
        ));
        let mut csg = stage::SECURITY;
        let mut pending: Vec<(String, String)> = first;
        let mut offered_ops = false;
        let mut chap_state: Option<(u8, Vec<u8>)> = None; // our challenge to the target
        let mut auth_done = config.chap.is_none();
        for _ in 0..MAX_LOGIN_ROUNDS {
            // Ask to move on whenever nothing is left to settle in this stage. The PDU that
            // carries our CHAP_R asks too, mutual challenge or not (RFC 7143's own example):
            // tgt is done with the security stage once CHAP_R verifies, and refuses any later
            // security-stage PDU with 0x0200. The target's answer to our challenge then rides
            // on its transit response, and is checked before the operational stage begins.
            let transit = match csg {
                stage::SECURITY if auth_done || chap_state.is_some() => Some(stage::OPERATIONAL),
                stage::SECURITY => None,
                _ => Some(stage::FULL_FEATURE),
            };
            if csg == stage::OPERATIONAL && !offered_ops {
                offered_ops = true;
                let mut ops = text::initiator_offer(config.digests, OUR_MAX_RECV_DATA_SEGMENT);
                if kind == Kind::Discovery {
                    ops.retain(|(k, _)| {
                        matches!(
                            k.as_str(),
                            "HeaderDigest"
                                | "DataDigest"
                                | "MaxRecvDataSegmentLength"
                                | "DefaultTime2Wait"
                                | "DefaultTime2Retain"
                        )
                    });
                }
                pending.extend(ops);
            }
            let req = login_pdu(
                &isid,
                itt,
                cmd_sn,
                exp_stat_sn,
                csg,
                transit,
                &std::mem::take(&mut pending),
            );
            stream.write_all(&req.encode(Digests::default())).await?;
            // A response may arrive in several PDUs (C bit): gather its text.
            let mut body = Vec::new();
            let resp = loop {
                let r = tokio::time::timeout(
                    RESPONSE_TIMEOUT,
                    pdu::read_pdu(
                        &mut stream,
                        Digests::default(),
                        pdu::DEFAULT_MAX_RECV_DATA_SEGMENT.max(OUR_MAX_RECV_DATA_SEGMENT as usize),
                        PDU_DEADLINE,
                    ),
                )
                .await
                .context("the target did not answer the login within 30 s")?
                .map_err(|e| anyhow::anyhow!("login: {e}"))?;
                ensure!(
                    r.opcode() == op::LOGIN_RESPONSE,
                    "the target answered a login with {}",
                    op::name(r.opcode())
                );
                ensure!(
                    body.len() + r.data.len() <= text::MAX_TEXT,
                    "the target's login text is over 64 KiB"
                );
                body.extend(&r.data);
                exp_stat_sn = r.u32_at(24).wrapping_add(1);
                let status = r.u16_at(36);
                if status != login_status::SUCCESS || r.flags() & 0x40 == 0 {
                    break r;
                }
                // Continued: ask for the rest with an empty request in the same stage.
                let more = login_pdu(&isid, itt, cmd_sn, exp_stat_sn, csg, None, &[]);
                stream.write_all(&more.encode(Digests::default())).await?;
            };
            let status = resp.u16_at(36);
            if status != login_status::SUCCESS {
                return Ok((
                    LoginOutcome {
                        status,
                        target_alias: None,
                        tsih: 0,
                        params,
                    },
                    None,
                ));
            }
            let keys = text::parse(&body).map_err(|e| anyhow::anyhow!("login answer: {e}"))?;
            for (k, v) in &keys {
                match k.as_str() {
                    "TargetAlias" => alias = Some(crate::utils::sanitize::line_field(v)),
                    "TargetPortalGroupTag" | "TargetAddress" => {}
                    "AuthMethod" => match v.as_str() {
                        "CHAP" => {
                            ensure!(
                                config.chap.is_some(),
                                "the target requires CHAP and no chap_name/chap_secret is configured"
                            );
                            pending.push(("CHAP_A".into(), chap::ALGORITHM_MD5.into()));
                        }
                        "None" => auth_done = true,
                        other => bail!("the target chose AuthMethod={other}"),
                    },
                    "CHAP_A" => ensure!(
                        v == chap::ALGORITHM_MD5,
                        "the target chose CHAP algorithm {v}, not MD5"
                    ),
                    "CHAP_I" | "CHAP_C" if csg == stage::SECURITY && chap_state.is_none() => {}
                    "CHAP_N" => {}
                    "CHAP_R" => {
                        let (id, challenge) = chap_state
                            .take()
                            .context("the target sent CHAP_R without being challenged")?;
                        let mutual = config.mutual.as_ref().context("unexpected CHAP_R")?;
                        let got = chap::decode_binary(v).context("CHAP_R is not binary")?;
                        let want = chap::response(id, mutual.secret.as_bytes(), &challenge);
                        ensure!(
                            chap::same(&got, &want),
                            "the target failed mutual CHAP: it does not hold the configured secret"
                        );
                        if !mutual.name.is_empty() {
                            ensure!(
                                text::get(&keys, "CHAP_N") == Some(mutual.name.as_str()),
                                "the target answered mutual CHAP under another name"
                            );
                        }
                        auth_done = true;
                    }
                    _ if (csg != stage::SECURITY || text::get(&keys, "AuthMethod").is_none())
                        && !matches!(v.as_str(), "NotUnderstood" | "Irrelevant" | "Reject") =>
                    {
                        // The answer must be one of the values offered (RFC 7143 6.2). tgt
                        // answers its own default, None, to an offer of CRC32C alone; taking
                        // that would run without the digests the operator asked for.
                        if matches!(k.as_str(), "HeaderDigest" | "DataDigest") {
                            let offered = config.digests.offer();
                            ensure!(
                                offered.split(',').any(|o| o == v),
                                "the target answered {k}={v}, which was not offered ({offered})"
                            );
                        }
                        text::apply_as_initiator(&mut params, k, v)
                            .map_err(|e| anyhow::anyhow!("the target answered {e}"))?;
                    }
                    _ => {}
                }
            }
            // A target that answers our mutual challenge with anything but CHAP_R has not
            // proved itself, so the login goes no further.
            ensure!(
                chap_state.is_none(),
                "the target did not answer the mutual CHAP challenge"
            );
            // The challenge: answer it, and challenge back for mutual CHAP.
            if let (Some(i), Some(c)) = (text::get(&keys, "CHAP_I"), text::get(&keys, "CHAP_C")) {
                if text::get(&keys, "CHAP_R").is_none() {
                    let cred = config.chap.as_ref().context("CHAP without credentials")?;
                    let id: u8 = i.parse().context("CHAP_I is not 0-255")?;
                    let challenge = chap::decode_binary(c).context("CHAP_C is not binary")?;
                    let r = chap::response(id, cred.secret.as_bytes(), &challenge);
                    pending.push(("CHAP_N".into(), cred.name.clone()));
                    pending.push(("CHAP_R".into(), chap::encode_binary(&r)));
                    if config.mutual.is_some() {
                        let (my_id, my_challenge) = chap::challenge();
                        pending.push(("CHAP_I".into(), my_id.to_string()));
                        pending.push(("CHAP_C".into(), chap::encode_binary(&my_challenge)));
                        chap_state = Some((my_id, my_challenge.to_vec()));
                    } else {
                        auth_done = true;
                    }
                }
            }
            if resp.flags() & 0x80 != 0 {
                let nsg = resp.flags() & 0x03;
                if nsg == stage::FULL_FEATURE {
                    ensure!(
                        auth_done,
                        "the target ended the login before authenticating"
                    );
                    // RFC 7143 has the final response carry the new session's TSIH; gotgt
                    // 0.2.2 sends 0. Nothing here depends on it (one connection, no
                    // reinstatement), so a missing TSIH is reported rather than refused.
                    let tsih = resp.u16_at(14);
                    let digests = Digests {
                        header: params.header_digest,
                        data: params.data_digest,
                    };
                    let (mut r, w) = stream.into_split();
                    let (tx, rx) = mpsc::channel(64);
                    let max = params.our_max_recv_data_segment as usize;
                    let reader = tokio::spawn(async move {
                        loop {
                            let item = pdu::read_pdu(&mut r, digests, max, PDU_DEADLINE)
                                .await
                                .map_err(|e| e.to_string());
                            let stop = item.is_err();
                            if tx.send(item).await.is_err() || stop {
                                return;
                            }
                        }
                    });
                    let reader_task = Some(reader);
                    let reader = reader_task.as_ref().expect("just set").abort_handle();
                    let outcome = LoginOutcome {
                        status,
                        target_alias: alias.clone(),
                        tsih,
                        params: params.clone(),
                    };
                    return Ok((
                        outcome,
                        Some(Session {
                            kind,
                            target: target.to_string(),
                            params,
                            digests,
                            tsih,
                            alias,
                            writer: w,
                            pdus: rx,
                            reader,
                            reader_task,
                            cmd_sn,
                            exp_stat_sn,
                            next_itt: 1,
                            last_task: None,
                        }),
                    ));
                }
                if nsg > csg {
                    csg = nsg;
                }
            }
        }
        bail!("the target did not finish the login in {MAX_LOGIN_ROUNDS} rounds")
    }

    async fn send(&mut self, p: &Pdu) -> Result<()> {
        self.writer.write_all(&p.encode(self.digests)).await?;
        Ok(())
    }

    fn itt(&mut self) -> u32 {
        let i = self.next_itt;
        self.next_itt = self.next_itt.wrapping_add(1);
        if self.next_itt == RESERVED_TAG {
            self.next_itt = 1;
        }
        i
    }

    /// The next PDU from the target, answering its NOP-In pings on the way.
    async fn next(&mut self) -> Result<Pdu> {
        loop {
            let p = tokio::time::timeout(RESPONSE_TIMEOUT, self.pdus.recv())
                .await
                .context("the target did not answer within 30 s")?
                .context("the connection closed")?
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if matches!(
                p.opcode(),
                op::SCSI_RESPONSE
                    | op::TASK_MGMT_RESPONSE
                    | op::TEXT_RESPONSE
                    | op::LOGOUT_RESPONSE
                    | op::NOP_IN
                    | op::REJECT
            ) || (p.opcode() == op::DATA_IN && p.flags() & 0x01 != 0)
            {
                let stat_sn = p.u32_at(24);
                // NOP-In pings without a status carry StatSN without consuming one.
                if !(p.opcode() == op::NOP_IN && p.itt() == RESERVED_TAG) {
                    self.exp_stat_sn = stat_sn.wrapping_add(1);
                }
            }
            if p.opcode() == op::NOP_IN && p.u32_at(20) != RESERVED_TAG {
                // A ping that wants an answer: NOP-Out with its TTT.
                let mut r = Pdu::new(op::NOP_OUT);
                r.set_immediate();
                r.set_flags(0x80);
                r.set_lun(p.lun());
                r.set_itt(RESERVED_TAG);
                r.set_u32(20, p.u32_at(20));
                r.set_u32(24, self.cmd_sn);
                r.set_u32(28, self.exp_stat_sn);
                self.send(&r).await?;
                continue;
            }
            if p.opcode() == op::ASYNC_MESSAGE {
                continue;
            }
            return Ok(p);
        }
    }

    /// The next PDU the target sends while no command is running. Cancel-safe: a select
    /// may drop it without losing anything.
    pub async fn unsolicited(&mut self) -> Option<std::result::Result<Pdu, String>> {
        self.pdus.recv().await
    }

    /// Deal with a PDU that arrived while idle: answer a NOP-In ping, ignore the rest.
    pub async fn handle_unsolicited(&mut self, p: Pdu) -> Result<()> {
        if p.opcode() == op::NOP_IN && p.u32_at(20) != RESERVED_TAG {
            let mut r = Pdu::new(op::NOP_OUT);
            r.set_immediate();
            r.set_flags(0x80);
            r.set_lun(p.lun());
            r.set_itt(RESERVED_TAG);
            r.set_u32(20, p.u32_at(20));
            r.set_u32(24, self.cmd_sn);
            r.set_u32(28, self.exp_stat_sn);
            self.send(&r).await?;
        }
        Ok(())
    }

    /// Run one SCSI command. `read_len` is the data the command brings back (0 for none);
    /// `write` is the data it sends.
    pub async fn command(
        &mut self,
        lun: u16,
        cdb: [u8; 16],
        read_len: usize,
        write: Option<&[u8]>,
    ) -> Result<CommandOutcome> {
        ensure!(
            read_len <= MAX_COMMAND_BYTES,
            "a command bringing back more than 16 MiB"
        );
        let itt = self.itt();
        let lun_field = scsi::lun_field(lun);
        let write = write.unwrap_or_default();
        let edtl = if write.is_empty() {
            read_len
        } else {
            write.len()
        };
        let mut p = Pdu::new(op::SCSI_COMMAND);
        let mut flags = 0x01u8; // ATTR simple
        if read_len > 0 {
            flags |= 0x40;
        }
        // Immediate data, then unsolicited Data-Out, as negotiated.
        let first_burst = (self.params.first_burst as usize).min(write.len());
        let mrdsl = (self.params.peer_max_recv_data_segment as usize).max(512);
        let immediate = if self.params.immediate_data {
            first_burst.min(mrdsl)
        } else {
            0
        };
        let unsolicited_end = if self.params.initial_r2t {
            immediate
        } else {
            first_burst
        };
        if !write.is_empty() {
            flags |= 0x20;
        }
        if unsolicited_end == immediate {
            flags |= 0x80;
        }
        p.set_flags(flags);
        p.set_lun(lun_field);
        p.set_itt(itt);
        p.set_u32(20, edtl as u32);
        p.set_u32(24, self.cmd_sn);
        self.last_task = Some((itt, self.cmd_sn));
        self.cmd_sn = self.cmd_sn.wrapping_add(1);
        p.set_u32(28, self.exp_stat_sn);
        p.bhs[32..48].copy_from_slice(&cdb);
        p.data = write[..immediate].to_vec();
        self.send(&p).await?;
        if unsolicited_end > immediate {
            self.send_data(
                itt,
                lun_field,
                RESERVED_TAG,
                write,
                immediate,
                unsolicited_end,
            )
            .await?;
        }
        let mut out = CommandOutcome::default();
        let mut data_sn = 0u32;
        loop {
            let r = self.next().await?;
            if r.itt() != itt && r.opcode() != op::REJECT {
                continue;
            }
            match r.opcode() {
                op::DATA_IN => {
                    ensure!(
                        r.u32_at(36) == data_sn,
                        "Data-In DataSN {} where {data_sn} was due",
                        r.u32_at(36)
                    );
                    data_sn += 1;
                    let offset = r.u32_at(40) as usize;
                    ensure!(
                        offset == out.data.len(),
                        "Data-In at offset {offset} where {} was due",
                        out.data.len()
                    );
                    ensure!(
                        out.data.len() + r.data.len() <= read_len,
                        "the target sent more data than the command asked for"
                    );
                    out.data.extend(&r.data);
                    if r.flags() & 0x01 != 0 {
                        out.status = r.bhs[3];
                        Self::residuals(&r, &mut out);
                        return Ok(out);
                    }
                }
                op::R2T => {
                    let ttt = r.u32_at(20);
                    let offset = r.u32_at(40) as usize;
                    let len = r.u32_at(44) as usize;
                    ensure!(
                        offset.checked_add(len).is_some_and(|e| e <= write.len()),
                        "an R2T for data outside the write"
                    );
                    self.send_data(itt, lun_field, ttt, write, offset, offset + len)
                        .await?;
                }
                op::SCSI_RESPONSE => {
                    ensure!(
                        r.bhs[2] == 0,
                        "the target could not complete the command (iSCSI response 0x{:02x})",
                        r.bhs[2]
                    );
                    out.status = r.bhs[3];
                    Self::residuals(&r, &mut out);
                    if r.data.len() >= 2 {
                        let n = u16::from_be_bytes([r.data[0], r.data[1]]) as usize;
                        out.sense = r.data.get(2..2 + n).and_then(Sense::parse);
                    }
                    return Ok(out);
                }
                op::REJECT => bail!(
                    "the target rejected the command (reason 0x{:02x})",
                    r.bhs[2]
                ),
                _ => {}
            }
        }
    }

    fn residuals(r: &Pdu, out: &mut CommandOutcome) {
        let f = r.flags();
        let residual = r.u32_at(44);
        if f & 0x04 != 0 {
            out.overflow = residual;
        }
        if f & 0x02 != 0 {
            out.underflow = residual;
        }
    }

    /// Data-Out PDUs for `data[from..to]`, each within the target's MaxRecvDataSegmentLength.
    async fn send_data(
        &mut self,
        itt: u32,
        lun: [u8; 8],
        ttt: u32,
        data: &[u8],
        from: usize,
        to: usize,
    ) -> Result<()> {
        let mrdsl = (self.params.peer_max_recv_data_segment as usize).max(512);
        let mut at = from;
        let mut data_sn = 0u32;
        while at < to {
            let end = (at + mrdsl).min(to);
            let mut d = Pdu::new(op::DATA_OUT);
            d.set_flags(if end == to { 0x80 } else { 0 });
            d.set_lun(lun);
            d.set_itt(itt);
            d.set_u32(20, ttt);
            d.set_u32(28, self.exp_stat_sn);
            d.set_u32(36, data_sn);
            d.set_u32(40, at as u32);
            d.data = data[at..end].to_vec();
            self.send(&d).await?;
            data_sn += 1;
            at = end;
        }
        Ok(())
    }

    /// SendTargets=All (or a name), with continuation: (target name, addresses) pairs.
    pub async fn send_targets(&mut self, which: &str) -> Result<Vec<(String, Vec<String>)>> {
        let itt = self.itt();
        let mut body = Vec::new();
        let mut ttt = RESERVED_TAG;
        let mut payload = text::encode(&[("SendTargets", which)]);
        loop {
            let mut p = Pdu::new(op::TEXT_REQUEST);
            p.set_immediate();
            p.set_flags(0x80);
            p.set_itt(itt);
            p.set_u32(20, ttt);
            p.set_u32(24, self.cmd_sn);
            p.set_u32(28, self.exp_stat_sn);
            p.data = std::mem::take(&mut payload);
            self.send(&p).await?;
            let r = loop {
                let r = self.next().await?;
                if r.opcode() == op::REJECT {
                    bail!(
                        "the target rejected SendTargets (reason 0x{:02x})",
                        r.bhs[2]
                    );
                }
                if r.opcode() == op::TEXT_RESPONSE && r.itt() == itt {
                    break r;
                }
            };
            ensure!(
                body.len() + r.data.len() <= MAX_TEXT_BYTES,
                "the target's SendTargets answer is over 64 KiB"
            );
            body.extend(&r.data);
            if r.flags() & 0x40 == 0 {
                break;
            }
            ttt = r.u32_at(20);
        }
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for item in body.split(|b| *b == 0).filter(|i| !i.is_empty()) {
            let s = String::from_utf8_lossy(item);
            let Some((k, v)) = s.split_once('=') else {
                continue;
            };
            let v = crate::utils::sanitize::line_field(v);
            match k {
                "TargetName" => out.push((v, vec![])),
                "TargetAddress" => {
                    if let Some(last) = out.last_mut() {
                        if last.1.len() < 16 {
                            last.1.push(v);
                        }
                    }
                }
                _ => {}
            }
            if out.len() > 256 {
                break;
            }
        }
        Ok(out)
    }

    /// A task management function (RFC 7143 §11.5), sent immediate as every initiator does,
    /// and the target's response code. `referenced` is the (ITT, CmdSN) an ABORT TASK names;
    /// the other functions name none.
    pub async fn task_management(
        &mut self,
        function: u8,
        lun: u16,
        referenced: Option<(u32, u32)>,
    ) -> Result<u8> {
        let itt = self.itt();
        let mut p = Pdu::new(op::TASK_MGMT_REQUEST);
        p.set_immediate();
        p.set_flags(0x80 | (function & 0x7F));
        p.set_lun(scsi::lun_field(lun));
        p.set_itt(itt);
        let (ref_itt, ref_cmd_sn) = referenced.unwrap_or((RESERVED_TAG, self.cmd_sn));
        p.set_u32(20, ref_itt);
        p.set_u32(24, self.cmd_sn);
        p.set_u32(28, self.exp_stat_sn);
        p.set_u32(32, ref_cmd_sn);
        self.send(&p).await?;
        loop {
            let r = self.next().await?;
            match r.opcode() {
                op::TASK_MGMT_RESPONSE if r.itt() == itt => return Ok(r.bhs[2]),
                op::REJECT if r.data.get(16..20) == Some(&itt.to_be_bytes()[..]) => bail!(
                    "the target rejected the task management request (reason 0x{:02x})",
                    r.bhs[2]
                ),
                _ => {}
            }
        }
    }

    /// Log out (close the session) and wait for the target's answer.
    pub async fn logout(&mut self) -> Result<u8> {
        let itt = self.itt();
        let mut p = Pdu::new(op::LOGOUT_REQUEST);
        p.set_immediate();
        p.set_flags(0x80); // reason 0: close the session
        p.set_itt(itt);
        p.set_u32(24, self.cmd_sn);
        p.set_u32(28, self.exp_stat_sn);
        self.send(&p).await?;
        loop {
            let r = self.next().await?;
            if r.opcode() == op::LOGOUT_RESPONSE && r.itt() == itt {
                let _ = self.writer.shutdown().await;
                return Ok(r.bhs[2]);
            }
        }
    }
}
