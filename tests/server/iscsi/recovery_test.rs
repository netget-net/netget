//! Task management, sessions of several connections and error recovery levels 1 and 2, driven
//! by the raw initiator of `support.rs` (PDUs written from RFC 7143's offsets).
//!
//! No independent initiator drives these: libiscsi and open-iscsi both hard-code
//! ErrorRecoveryLevel=0 and MaxConnections=1 in their login, neither sends SNACK, DataACK or
//! TASK REASSIGN, and the kernel sends only ABORT TASK, LUN RESET and TARGET WARM RESET (see
//! tests/server/iscsi/AGENTS.md). The resets libiscsi does send are in `real_client_test.rs`.
//! What these tests assert is what the target puts on the wire, and tshark reads it.
use super::support::*;
use crate::helpers::pcap_oracle::PcapOracle;
use serde_json::json;
use std::time::Duration;

fn oracle(raw: &Raw) -> PcapOracle {
    PcapOracle::tcp("iscsi")
        .to_server(&raw.sent)
        .from_server(&raw.received)
}

/// A raw initiator logged in to disk0 as its own I_T nexus.
async fn session(port: u16, name: &str, isid_tail: u8, ops: &[(&str, &str)]) -> Raw {
    let mut r = Raw::connect(port).await;
    r.initiator = format!("iqn.2026-10.org.example:{name}");
    r.isid = [0x80, 0x00, 0x00, 0x00, 0x00, isid_tail];
    r.login("Normal", Some(DISK0), ops).await;
    r
}

const NO_IMMEDIATE: &[(&str, &str)] = &[("InitialR2T", "Yes"), ("ImmediateData", "No")];

/// A write of one block that waits for its data: (ITT, the R2T).
async fn write_waiting(raw: &mut Raw, lun: u8, lba: u32) -> (u32, Got) {
    let (b, itt) = raw.scsi_bhs(0xA0, lun, 512, &write10(lba, 1));
    raw.send(b, &[]).await;
    let r2t = raw.recv().await;
    assert_eq!((r2t.opcode(), r2t.itt()), (0x31, itt), "an R2T: {r2t:?}");
    (itt, r2t)
}

fn sense_of(g: &Got) -> Option<(u8, u8, u8)> {
    assert_eq!(g.opcode(), 0x21, "a SCSI Response: {g:?}");
    g.sense()
}

#[tokio::test]
async fn resets_are_the_models_decision_and_leave_a_unit_attention_on_every_nexus() {
    let srv = start(policy(POLICY), None).await;
    let mut a = session(srv.port, "host-a", 1, &[]).await;
    let mut b = session(srv.port, "host-b", 2, NO_IMMEDIATE).await;
    assert_eq!(a.tur(0).await.status(), 0);
    // B has a write waiting for its data when A resets LUN 0.
    let (witt, r2t) = write_waiting(&mut b, 0, 600).await;
    assert_eq!(
        a.tmf(5, 0).await,
        0,
        "LOGICAL UNIT RESET: function complete"
    );
    let asked = events(&srv.state, srv.id, "iscsi_task_management").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["function"], "logical_unit_reset");
    assert_eq!(asked[0]["lun"], 0);
    assert_eq!(asked[0]["outstanding_tasks"], 1, "B's write");
    assert_eq!(asked[0]["sessions_affected"], 2);
    // B's write ended with no response: its late data belongs to no task.
    let d = b.data_out_bhs(witt, r2t.u32(20), 0, 0, true);
    b.send(d, &[7u8; 512]).await;
    assert!(
        b.recv_within(Duration::from_millis(500)).await.is_none(),
        "no response for a task the reset ended"
    );
    // Every nexus gets BUS DEVICE RESET FUNCTION OCCURRED on its next command to LUN 0, once,
    // and the command does not run.
    for raw in [&mut a, &mut b] {
        let g = raw.tur(0).await;
        assert_eq!(g.status(), 0x02);
        assert_eq!(sense_of(&g), Some((0x06, 0x29, 0x03)));
        assert_eq!(raw.tur(0).await.status(), 0, "reported once");
    }
    assert_eq!(b.tur(1).await.status(), 0, "LUN 1 was not reset");
    let (back, _) = b.read_cmd(0, 512, &read10(600, 1)).await;
    assert!(
        back.iter().all(|x| *x == 0),
        "the ended write wrote nothing"
    );

    // TARGET WARM RESET: POWER ON, RESET, OR BUS DEVICE RESET OCCURRED on every LUN of every
    // nexus. REQUEST SENSE returns it as its data, and clears it.
    assert_eq!(b.tmf(6, 0).await, 0);
    let (sense, g) = a.read_cmd(0, 18, &[0x03, 0, 0, 0, 18, 0]).await;
    assert_eq!(g.status(), 0);
    assert_eq!((sense[2] & 0x0F, sense[12], sense[13]), (0x06, 0x29, 0x00));
    assert_eq!(a.tur(0).await.status(), 0);
    assert_eq!(sense_of(&a.tur(1).await), Some((0x06, 0x29, 0x00)));
    for lun in [0, 1] {
        assert_eq!(sense_of(&b.tur(lun).await), Some((0x06, 0x29, 0x00)));
    }

    // Refusals change nothing: the model's (authorization failed), its silence and an invalid
    // answer (function rejected, fail closed).
    for (who, tail, response) in [
        ("x:refuses-resets", 3u8, 6u8),
        ("x:silent-resets", 4, 255),
        ("x:invalid-resets", 5, 255),
        // A valid action, but not a decision about the reset.
        ("x:wrong-resets", 6, 255),
    ] {
        let mut c = session(srv.port, who, tail, &[]).await;
        assert_eq!(c.tmf(5, 0).await, response, "{who}");
        assert_eq!(c.tmf(6, 0).await, response, "{who}");
        assert_eq!(
            a.tur(0).await.status(),
            0,
            "{who}'s refused reset left no unit attention"
        );
    }

    // TARGET COLD RESET: answered, then every session of the target ends; the power-on unit
    // attention waits for each nexus's next login.
    assert_eq!(a.tmf(7, 0).await, 0);
    assert!(a.closed().await, "the issuing connection closes");
    assert!(b.closed().await, "every session of the target ends");
    let mut a2 = session(srv.port, "host-a", 1, &[]).await;
    assert_eq!(sense_of(&a2.tur(0).await), Some((0x06, 0x29, 0x01)));
    assert_eq!(a2.tur(0).await.status(), 0);
    let mut fresh = session(srv.port, "host-new", 9, &[]).await;
    assert_eq!(
        fresh.tur(0).await.status(),
        0,
        "a nexus that was not there has nothing owed"
    );

    let rows = oracle(&a)
        .fields(&["iscsi.taskmanfun.function", "iscsi.taskmanfun.response"])
        .unwrap();
    let functions: Vec<&str> = rows
        .iter()
        .map(|r| r[0].as_str())
        .filter(|f| !f.is_empty())
        .collect();
    assert!(
        functions.iter().any(|f| f.contains('5')) && functions.iter().any(|f| f.contains('7')),
        "tshark reads the LUN reset and the cold reset: {rows:?}"
    );
    oracle(&a).assert_clean();
    oracle(&b).assert_clean();
}

#[tokio::test]
async fn a_reset_the_model_cannot_answer_fails_closed() {
    // Logins and discovery have a handler; a reset falls through to the unreachable model.
    let handlers = Some(vec![
        json!({"event_pattern":"iscsi_login","handler":{"type":"script","language":"python","code":POLICY}}),
    ]);
    let srv = start(handlers, None).await;
    let mut a = session(srv.port, "host-a", 1, NO_IMMEDIATE).await;
    let (witt, r2t) = write_waiting(&mut a, 0, 10).await;
    assert_eq!(a.tmf(5, 0).await, 255, "function rejected");
    assert_eq!(a.tmf(7, 0).await, 255, "function rejected");
    assert_eq!(
        a.tur(0).await.status(),
        0,
        "no unit attention: nothing was reset"
    );
    // The write the refused resets would have ended is still there.
    let d = a.data_out_bhs(witt, r2t.u32(20), 0, 0, true);
    a.send(d, &[5u8; 512]).await;
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, witt, 0));
}

#[tokio::test]
async fn task_sets_wait_for_the_data_they_end_and_unsupported_functions_are_refused() {
    let srv = start(policy(POLICY), None).await;
    let mut a = session(srv.port, "host-a", 1, NO_IMMEDIATE).await;
    let mut b = session(srv.port, "host-b", 2, NO_IMMEDIATE).await;
    // ABORT TASK SET while its write has an R2T outstanding: the response waits for the data
    // the R2T asked for (RFC 7143 §4.2.3.3 a), and the write is not answered.
    let (witt, r2t) = write_waiting(&mut a, 0, 700).await;
    let tmf = a.send_tmf(2, 0, 0xffff_ffff, a.cmd_sn, 0).await;
    assert!(
        a.recv_within(Duration::from_millis(700)).await.is_none(),
        "no response while the transfer it ended is still owed"
    );
    let d = a.data_out_bhs(witt, r2t.u32(20), 0, 0, true);
    a.send(d, &[9u8; 512]).await;
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.bhs[2]), (0x22, tmf, 0));
    assert!(a.recv_within(Duration::from_millis(500)).await.is_none());
    let (back, _) = a.read_cmd(0, 512, &read10(700, 1)).await;
    assert!(back.iter().all(|x| *x == 0));
    assert_eq!(
        a.tur(0).await.status(),
        0,
        "ABORT TASK SET leaves no unit attention"
    );

    // CLEAR TASK SET: one task set per logical unit, so B's write goes too, and B is told
    // COMMANDS CLEARED BY ANOTHER INITIATOR.
    let (bitt, br2t) = write_waiting(&mut b, 0, 701).await;
    assert_eq!(a.tmf(4, 0).await, 0);
    let d = b.data_out_bhs(bitt, br2t.u32(20), 0, 0, true);
    b.send(d, &[9u8; 512]).await;
    assert!(b.recv_within(Duration::from_millis(500)).await.is_none());
    assert_eq!(sense_of(&b.tur(0).await), Some((0x06, 0x2F, 0x00)));
    assert_eq!(
        a.tur(0).await.status(),
        0,
        "the issuer is not told of its own clear"
    );

    // What is not supported says so.
    assert_eq!(a.tmf(3, 0).await, 5, "CLEAR ACA: no ACA here");
    assert_eq!(
        a.tmf(3, 9).await,
        2,
        "CLEAR ACA on a LUN that does not exist"
    );
    assert_eq!(
        a.tmf(2, 9).await,
        2,
        "ABORT TASK SET on a LUN that does not exist"
    );
    assert_eq!(
        a.tmf(5, 9).await,
        2,
        "LUN RESET on a LUN that does not exist"
    );
    assert_eq!(
        a.tmf(8, 0).await,
        4,
        "TASK REASSIGN at error recovery level 0"
    );
    assert_eq!(a.tmf(9, 0).await, 5, "QUERY TASK");
    assert_eq!(a.tmf(13, 0).await, 255, "an unassigned function");
    let mut tur = vec![0u8; 6];
    tur[5] = 0x04; // NACA
    let (b6, _) = a.scsi_bhs(0x80, 0, 0, &tur);
    a.send(b6, &[]).await;
    assert_eq!(
        sense_of(&a.recv().await),
        Some((0x05, 0x24, 0x00)),
        "NACA is refused"
    );
    oracle(&a).assert_clean();
}

#[tokio::test]
async fn a_session_of_two_connections_runs_commands_in_cmdsn_order_across_them() {
    let srv = start(policy(POLICY), Some(json!({"max_connections": 2}))).await;
    let mut a = Raw::connect(srv.port).await;
    let r = a
        .login("Normal", Some(DISK0), &[("MaxConnections", "8")])
        .await;
    assert_eq!(key(&r.text(), "MaxConnections"), Some("2"), "the minimum");
    assert_ne!(a.tsih, 0);
    // A second connection of the session: same ISID and TSIH, CID 1. The model is not asked
    // again, and the session-wide keys are the session's.
    let mut b = Raw::join(srv.port, &a, 1).await;
    let r = b
        .login(
            "Normal",
            Some(DISK0),
            &[("MaxConnections", "1"), ("MaxBurstLength", "512")],
        )
        .await;
    assert_eq!(b.tsih, a.tsih, "the same session");
    assert_eq!(key(&r.text(), "MaxConnections"), Some("2"));
    assert_eq!(
        key(&r.text(), "MaxBurstLength"),
        Some("262144"),
        "the leading login's value"
    );
    assert_eq!(events(&srv.state, srv.id, "iscsi_login").await.len(), 1);
    // A third is over MaxConnections: too many connections.
    let mut c = Raw::join(srv.port, &a, 2).await;
    let s = c
        .login_step(
            0,
            Some(1),
            &[
                ("InitiatorName", INITIATOR),
                ("SessionType", "Normal"),
                ("TargetName", DISK0),
                ("AuthMethod", "None"),
            ],
        )
        .await;
    assert_eq!(
        s.login_status(),
        0x0206,
        "too many connections: {:?}",
        s.text()
    );

    // CmdSN N+1 on A (a READ) arrives before N on B (a WRITE of the same block): it is held,
    // then runs after the WRITE, and reads what the WRITE wrote.
    let n = a.cmd_sn;
    a.cmd_sn = n + 1;
    let (rd, ritt) = a.scsi_bhs(0xC0, 0, 512, &read10(800, 1));
    a.send(rd, &[]).await;
    assert!(
        a.recv_within(Duration::from_millis(700)).await.is_none(),
        "CmdSN N+1 waits for N"
    );
    b.cmd_sn = n;
    let (wr, witt) = b.scsi_bhs(0xA0, 0, 512, &write10(800, 1));
    b.send(wr, &[0x4D; 512]).await;
    let g = b.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, witt, 0));
    let g = a.recv().await;
    assert_eq!(
        (g.opcode(), g.itt()),
        (0x25, ritt),
        "the READ runs once N has"
    );
    assert!(
        g.data.iter().all(|x| *x == 0x4D),
        "and reads the WRITE's data"
    );
    assert_eq!(g.u32(28), n + 2, "ExpCmdSN is the session's");
    // Three commands become runnable at once: N+1 on B (a WRITE of block 801) and N+2 on A (a
    // READ of it) are held, then N on A fills the gap. A runs N, but its own N+2 waits for B's
    // N+1 although both are already in order: only the front of the queue runs.
    let n = n + 2;
    b.cmd_sn = n + 1;
    let (wr, witt) = b.scsi_bhs(0xA0, 0, 512, &write10(801, 1));
    b.send(wr, &[0x58; 512]).await;
    a.cmd_sn = n + 2;
    let (rd, ritt) = a.scsi_bhs(0xC0, 0, 512, &read10(801, 1));
    a.send(rd, &[]).await;
    assert!(a.recv_within(Duration::from_millis(300)).await.is_none());
    a.cmd_sn = n;
    let (tu, titt) = a.scsi_bhs(0x80, 0, 0, &[0u8; 6]);
    a.send(tu, &[]).await;
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, titt, 0));
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.itt()), (0x25, ritt));
    assert!(
        g.data.iter().all(|x| *x == 0x58),
        "N+2 ran after the other connection's N+1"
    );
    let g = b.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, witt, 0));
    let n = n + 1;
    a.cmd_sn = n + 2;
    b.cmd_sn = n + 2;
    // A command beyond the window on either connection is dropped, not held.
    b.cmd_sn = n + 2 + 40;
    let (t, _) = b.scsi_bhs(0x80, 0, 0, &[0u8; 6]);
    b.send(t, &[]).await;
    assert!(b.recv_within(Duration::from_millis(500)).await.is_none());
    b.cmd_sn = n + 2;

    // Logout of B's connection from A ("close the connection", CID 1): B closes, the session
    // goes on on A.
    let g = a.logout_cid(1, 1).await;
    assert_eq!(g.bhs[2], 0);
    assert!(
        b.closed().await,
        "the connection logged out from the other one closes"
    );
    assert_eq!(a.tur(0).await.status(), 0);
    let g = a.logout_cid(1, 7).await;
    assert_eq!(g.bhs[2], 1, "CID not found");
    let g = a.logout_cid(2, 0).await;
    assert_eq!(
        g.bhs[2], 2,
        "recovery logout at error recovery level 0: not supported"
    );

    // Session reinstatement: the same initiator port logging in with TSIH 0 replaces the
    // session, and the old one's connection closes.
    let mut again = Raw::connect(srv.port).await;
    again.login("Normal", Some(DISK0), &[]).await;
    assert!(
        a.closed().await,
        "the reinstated session's connection closes"
    );
    assert_ne!(again.tsih, 0);
    assert_eq!(again.tur(0).await.status(), 0);
    let rows = oracle(&b).fields(&["iscsi.tsih", "iscsi.cid"]).unwrap();
    assert!(
        rows.iter()
            .any(|r| r[1].split(',').any(|c| c == "0x0001" || c == "1")),
        "tshark reads the joining login's CID: {rows:?}"
    );
    oracle(&a).assert_clean();
}

/// The operational keys of an error recovery level 1 session with data digests, small PDUs
/// and bursts, and writes that wait for R2T.
const ERL1: &[(&str, &str)] = &[
    ("HeaderDigest", "None"),
    ("DataDigest", "CRC32C"),
    ("ErrorRecoveryLevel", "1"),
    ("InitialR2T", "Yes"),
    ("ImmediateData", "No"),
    ("MaxRecvDataSegmentLength", "512"),
    ("MaxBurstLength", "1024"),
];

/// Send `bhs` with `data`, its data digest broken.
async fn send_corrupt(raw: &mut Raw, bhs: [u8; 48], data: &[u8]) {
    let mut bytes = raw.frame(bhs, data);
    let n = bytes.len();
    bytes[n - 1] ^= 0xFF;
    raw.write(&bytes).await;
}

#[tokio::test]
async fn error_recovery_level_1_recovers_lost_data_and_answers_every_snack() {
    let srv = start(policy(POLICY), None).await;
    let mut a = Raw::connect(srv.port).await;
    let r = a.login("Normal", Some(DISK0), ERL1).await;
    assert_eq!(key(&r.text(), "ErrorRecoveryLevel"), Some("1"));

    // A lost Data-Out (data digest error): Reject, then a recovery R2T for just its range.
    let (b, witt) = a.scsi_bhs(0xA0, 0, 1024, &write10(900, 2));
    a.send(b, &[]).await;
    let r2t = a.recv().await;
    assert_eq!((r2t.opcode(), r2t.u32(40), r2t.u32(44)), (0x31, 0, 1024));
    let d0 = a.data_out_bhs(witt, r2t.u32(20), 0, 0, false);
    send_corrupt(&mut a, d0, &[0x41; 512]).await;
    let rej = a.recv().await;
    assert_eq!(
        (rej.opcode(), rej.bhs[2]),
        (0x3f, 0x02),
        "Reject: data digest error"
    );
    let d1 = a.data_out_bhs(witt, r2t.u32(20), 1, 512, true);
    a.send(d1, &[0x42; 512]).await;
    let rec = a.recv().await;
    assert_eq!(rec.opcode(), 0x31, "a recovery R2T: {rec:?}");
    assert_eq!(
        (rec.u32(36), rec.u32(40), rec.u32(44)),
        (1, 0, 512),
        "R2TSN 1, the lost range"
    );
    assert_ne!(rec.u32(20), r2t.u32(20), "a tag of its own");
    let d = a.data_out_bhs(witt, rec.u32(20), 0, 0, true);
    a.send(d, &[0x41; 512]).await;
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, witt, 0));
    let (back, _) = a.read_cmd(0, 1024, &read10(900, 2)).await;
    assert_eq!(back[..512], [0x41; 512], "the recovered range");
    assert_eq!(back[512..], [0x42; 512]);

    // SNACK, on a session without digests so that tshark can frame it too. A read of four
    // PDUs (MaxRecvDataSegmentLength 512, MaxBurstLength 1024): the end of the first burst
    // asks for a DataACK (the A bit, with a tag), the last carries the status.
    let mut a = Raw::connect(srv.port).await;
    a.isid = [0x80, 0, 0, 0, 0, 0x31];
    let mut ops = ERL1.to_vec();
    ops[1] = ("DataDigest", "None");
    a.login("Normal", Some(DISK0), &ops).await;
    let (rd, ritt) = a.scsi_bhs(0xC0, 0, 2048, &read10(0, 4));
    a.send(rd, &[]).await;
    let mut pdus = Vec::new();
    for _ in 0..4 {
        pdus.push(a.recv().await);
    }
    assert!(pdus.iter().all(|p| p.opcode() == 0x25 && p.itt() == ritt));
    assert_eq!(&pdus[0].data[..17], b"hello from netget");
    assert_eq!(pdus[1].data, vec![0; 512]);
    assert_eq!(pdus[1].flags() & 0x40, 0x40, "A bit at the burst's end");
    let ack_tag = pdus[1].u32(20);
    assert_ne!(ack_tag, 0xffff_ffff);
    assert_eq!(pdus[3].flags() & 0x01, 0x01, "status in the last");
    let stat = pdus[3].u32(24);

    // Data SNACK for DataSN 1-2 (acknowledging nothing): exact replicas.
    a.send_snack(0, 0, ritt, 0xffff_ffff, 1, 2, stat).await;
    for want in [&pdus[1], &pdus[2]] {
        let g = a.recv().await;
        assert_eq!(
            (g.opcode(), g.u32(36), g.u32(40)),
            (0x25, want.u32(36), want.u32(40))
        );
        assert_eq!((g.flags(), &g.data), (want.flags(), &want.data));
    }
    // Status SNACK: the status-carrying Data-In again, under its StatSN.
    a.send_snack(1, 0, 0xffff_ffff, 0xffff_ffff, stat, 1, stat)
        .await;
    let g = a.recv().await;
    assert_eq!(
        (g.opcode(), g.u32(24), g.flags() & 0x01, g.u32(36)),
        (0x25, stat, 1, 3)
    );
    // A StatSN never sent, and a SNACK type that does not exist: Protocol Error.
    a.send_snack(1, 0, 0xffff_ffff, 0xffff_ffff, stat + 100, 1, stat)
        .await;
    assert_eq!(a.recv().await.bhs[2], 0x04);
    a.send_snack(9, 0, ritt, 0xffff_ffff, 0, 0, stat).await;
    assert_eq!(a.recv().await.bhs[2], 0x04);
    // DataACK of the first two PDUs (no answer); asking for one of them again is then a
    // Protocol Error.
    a.send_snack(2, 0, 0xffff_ffff, ack_tag, 2, 0, stat).await;
    assert!(a.recv_within(Duration::from_millis(500)).await.is_none());
    a.send_snack(0, 0, ritt, 0xffff_ffff, 1, 1, stat).await;
    let g = a.recv().await;
    assert_eq!((g.opcode(), g.bhs[2]), (0x3f, 0x04), "already acknowledged");
    a.send_snack(2, 0, 0xffff_ffff, 0x0bad_0bad, 2, 0, stat)
        .await;
    assert_eq!(a.recv().await.bhs[2], 0x08, "Invalid DataACK");
    // R-Data SNACK: the unacknowledged data from the DataACK's point, then a SCSI Response
    // carrying the SNACK Tag under the original StatSN (§11.16.3).
    a.send_snack(3, 0, ritt, 0x55, 0, 0, stat).await;
    for want in [2u32, 3] {
        let g = a.recv().await;
        assert_eq!((g.opcode(), g.u32(36)), (0x25, want));
        assert_eq!(g.flags() & 0x01, 0, "no status in the resent data");
    }
    let g = a.recv().await;
    assert_eq!(
        (g.opcode(), g.itt(), g.u32(20), g.u32(24), g.status()),
        (0x21, ritt, 0x55, stat, 0)
    );
    // The retransmission bound: eight for the task (two spent above), then SNACK reject.
    for i in 0..6 {
        a.send_snack(0, 0, ritt, 0xffff_ffff, 3, 1, stat).await;
        assert_eq!(a.recv().await.opcode(), 0x25, "retransmission {i}");
    }
    a.send_snack(0, 0, ritt, 0xffff_ffff, 3, 1, stat).await;
    let g = a.recv().await;
    assert_eq!(
        (g.opcode(), g.bhs[2]),
        (0x3f, 0x03),
        "SNACK reject past the bound"
    );
    // Once the status is acknowledged, nothing of the read is kept.
    a.exp_stat_sn = stat + 1;
    assert_eq!(a.tur(0).await.status(), 0);
    a.send_snack(0, 0, ritt, 0xffff_ffff, 3, 1, a.exp_stat_sn)
        .await;
    assert_eq!(a.recv().await.bhs[2], 0x04);

    // At error recovery level 0 a lost Data-Out ends its write with PROTOCOL SERVICE CRC
    // ERROR once its sequence is over, and SNACK is refused.
    let mut z = Raw::connect(srv.port).await;
    z.isid = [0x80, 0, 0, 0, 0, 0x30];
    let mut ops = ERL1.to_vec();
    ops[2] = ("ErrorRecoveryLevel", "0");
    let r = z.login("Normal", Some(DISK0), &ops).await;
    assert_eq!(key(&r.text(), "ErrorRecoveryLevel"), Some("0"));
    let (zitt, zr2t) = write_waiting(&mut z, 0, 950).await;
    let d = z.data_out_bhs(zitt, zr2t.u32(20), 0, 0, true);
    send_corrupt(&mut z, d, &[1u8; 512]).await;
    assert_eq!(z.recv().await.bhs[2], 0x02);
    let g = z.recv().await;
    assert_eq!((g.itt(), sense_of(&g)), (zitt, Some((0x0B, 0x47, 0x05))));
    z.send_snack(1, 0, 0xffff_ffff, 0xffff_ffff, 0, 0, z.exp_stat_sn)
        .await;
    assert_eq!(z.recv().await.bhs[2], 0x04, "no SNACK at level 0");

    let rows = oracle(&a).fields(&["iscsi.snack.type"]).unwrap();
    let types: Vec<&str> = rows
        .iter()
        .flat_map(|r| r[0].split(','))
        .filter(|t| !t.is_empty())
        .collect();
    assert!(types.len() >= 10, "tshark reads the SNACKs: {rows:?}");
    oracle(&a).assert_clean();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_recovery_level_2_reassigns_a_failed_connections_tasks() {
    let srv = start(policy(POLICY), None).await;
    let ops: &[(&str, &str)] = &[
        ("ErrorRecoveryLevel", "2"),
        ("MaxConnections", "2"),
        ("InitialR2T", "Yes"),
        ("ImmediateData", "No"),
        ("MaxRecvDataSegmentLength", "512"),
        ("DefaultTime2Wait", "0"),
        ("DefaultTime2Retain", "1"),
    ];
    let mut a = Raw::connect(srv.port).await;
    let r = a.login("Normal", Some(DISK0), ops).await;
    assert_eq!(key(&r.text(), "ErrorRecoveryLevel"), Some("2"));
    assert_eq!(key(&r.text(), "DefaultTime2Wait"), Some("2"), "the maximum");
    assert_eq!(
        key(&r.text(), "DefaultTime2Retain"),
        Some("1"),
        "the minimum"
    );
    // A read of four Data-In PDUs; the initiator takes one, and the connection dies.
    let (rd, ritt) = a.scsi_bhs(0xC0, 0, 2048, &read10(0, 4));
    a.send(rd, &[]).await;
    let first = a.recv().await;
    assert_eq!((first.opcode(), first.u32(36)), (0x25, 0));
    let mut cmd_sn = a.cmd_sn;
    let mut b = Raw::join(srv.port, &a, 1).await;
    drop(a);
    b.login(
        "Normal",
        Some(DISK0),
        &[("MaxRecvDataSegmentLength", "512")],
    )
    .await;
    b.cmd_sn = cmd_sn;
    // Before the recovery logout the task is still allegiant to the failed connection.
    let t = b.send_tmf(8, 0, ritt, 0, 1).await;
    let g = b.recv().await;
    assert_eq!((g.itt(), g.bhs[2]), (t, 3), "task still allegiant");
    let g = b.logout_cid(2, 0).await;
    assert_eq!(g.bhs[2], 0, "the failed connection is removed for recovery");
    assert_eq!(
        (
            u16::from_be_bytes([g.bhs[40], g.bhs[41]]),
            u16::from_be_bytes([g.bhs[42], g.bhs[43]])
        ),
        (2, 1),
        "Time2Wait and Time2Retain"
    );
    // TASK REASSIGN with ExpDataSN 1: the response, then DataSN 1-3 and the status.
    let t = b.send_tmf(8, 0, ritt, 0, 1).await;
    let g = b.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.bhs[2]), (0x22, t, 0));
    let mut data = first.data.clone();
    for want in 1..4u32 {
        let g = b.recv().await;
        assert_eq!((g.opcode(), g.itt(), g.u32(36)), (0x25, ritt, want));
        data.extend(&g.data);
    }
    let g = b.recv().await;
    assert_eq!(
        (g.opcode(), g.itt(), g.status(), g.u32(36)),
        (0x21, ritt, 0, 4)
    );
    assert_eq!(&data[..17], b"hello from netget");
    assert_eq!(data.len(), 2048);

    // A write that lost its connection with an R2T outstanding continues with a new R2T.
    let mut c = Raw::join(srv.port, &b, 2).await;
    c.login("Normal", Some(DISK0), &[]).await;
    c.cmd_sn = cmd_sn;
    let (witt, _) = write_waiting(&mut c, 0, 960).await;
    cmd_sn = c.cmd_sn;
    drop(c);
    b.cmd_sn = cmd_sn;
    assert_eq!(b.logout_cid(2, 2).await.bhs[2], 0);
    let t = b.send_tmf(8, 0, witt, 0, 0).await;
    let g = b.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.bhs[2]), (0x22, t, 0));
    let r2t = b.recv().await;
    assert_eq!(
        (r2t.opcode(), r2t.itt(), r2t.u32(40), r2t.u32(44)),
        (0x31, witt, 0, 512)
    );
    let d = b.data_out_bhs(witt, r2t.u32(20), 0, 0, true);
    b.send(d, &[0x6E; 512]).await;
    let g = b.recv().await;
    assert_eq!((g.opcode(), g.itt(), g.status()), (0x21, witt, 0));
    let (back, _) = b.read_cmd(0, 512, &read10(960, 1)).await;
    assert!(back.iter().all(|x| *x == 0x6E));

    // A task nobody reassigns ends when Time2Wait + Time2Retain run out, and the session is
    // told: SOME COMMANDS CLEARED BY ISCSI PROTOCOL EVENT.
    let mut e = Raw::join(srv.port, &b, 3).await;
    e.login("Normal", Some(DISK0), &[]).await;
    e.cmd_sn = b.cmd_sn;
    let (eitt, _) = write_waiting(&mut e, 0, 970).await;
    b.cmd_sn = e.cmd_sn;
    drop(e);
    assert_eq!(b.logout_cid(2, 3).await.bhs[2], 0);
    let mut cleared = None;
    for _ in 0..100 {
        let g = b.tur(0).await;
        if g.status() != 0 {
            cleared = sense_of(&g);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        cleared,
        Some((0x06, 0x47, 0x7F)),
        "the expired task is reported"
    );
    let t = b.send_tmf(8, 0, eitt, 0, 0).await;
    let g = b.recv().await;
    assert_eq!((g.itt(), g.bhs[2]), (t, 1), "task does not exist");

    // Connection reinstatement: a new connection with B's CID replaces B.
    let mut f = Raw::join(srv.port, &b, 1).await;
    f.login("Normal", Some(DISK0), &[]).await;
    assert!(b.closed().await, "the reinstated connection closes");
    f.cmd_sn = b.cmd_sn;
    assert_eq!(f.tur(0).await.status(), 0);
    oracle(&f).assert_clean();
}
