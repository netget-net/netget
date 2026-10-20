//! NetGet's iSCSI target driven by a raw initiator written from RFC 7143's offsets: discovery,
//! login and negotiation, CHAP, the SCSI block commands, R2T, digests, task management, every
//! bound and sequence check, and the fail-closed paths. No LLM: a python policy plays the model
//! (see `support::POLICY`). tshark's iscsi and scsi dissectors read the bytes both ways. The
//! independent initiators are in `real_client_test.rs`.
use super::support::*;
use crate::helpers::pcap_oracle::PcapOracle;
use serde_json::json;
use std::time::Duration;

fn oracle(raw: &Raw) -> PcapOracle {
    PcapOracle::tcp("iscsi")
        .to_server(&raw.sent)
        .from_server(&raw.received)
}

#[tokio::test]
async fn discovery_lists_the_models_targets_and_tshark_reads_the_session() {
    let srv = start(policy(POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    raw.login(
        "Discovery",
        None,
        &[
            ("HeaderDigest", "None"),
            ("DataDigest", "None"),
            ("MaxRecvDataSegmentLength", "8192"),
        ],
    )
    .await;
    let answer = raw.text_request(&[("SendTargets", "All")]).await;
    let names: Vec<&str> = answer
        .iter()
        .filter(|(k, _)| k == "TargetName")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(names, [DISK0, "iqn.2026-10.net.netget:backup"]);
    let addresses: Vec<&str> = answer
        .iter()
        .filter(|(k, _)| k == "TargetAddress")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        addresses,
        [
            format!("127.0.0.1:{},1", srv.port).as_str(),
            "192.0.2.7:3260,1"
        ],
        "a target without addresses is at the portal the initiator used"
    );
    // A discovery session has no LUNs: a SCSI command is rejected.
    let (b, _) = raw.scsi_bhs(0x80, 0, 0, &[0u8; 6]);
    raw.send(b, &[]).await;
    let g = raw.recv().await;
    assert_eq!(
        (g.opcode(), g.bhs[2]),
        (0x3f, 0x05),
        "Reject: command not supported"
    );
    let g = raw.logout().await;
    assert_eq!(g.bhs[2], 0, "logout succeeded");
    assert!(raw.closed().await, "the target closes after logout");
    assert!(events(&srv.state, srv.id, "iscsi_login").await.is_empty());
    assert_eq!(events(&srv.state, srv.id, "iscsi_discovery").await.len(), 1);

    oracle(&raw).also_named("iscsi").assert_clean();
    // Wireshark 4.6 gives the well-known keys fields of their own (iscsi.login.*); 4.2, which
    // Ubuntu 24.04 ships, has only iscsi.keyvalue, one "Key=Value" string per pair, and refuses
    // the 4.6 names outright. Read whichever this tshark has.
    let (send_targets, target_names) =
        match oracle(&raw).fields(&["iscsi.login.send_targets", "iscsi.login.target_name"]) {
            Ok(rows) => (
                rows.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
                rows.iter().map(|r| r[1].clone()).collect::<Vec<_>>(),
            ),
            Err(e) if e.contains("aren't valid") => {
                let rows = oracle(&raw).fields(&["iscsi.keyvalue"]).unwrap();
                let pairs: Vec<String> = rows
                    .iter()
                    .flat_map(|r| r[0].split(',').map(str::to_string).collect::<Vec<_>>())
                    .collect();
                let of = |key: &str| {
                    pairs
                        .iter()
                        .filter_map(|p| p.strip_prefix(key).map(str::to_string))
                        .collect::<Vec<_>>()
                };
                (of("SendTargets="), vec![of("TargetName=").join(",")])
            }
            Err(e) => panic!("{e}"),
        };
    assert!(
        send_targets.iter().any(|v| v == "All"),
        "tshark reads SendTargets=All: {send_targets:?}"
    );
    assert!(
        target_names
            .iter()
            .any(|v| v == "iqn.2026-10.net.netget:disk0,iqn.2026-10.net.netget:backup"),
        "tshark reads both TargetName keys of the answer: {target_names:?}"
    );
}

/// Operational keys that make the target send unsolicited data, small PDUs and so on.
const OPS: &[(&str, &str)] = &[
    ("HeaderDigest", "None"),
    ("DataDigest", "None"),
    ("ErrorRecoveryLevel", "0"),
    ("InitialR2T", "No"),
    ("ImmediateData", "Yes"),
    ("MaxBurstLength", "262144"),
    ("FirstBurstLength", "65536"),
    ("MaxRecvDataSegmentLength", "1024"),
    ("MaxOutstandingR2T", "1"),
    ("DataPDUInOrder", "Yes"),
    ("DataSequenceInOrder", "Yes"),
];

#[tokio::test]
async fn a_normal_session_serves_the_described_luns() {
    // InitialR2T=No on this target, so the initiator's unsolicited burst is allowed.
    let srv = start(policy(POLICY), Some(json!({"initial_r2t": false}))).await;
    let mut raw = Raw::connect(srv.port).await;
    let r = raw.login("Normal", Some(DISK0), OPS).await;
    let t = r.text();
    assert_eq!(key(&t, "InitialR2T"), Some("No"));
    assert_eq!(key(&t, "ImmediateData"), Some("Yes"));
    assert_eq!(
        key(&t, "MaxRecvDataSegmentLength"),
        Some("262144"),
        "the target declares its own"
    );
    assert_eq!(key(&t, "TargetAlias"), Some("netget disk"));
    assert_ne!(u16::from_be_bytes([r.bhs[14], r.bhs[15]]), 0, "a TSIH");
    let login = events(&srv.state, srv.id, "iscsi_login").await;
    assert_eq!(login.len(), 1);
    assert_eq!(login[0]["target_name"], DISK0);
    assert_eq!(login[0]["initiator_name"], INITIATOR);

    // REPORT LUNS: 0 and 1.
    let mut cdb = vec![0xA0, 0, 0, 0, 0, 0];
    cdb.extend(4096u32.to_be_bytes());
    cdb.extend([0, 0]);
    let (d, st) = raw.read_cmd(0, 4096, &cdb).await;
    assert_eq!(st.status(), 0);
    assert_eq!(be32(&d, 0), 16, "two LUNs");
    assert_eq!(&d[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&d[16..24], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_ne!(st.flags() & 0x02, 0, "underflow: 24 of 4096 bytes");
    assert_eq!(st.u32(44), 4096 - 24);

    // Standard INQUIRY and the three VPD pages.
    let (d, st) = raw.read_cmd(0, 96, &[0x12, 0, 0, 0, 96, 0]).await;
    assert_eq!(st.status(), 0);
    assert_eq!(d[0], 0, "a direct-access block device");
    assert_eq!(&d[8..16], b"NETGET  ");
    assert_eq!(&d[16..32], b"BOOT-DISK       ");
    let (d, _) = raw.read_cmd(0, 255, &[0x12, 1, 0x00, 0, 255, 0]).await;
    assert_eq!(&d[4..], &[0x00, 0x80, 0x83, 0xB0, 0xB1]);
    let (d, _) = raw.read_cmd(0, 255, &[0x12, 1, 0x80, 0, 255, 0]).await;
    assert_eq!(&d[4..], b"SER0001");
    let (d, _) = raw.read_cmd(0, 255, &[0x12, 1, 0x83, 0, 255, 0]).await;
    assert_eq!(d[1], 0x83);
    assert!(
        d.windows(DISK0.len()).any(|w| w == DISK0.as_bytes()),
        "the SCSI name string designator names the target"
    );
    let (_, st) = raw.read_cmd(0, 255, &[0x12, 1, 0xB9, 0, 255, 0]).await;
    assert_eq!(st.status(), 2);
    assert_eq!(st.sense(), Some((5, 0x24, 0)), "an unsupported page");

    // INQUIRY on a LUN that does not exist: qualifier 3. Anything else: not supported.
    let (d, _) = raw.read_cmd(7, 36, &[0x12, 0, 0, 0, 36, 0]).await;
    assert_eq!(d[0], 0x7F);
    let g = raw.tur(7).await;
    assert_eq!((g.status(), g.sense()), (2, Some((5, 0x25, 0))));

    // READ CAPACITY: 2048 blocks of 512 on LUN 0, 512 blocks of 4096 on LUN 1.
    let (d, _) = raw.read_cmd(0, 8, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]).await;
    assert_eq!((be32(&d, 0), be32(&d, 4)), (2047, 512));
    let mut rc16 = vec![0x9E, 0x10];
    rc16.extend([0u8; 8]);
    rc16.extend(32u32.to_be_bytes());
    rc16.extend([0, 0]);
    let (d, _) = raw.read_cmd(1, 32, &rc16).await;
    assert_eq!(u64::from_be_bytes(d[..8].try_into().unwrap()), 511);
    assert_eq!(be32(&d, 8), 4096);

    // READ: the text, the fill, zeroes; a 4 KiB read comes back in 1 KiB Data-In PDUs.
    let (d, st) = raw.read_cmd(0, 512, &read10(0, 1)).await;
    assert_eq!(st.status(), 0);
    assert_eq!(
        st.flags() & 0x81,
        0x81,
        "status collapsed into the last Data-In"
    );
    assert_eq!(&d[..17], b"hello from netget");
    assert!(d[17..].iter().all(|b| *b == 0));
    let (d, _) = raw.read_cmd(0, 512, &read10(8, 1)).await;
    assert!(d.iter().all(|b| *b == 0xAB));
    let (b, itt) = raw.scsi_bhs(0xC0, 0, 4096, &read10(8, 8));
    raw.send(b, &[]).await;
    let mut pdus = Vec::new();
    loop {
        let g = raw.recv().await;
        assert_eq!(g.itt(), itt);
        assert!(
            g.data.len() <= 1024,
            "within the initiator's MaxRecvDataSegmentLength"
        );
        let last = g.flags() & 0x01 != 0;
        pdus.push(g);
        if last {
            break;
        }
    }
    assert_eq!(pdus.len(), 4);
    let (d, _) = raw.read_cmd(1, 4096, &read10(0, 1)).await;
    assert_eq!(&d[..4], &[0xde, 0xad, 0xbe, 0xef]);

    // A medium error names its first failing block; past the end is out of range.
    let (_, st) = raw.read_cmd(0, 8192, &read10(1020, 16)).await;
    assert_eq!(st.sense(), Some((3, 0x11, 0)));
    assert_eq!(
        be32(&st.data[2..], 3),
        1024,
        "INFORMATION: the first bad LBA"
    );
    let (_, st) = raw.read_cmd(0, 1024, &read10(2047, 2)).await;
    assert_eq!(st.sense(), Some((5, 0x21, 0)));

    // WRITE with immediate data, read back; LUN 1 refuses as write-protected.
    let mut block = vec![0u8; 512];
    block[..10].copy_from_slice(b"written ok");
    let (b, _) = raw.scsi_bhs(0xA0, 0, 512, &write10(100, 1));
    raw.send(b, &block).await;
    let g = raw.recv().await;
    assert_eq!((g.opcode(), g.status()), (0x21, 0));
    let (d, _) = raw.read_cmd(0, 512, &read10(100, 1)).await;
    assert_eq!(d, block, "the session reads its own write");
    let (b, _) = raw.scsi_bhs(0xA0, 1, 4096, &write10(0, 1));
    raw.send(b, &vec![1u8; 4096]).await;
    let g = raw.recv().await;
    assert_eq!(
        g.sense(),
        Some((7, 0x27, 0)),
        "DATA PROTECT / WRITE PROTECTED"
    );

    // Unsolicited Data-Out after the immediate data (InitialR2T=No): 2 KiB in two PDUs.
    let data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let (b, itt) = raw.scsi_bhs(0x20, 0, 2048, &write10(200, 4)); // F clear: Data-Out follows
    raw.send(b, &data[..1024]).await;
    let mut d = [0u8; 48];
    d[0] = 0x05;
    d[1] = 0x80;
    d[16..20].copy_from_slice(&itt.to_be_bytes());
    d[20..24].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    d[40..44].copy_from_slice(&1024u32.to_be_bytes());
    raw.send(d, &data[1024..]).await;
    let g = raw.recv().await;
    assert_eq!((g.opcode(), g.status()), (0x21, 0), "{g:?}");
    let (back, _) = raw.read_cmd(0, 2048, &read10(200, 4)).await;
    assert_eq!(back, data);

    // MODE SENSE(6): write-protect bit for the read-only LUN only.
    let (d, _) = raw.read_cmd(0, 255, &[0x1A, 0, 0x3F, 0, 255, 0]).await;
    assert_eq!(d[2] & 0x80, 0);
    let (d, _) = raw.read_cmd(1, 255, &[0x1A, 0, 0x3F, 0, 255, 0]).await;
    assert_eq!(d[2] & 0x80, 0x80);
    assert_eq!(d[3], 8, "a block descriptor");

    // NOP-Out ping comes back with its data.
    let mut nop = [0u8; 48];
    nop[0] = 0x40;
    nop[1] = 0x80;
    let itt = raw.next_itt();
    nop[16..20].copy_from_slice(&itt.to_be_bytes());
    nop[20..24].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    nop[24..28].copy_from_slice(&raw.cmd_sn.to_be_bytes());
    raw.send(nop, b"ping").await;
    let g = raw.recv().await;
    assert_eq!(
        (g.opcode(), g.itt(), g.data.as_slice()),
        (0x20, itt, &b"ping"[..])
    );

    raw.logout().await;
    assert_eq!(
        events(&srv.state, srv.id, "iscsi_login").await.len(),
        1,
        "every command was served from the description, with no further model call"
    );
    oracle(&raw).also_named("scsi").assert_clean();
    let fields = oracle(&raw).fields(&["scsi.inquiry.product_id"]).unwrap();
    assert!(format!("{fields:?}").contains("BOOT-DISK"), "{fields:?}");
}

#[tokio::test]
async fn r2t_solicits_write_data_in_bursts() {
    let srv = start(policy(POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    raw.login(
        "Normal",
        Some(DISK0),
        &[
            ("InitialR2T", "Yes"),
            ("ImmediateData", "No"),
            ("MaxBurstLength", "1024"),
            ("FirstBurstLength", "512"),
            ("MaxRecvDataSegmentLength", "8192"),
        ],
    )
    .await;
    let data: Vec<u8> = (0..2560u32).map(|i| (i * 7 % 256) as u8).collect();
    let (b, itt) = raw.scsi_bhs(0xA0, 0, 2560, &write10(300, 5));
    raw.send(b, &[]).await;
    let mut r2ts = Vec::new();
    loop {
        let g = raw.recv().await;
        assert_eq!(g.itt(), itt);
        if g.opcode() == 0x21 {
            assert_eq!(g.status(), 0, "{g:?}");
            break;
        }
        assert_eq!(g.opcode(), 0x31, "an R2T: {g:?}");
        let (ttt, sn, offset, len) = (g.u32(20), g.u32(36), g.u32(40), g.u32(44));
        assert_eq!(sn as usize, r2ts.len(), "R2TSN in order");
        assert!(len <= 1024, "within MaxBurstLength");
        r2ts.push((offset, len));
        // Answer in two Data-Out PDUs to exercise DataSN.
        let half = len / 2;
        for (i, (from, to)) in [(offset, offset + half), (offset + half, offset + len)]
            .into_iter()
            .enumerate()
        {
            let mut d = [0u8; 48];
            d[0] = 0x05;
            d[1] = if i == 1 { 0x80 } else { 0 };
            d[16..20].copy_from_slice(&itt.to_be_bytes());
            d[20..24].copy_from_slice(&ttt.to_be_bytes());
            d[36..40].copy_from_slice(&(i as u32).to_be_bytes());
            d[40..44].copy_from_slice(&from.to_be_bytes());
            raw.send(d, &data[from as usize..to as usize]).await;
        }
    }
    assert_eq!(r2ts, [(0, 1024), (1024, 1024), (2048, 512)]);
    let (back, _) = raw.read_cmd(0, 2560, &read10(300, 5)).await;
    assert_eq!(back, data);

    // A Data-Out whose offset skips ahead, and one whose DataSN is wrong, are protocol errors:
    // their task ends with CHECK CONDITION, nothing written, and the session goes on (no
    // Reject and no close: libiscsi's iSCSIDataSnInvalid hangs on Linux after either).
    for (lba, data_sn, offset) in [(400u32, 0u32, 256u32), (401, 7, 0)] {
        let (b, itt) = raw.scsi_bhs(0xA0, 0, 512, &write10(lba, 1));
        raw.send(b, &[]).await;
        let g = raw.recv().await;
        assert_eq!(g.opcode(), 0x31);
        let mut d = [0u8; 48];
        d[0] = 0x05;
        d[1] = 0x80;
        d[16..20].copy_from_slice(&itt.to_be_bytes());
        d[20..24].copy_from_slice(&g.u32(20).to_be_bytes());
        d[36..40].copy_from_slice(&data_sn.to_be_bytes());
        d[40..44].copy_from_slice(&offset.to_be_bytes());
        raw.send(d, &[0x5Au8; 512][..512 - offset as usize]).await;
        let g = raw.recv().await;
        assert_eq!((g.opcode(), g.itt()), (0x21, itt), "the task's own answer");
        assert_eq!(g.status(), 2);
        assert_eq!(g.sense(), Some((0x0B, 0x4B, 0x00)), "DATA PHASE ERROR");
    }
    let (back, _) = raw.read_cmd(0, 1024, &read10(400, 2)).await;
    assert!(back.iter().all(|b| *b == 0), "nothing was written");
    assert_eq!(raw.tur(0).await.status(), 0, "the session goes on");
    oracle(&raw).assert_clean();
}

#[tokio::test]
async fn chap_is_checked_in_rust_before_the_model_is_asked() {
    let params = json!({
        "chap_accounts": [{"name": "alice", "secret": "wonderland12"}],
        "target_chap_name": "netget-target",
        "target_chap_secret": "targetsecret1",
    });
    let srv = start(policy(POLICY), Some(params)).await;

    async fn chap(port: u16, name: &str, secret: &str, mutual: bool) -> (Raw, Got) {
        let mut raw = Raw::connect(port).await;
        let r = raw
            .login_step(
                0,
                None,
                &[
                    ("InitiatorName", INITIATOR),
                    ("SessionType", "Normal"),
                    ("TargetName", DISK0),
                    ("AuthMethod", "CHAP,None"),
                ],
            )
            .await;
        assert_eq!(key(&r.text(), "AuthMethod"), Some("CHAP"));
        assert_eq!(key(&r.text(), "TargetPortalGroupTag"), Some("1"));
        let r = raw.login_step(0, None, &[("CHAP_A", "5")]).await;
        let t = r.text();
        assert_eq!(key(&t, "CHAP_A"), Some("5"));
        let id: u8 = key(&t, "CHAP_I").unwrap().parse().unwrap();
        let challenge = hex::decode(key(&t, "CHAP_C").unwrap().trim_start_matches("0x")).unwrap();
        // MD5(id || secret || challenge), computed here with the md-5 crate's own API.
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update([id]);
        h.update(secret.as_bytes());
        h.update(&challenge);
        let response = format!("0x{}", hex::encode(h.finalize()));
        let mut keys = vec![("CHAP_N", name.to_string()), ("CHAP_R", response)];
        if mutual {
            keys.push(("CHAP_I", "77".into()));
            keys.push(("CHAP_C", "0x0102030405060708090a0b0c0d0e0f10".into()));
        }
        let keys: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = raw.login_step(0, Some(1), &keys).await;
        (raw, r)
    }

    let (mut raw, r) = chap(srv.port, "alice", "not-the-secret", false).await;
    assert_eq!(r.login_status(), 0x0201, "authentication failure");
    assert!(raw.closed().await);
    let (mut raw, r) = chap(srv.port, "mallory", "wonderland12", false).await;
    assert_eq!(r.login_status(), 0x0201, "a secret under the wrong name");
    assert!(raw.closed().await);
    assert!(
        events(&srv.state, srv.id, "iscsi_login").await.is_empty(),
        "the model is never asked about an initiator that failed CHAP"
    );

    let (mut raw, r) = chap(srv.port, "alice", "wonderland12", true).await;
    assert_eq!(r.login_status(), 0, "{:?}", r.text());
    let t = r.text();
    assert_eq!(key(&t, "CHAP_N"), Some("netget-target"));
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update([77u8]);
    h.update(b"targetsecret1");
    h.update(hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap());
    assert_eq!(
        key(&t, "CHAP_R"),
        Some(format!("0x{}", hex::encode(h.finalize())).as_str()),
        "mutual CHAP: the target proves its secret"
    );
    raw.finish_operational(&[("MaxRecvDataSegmentLength", "8192")])
        .await;
    let g = raw.tur(0).await;
    assert_eq!(g.status(), 0);
    let login = events(&srv.state, srv.id, "iscsi_login").await;
    assert_eq!(login.len(), 1);
    assert_eq!(login[0]["authenticated_user"], "alice", "{}", login[0]);
    let all = serde_json::to_string(&login).unwrap();
    assert!(
        !all.contains("wonderland12") && !all.contains("targetsecret1"),
        "no secret reaches the model"
    );

    // No CHAP offered while it is required: refused.
    let mut raw = Raw::connect(srv.port).await;
    let r = raw
        .login_step(
            0,
            Some(1),
            &[
                ("InitiatorName", INITIATOR),
                ("TargetName", DISK0),
                ("AuthMethod", "None"),
            ],
        )
        .await;
    assert_eq!(r.login_status(), 0x0201);
    oracle(&raw).assert_clean();
}

#[tokio::test]
async fn logins_fail_closed_and_expose_nothing_the_model_did_not_describe() {
    // Only discovery has a handler: a login falls through to the unreachable model.
    let handlers = Some(vec![
        json!({"event_pattern":"iscsi_discovery","handler":{"type":"script","language":"python","code":POLICY}}),
    ]);
    let srv = start(handlers, None).await;
    let mut raw = Raw::connect(srv.port).await;
    let r = raw
        .login_step(
            0,
            Some(1),
            &[
                ("InitiatorName", INITIATOR),
                ("TargetName", DISK0),
                ("AuthMethod", "None"),
            ],
        )
        .await;
    assert_eq!(
        r.login_status(),
        0x0300,
        "target error when the backend fails"
    );
    assert!(raw.closed().await, "no session, so no LUN");

    let srv = start(policy(POLICY), None).await;
    for (target, initiator, status) in [
        ("iqn.2026-10.net.netget:silent", INITIATOR, 0x0300u16),
        ("iqn.2026-10.net.netget:invalid", INITIATOR, 0x0300),
        ("iqn.2026-10.net.netget:nothing", INITIATOR, 0x0203),
        (DISK0, "iqn.2026-10.org.example:denied", 0x0202),
    ] {
        let mut raw = Raw::connect(srv.port).await;
        let r = raw
            .login_step(
                0,
                Some(1),
                &[
                    ("InitiatorName", initiator),
                    ("TargetName", target),
                    ("AuthMethod", "None"),
                ],
            )
            .await;
        assert_eq!(r.login_status(), status, "{target} {initiator}");
        assert!(raw.closed().await);
    }
}

#[tokio::test]
async fn bounds_refuse_before_anything_is_buffered_or_asked() {
    let srv = start(policy(POLICY), None).await;
    // A login data segment over 8 KiB: closed unread.
    let mut raw = Raw::connect(srv.port).await;
    let mut b = raw.login_bhs(0, Some(1), false);
    b[5..8].copy_from_slice(&[0x00, 0x20, 0x01]); // 8193 bytes declared
    raw.write(&b).await;
    assert!(raw.closed().await);
    // 129 keys in one login.
    let mut raw = Raw::connect(srv.port).await;
    let many: Vec<(String, String)> = (0..129)
        .map(|i| (format!("X-k{i}"), "v".to_string()))
        .collect();
    let mut pairs: Vec<(&str, &str)> = vec![("InitiatorName", INITIATOR), ("TargetName", DISK0)];
    pairs.extend(many.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let r = raw.login_step(0, Some(1), &pairs).await;
    assert_eq!(r.login_status(), 0x0200);
    // A key sent twice.
    let mut raw = Raw::connect(srv.port).await;
    let r = raw
        .login_step(
            0,
            Some(1),
            &[("InitiatorName", INITIATOR), ("InitiatorName", INITIATOR)],
        )
        .await;
    assert_eq!(r.login_status(), 0x0200);
    // A version this target does not speak.
    let mut raw = Raw::connect(srv.port).await;
    let mut b = raw.login_bhs(0, Some(1), false);
    b[2] = 2;
    b[3] = 1;
    raw.send(b, &text(&[("InitiatorName", INITIATOR)])).await;
    assert_eq!(raw.recv().await.login_status(), 0x0205);
    assert!(events(&srv.state, srv.id, "iscsi_login").await.is_empty());

    // Full feature phase: a data segment over the target's MaxRecvDataSegmentLength (256 KiB).
    let mut raw = Raw::connect(srv.port).await;
    raw.login(
        "Normal",
        Some(DISK0),
        &[("MaxRecvDataSegmentLength", "8192")],
    )
    .await;
    let (mut b, _) = raw.scsi_bhs(0xA0, 0, 512, &write10(0, 1));
    b[5..8].copy_from_slice(&[0x04, 0x00, 0x01]);
    raw.write(&b).await;
    assert!(
        raw.closed().await,
        "an oversize data segment ends the connection unread"
    );

    // Immediate data beyond FirstBurstLength.
    let mut raw = Raw::connect(srv.port).await;
    raw.login(
        "Normal",
        Some(DISK0),
        &[("FirstBurstLength", "512"), ("MaxBurstLength", "1024")],
    )
    .await;
    let (b, _) = raw.scsi_bhs(0xA0, 0, 1024, &write10(0, 2));
    raw.send(b, &[0u8; 1024]).await;
    let g = raw.recv().await;
    assert_eq!((g.opcode(), g.bhs[2]), (0x3f, 0x04));
}

#[tokio::test]
async fn commands_out_of_cmdsn_order_are_dropped() {
    let srv = start(policy(POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    let r = raw.login("Normal", Some(DISK0), &[]).await;
    let exp = r.u32(28);
    let max = r.u32(32);
    assert_eq!(max.wrapping_sub(exp), 31, "a 32-command window");
    raw.cmd_sn = exp + 5;
    let (b, _) = raw.scsi_bhs(0x80, 0, 0, &[0u8; 6]);
    raw.send(b, &[]).await;
    assert!(
        raw.recv_within(Duration::from_millis(1500)).await.is_none(),
        "a command ahead of ExpCmdSN is not executed"
    );
    raw.cmd_sn = exp;
    let g = raw.tur(0).await;
    assert_eq!((g.opcode(), g.status()), (0x21, 0));
    assert_eq!(
        g.u32(28),
        exp + 1,
        "ExpCmdSN advanced past the in-order command only"
    );
    // A replay of the command just executed is dropped too.
    raw.cmd_sn = exp;
    let (b, _) = raw.scsi_bhs(0x80, 0, 0, &[0u8; 6]);
    raw.send(b, &[]).await;
    assert!(raw.recv_within(Duration::from_millis(1500)).await.is_none());
}

#[tokio::test]
async fn crc32c_digests_are_negotiated_and_checked() {
    let srv = start(policy(POLICY), Some(json!({"digests": "crc32c"}))).await;
    let mut raw = Raw::connect(srv.port).await;
    let r = raw
        .login(
            "Normal",
            Some(DISK0),
            &[
                ("HeaderDigest", "CRC32C,None"),
                ("DataDigest", "CRC32C,None"),
            ],
        )
        .await;
    assert_eq!(key(&r.text(), "HeaderDigest"), Some("CRC32C"));
    assert!(raw.header_digest && raw.data_digest);
    // The target's digests are checked by Raw::recv on every PDU.
    let (d, _) = raw.read_cmd(0, 512, &read10(0, 1)).await;
    assert_eq!(&d[..5], b"hello");
    // A wrong data digest: Reject (data digest error), and the session goes on.
    let mut nop = [0u8; 48];
    nop[0] = 0x40;
    nop[1] = 0x80;
    nop[16..20].copy_from_slice(&7u32.to_be_bytes());
    nop[20..24].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    nop[24..28].copy_from_slice(&raw.cmd_sn.to_be_bytes());
    let mut bytes = raw.frame(nop, b"ping");
    let n = bytes.len();
    bytes[n - 1] ^= 0xFF;
    raw.write(&bytes).await;
    let g = raw.recv().await;
    assert_eq!((g.opcode(), g.bhs[2]), (0x3f, 0x02));
    assert_eq!(raw.tur(0).await.status(), 0);
    // A wrong header digest: the stream cannot be trusted, so the connection ends.
    let mut bytes = raw.frame(nop, b"ping");
    bytes[49] ^= 0xFF;
    raw.write(&bytes).await;
    assert!(raw.closed().await);

    // A target configured for CRC32C only refuses an initiator that offers only None.
    let mut raw = Raw::connect(srv.port).await;
    raw.login_step(
        0,
        Some(1),
        &[
            ("InitiatorName", INITIATOR),
            ("TargetName", DISK0),
            ("AuthMethod", "None"),
        ],
    )
    .await;
    let r = raw
        .login_step(1, Some(3), &[("HeaderDigest", "None")])
        .await;
    assert_eq!(key(&r.text(), "HeaderDigest"), Some("Reject"));
}

#[tokio::test]
async fn abort_task_ends_a_write_waiting_for_its_data() {
    let srv = start(policy(POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    raw.login(
        "Normal",
        Some(DISK0),
        &[("InitialR2T", "Yes"), ("ImmediateData", "No")],
    )
    .await;
    let (b, itt) = raw.scsi_bhs(0xA0, 0, 512, &write10(500, 1));
    raw.send(b, &[]).await;
    let r2t = raw.recv().await;
    assert_eq!(r2t.opcode(), 0x31);
    let ref_cmd_sn = raw.cmd_sn - 1;
    let mut tmf = [0u8; 48];
    tmf[0] = 0x42; // I + Task Management
    tmf[1] = 0x81; // ABORT TASK
    let tmf_itt = raw.next_itt();
    tmf[16..20].copy_from_slice(&tmf_itt.to_be_bytes());
    tmf[20..24].copy_from_slice(&itt.to_be_bytes());
    tmf[24..28].copy_from_slice(&raw.cmd_sn.to_be_bytes());
    tmf[32..36].copy_from_slice(&ref_cmd_sn.to_be_bytes());
    raw.send(tmf, &[]).await;
    let g = raw.recv().await;
    assert_eq!(
        (g.opcode(), g.itt(), g.bhs[2]),
        (0x22, tmf_itt, 0),
        "function complete"
    );
    // The aborted task's data is ignored; the session goes on.
    let mut d = [0u8; 48];
    d[0] = 0x05;
    d[1] = 0x80;
    d[16..20].copy_from_slice(&itt.to_be_bytes());
    d[20..24].copy_from_slice(&r2t.u32(20).to_be_bytes());
    raw.send(d, &[9u8; 512]).await;
    assert_eq!(raw.tur(0).await.status(), 0);
    let (back, _) = raw.read_cmd(0, 512, &read10(500, 1)).await;
    assert!(
        back.iter().all(|b| *b == 0),
        "the aborted write was not applied"
    );
    // ABORT TASK for a task that never existed.
    let mut tmf = [0u8; 48];
    tmf[0] = 0x42;
    tmf[1] = 0x81;
    tmf[16..20].copy_from_slice(&raw.next_itt().to_be_bytes());
    tmf[20..24].copy_from_slice(&0x7777u32.to_be_bytes());
    tmf[24..28].copy_from_slice(&raw.cmd_sn.to_be_bytes());
    tmf[32..36].copy_from_slice(&(raw.cmd_sn + 10).to_be_bytes());
    raw.send(tmf, &[]).await;
    assert_eq!(raw.recv().await.bhs[2], 1, "task does not exist");
    oracle(&raw).assert_clean();
}
