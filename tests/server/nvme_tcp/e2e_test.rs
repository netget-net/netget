//! NetGet's NVMe/TCP target against a raw host written from the specifications' offsets (see
//! `support.rs`), with a python policy playing the model (see `support::POLICY`). tshark's
//! nvme-tcp and nvme dissectors read the bytes both ways, in the order they crossed.
use super::support::*;
use serde_json::json;
use std::time::Duration;

/// A field tshark reads, across every packet, as one list.
fn tshark_values(raw: &Raw, field: &str) -> Vec<String> {
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
fn number(v: &str) -> Option<u64> {
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

#[tokio::test]
async fn discovery_log_lists_the_models_subsystems_and_tshark_reads_it() {
    let srv = start(policy(POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    let ic = raw.icreq(0, 0).await;
    assert_eq!(le16(&ic.header, 8), 0, "PFV 0");
    assert_eq!(ic.header[10], 0, "CPDA 0");
    assert_eq!(ic.header[11], 0, "no digests asked, none enabled");
    assert_eq!(le32(&ic.header, 12), 128 * 1024, "MAXH2CDATA");
    let c = raw
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISCOVERY, HOST))
        .await;
    assert!(c.ok(), "{c:?}");
    let cntlid = (c.dw0 & 0xFFFF) as u16;
    assert!(cntlid > 0 && cntlid < 0xFFF0);
    assert_eq!(c.sqid, 0);
    // Nothing but properties before CC.EN.
    let (_, c) = raw.identify(1, 0).await;
    assert_eq!(c.sc(), SEQUENCE_ERROR, "Identify before CC.EN");
    let c = raw.prop_get(0x00, true).await;
    let cap = c.dw0 as u64 | (c.dw1 as u64) << 32;
    assert_eq!(cap & 0xFFFF, 127, "CAP.MQES");
    assert!(cap & (1 << 37) != 0, "CAP.CSS: NVM command set");
    assert_eq!(raw.prop_get(0x08, false).await.dw0, 0x0001_0400, "VS 1.4");
    raw.enable().await;
    let (id, c) = raw.identify(1, 0).await;
    assert!(c.ok(), "{c:?}");
    assert_eq!(id.len(), 4096);
    assert_eq!(id[111], 2, "CNTRLTYPE: discovery controller");
    assert_eq!(le16(&id, 78), cntlid, "Identify's CNTLID is Connect's");
    assert_eq!(ascii(&id[768..1024]), DISCOVERY);
    assert_eq!(
        le32(&id, 516),
        0,
        "a discovery controller has no namespaces"
    );

    let (head, c) = raw.get_log(0x70, 0, 1024).await;
    assert!(c.ok(), "{c:?}");
    assert_eq!(le64(&head, 8), 2, "NUMREC");
    let genctr = le64(&head, 0);
    let (log, c) = raw.get_log(0x70, 0, 3 * 1024).await;
    assert!(c.ok());
    assert_eq!(&log[..1024], &head[..], "the header again");
    let e = &log[1024..2048];
    assert_eq!((e[0], e[1], e[2]), (3, 1, 2), "TCP, IPv4, NVM subsystem");
    assert_eq!(le16(e, 6), 0xFFFF, "dynamic controller");
    assert_eq!(
        ascii(&e[32..64]),
        srv.port.to_string(),
        "TRSVCID: this listener"
    );
    assert_eq!(ascii(&e[256..512]), DISK0);
    assert_eq!(
        ascii(&e[512..768]),
        "127.0.0.1",
        "TRADDR: the portal the host used"
    );
    let e = &log[2048..3072];
    assert_eq!(ascii(&e[256..512]), BACKUP);
    assert_eq!(ascii(&e[512..768]), "192.0.2.7");
    assert_eq!(ascii(&e[32..64]), "4420");
    // A read at an offset returns the same bytes; past the end is refused.
    let (second, c) = raw.get_log(0x70, 2048, 1024).await;
    assert!(c.ok());
    assert_eq!(second, log[2048..3072].to_vec());
    let (_, c) = raw.get_log(0x70, 8192, 4).await;
    assert_eq!(c.sc(), INVALID_FIELD, "LPO past the log");
    let (again, _) = raw.get_log(0x70, 0, 16).await;
    assert_eq!(le64(&again, 0), genctr, "the generation does not move");
    assert_eq!(
        events(&srv.state, srv.id, "nvme_tcp_discovery").await.len(),
        1,
        "the model is asked once per discovery controller"
    );
    // A discovery controller has no namespaces, health log or I/O commands.
    let (_, c) = raw.identify(0, 1).await;
    assert_eq!(c.sc(), INVALID_FIELD);
    let (_, c) = raw.get_log(0x02, 0, 512).await;
    assert_eq!(c.sc(), INVALID_LOG_PAGE);
    let (_, c) = raw
        .cmd(&Sqe::new(0x02, 1).range(0, 1).transport(512), &[])
        .await;
    assert_eq!(
        c.sc(),
        INVALID_LOG_PAGE,
        "opcode 02h on the admin queue is Get Log Page"
    );
    // Shutdown: CC.SHN normal, CSTS.SHST complete.
    let c = raw.prop_set(0x14, 1 | 6 << 16 | 4 << 20 | 1 << 14).await;
    assert!(c.ok());
    assert_eq!((raw.prop_get(0x1C, false).await.dw0 >> 2) & 3, 2, "SHST");
    assert!(events(&srv.state, srv.id, "nvme_tcp_connect")
        .await
        .is_empty());

    raw.oracle().also_named("nvme").assert_clean();
    let subnqns = tshark_values(&raw, "nvme.fabrics.cmd.connect.data.subnqn");
    assert!(subnqns.iter().any(|v| v == DISCOVERY), "{subnqns:?}");
    let listed = tshark_values(&raw, "nvme.cmd.get_logpage.identify.rcrd.subnqn");
    assert!(
        listed.iter().any(|v| v == DISK0) && listed.iter().any(|v| v == BACKUP),
        "tshark reads both discovery records: {listed:?}"
    );
    let maxdata = tshark_values(&raw, "nvme-tcp.icresp.maxdata");
    assert_eq!(
        maxdata.iter().map(|v| number(v)).collect::<Vec<_>>(),
        [Some(131072)],
        "tshark reads MAXH2CDATA"
    );
}

/// An admin queue to disk0, enabled. Returns (raw admin queue, CNTLID).
async fn disk0_admin(port: u16) -> (Raw, u16) {
    let mut raw = Raw::connect(port).await;
    let cntlid = raw.admin_session(DISK0, HOST, 0).await;
    (raw, cntlid)
}

#[tokio::test]
async fn an_association_serves_the_described_namespaces() {
    let srv = start(policy(POLICY), None).await;
    let (mut admin, cntlid) = disk0_admin(srv.port).await;
    let ev = events(&srv.state, srv.id, "nvme_tcp_connect").await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["host_nqn"], HOST);
    assert_eq!(ev[0]["subsystem_nqn"], DISK0);
    assert_eq!(ev[0]["host_id"], "6c3a8f04-1f3e-4b0e-9f43-2d1c0a6b7e55");

    let (id, c) = admin.identify(1, 0).await;
    assert!(c.ok());
    assert_eq!(ascii(&id[4..24]), "SER0001");
    assert_eq!(ascii(&id[24..64]), "NETGET-BOOT");
    assert_eq!(id[77], 8, "MDTS: 1 MiB");
    assert_eq!(le16(&id, 78), cntlid);
    assert_eq!(id[111], 1, "CNTRLTYPE: I/O controller");
    assert_eq!((id[512], id[513]), (0x66, 0x44), "SQES, CQES");
    assert_eq!(le32(&id, 516), 2, "NN");
    assert!(le32(&id, 536) & 1 != 0, "SGLs supported");
    assert!(
        le32(&id, 536) & (1 << 20) != 0,
        "SGL offsets (in-capsule data)"
    );
    assert_eq!(le32(&id, 1792), (64 + 8192) / 16, "IOCCSZ");
    assert_eq!(le32(&id, 1796), 1, "IORCSZ");
    assert!(le16(&id, 320) > 0, "KAS: keep alive is supported");
    assert_eq!(ascii(&id[768..1024]), DISK0);

    let (list, c) = admin.identify(2, 0).await;
    assert!(c.ok());
    assert_eq!((le32(&list, 0), le32(&list, 4), le32(&list, 8)), (1, 2, 0));
    let (list, _) = admin.identify(2, 1).await;
    assert_eq!((le32(&list, 0), le32(&list, 4)), (2, 0), "NSIDs above 1");
    let (ns1, c) = admin.identify(0, 1).await;
    assert!(c.ok());
    assert_eq!(le64(&ns1, 0), 2048, "NSZE");
    assert_eq!(ns1[130], 9, "LBAF0 LBADS: 512-byte blocks");
    assert_eq!(ns1[99] & 1, 0, "NSATTR: writable");
    let (ns2, _) = admin.identify(0, 2).await;
    assert_eq!(le64(&ns2, 0), 512);
    assert_eq!(ns2[130], 12, "4096-byte blocks");
    assert_eq!(ns2[99] & 1, 1, "NSATTR: write protected");
    let (absent, c) = admin.identify(0, 3).await;
    assert!(
        c.ok() && absent.iter().all(|b| *b == 0),
        "an inactive NSID reads as zeroes"
    );
    let (_, c) = admin.identify(0, 0).await;
    assert_eq!(c.sc(), INVALID_NAMESPACE);
    let (desc, c) = admin.identify(3, 1).await;
    assert!(c.ok());
    assert_eq!((desc[0], desc[1]), (1, 8), "EUI-64 descriptor");
    assert_eq!((desc[12], desc[13]), (2, 16), "NGUID descriptor");
    assert_eq!(
        &desc[16..32],
        &ns1[104..120],
        "the NGUID Identify Namespace reports"
    );
    let (_, c) = admin.identify(3, 9).await;
    assert_eq!(c.sc(), INVALID_NAMESPACE);
    let (_, c) = admin.identify(0x20, 0).await;
    assert_eq!(c.sc(), INVALID_FIELD, "an unknown CNS");
    let (nvm, c) = admin.identify(0x06, 0).await;
    assert!(
        c.ok() && nvm.iter().all(|b| *b == 0),
        "the NVM command set's Identify Controller reports no limits"
    );

    // Two I/O queues granted of the eight asked for? This target grants up to 8.
    let (_, c) = admin
        .cmd(&Sqe::new(0x09, 0).cdw(10, 0x07).cdw(11, 3 | 3 << 16), &[])
        .await;
    assert!(c.ok());
    assert_eq!(c.dw0, 3 | 3 << 16, "four I/O queues granted");
    let (_, c) = admin.cmd(&Sqe::new(0x0A, 0).cdw(10, 0x07), &[]).await;
    assert_eq!(c.dw0, 3 | 3 << 16, "Get Features reports the grant");
    let (_, c) = admin
        .cmd(&Sqe::new(0x09, 0).cdw(10, 0x07 | 1 << 31).cdw(11, 0), &[])
        .await;
    assert_eq!(c.sc(), (1, 0x0D), "not saveable");
    let (_, c) = admin.cmd(&Sqe::new(0x18, 0), &[]).await;
    assert!(c.ok(), "Keep Alive");

    // I/O queue 1.
    let mut io = Raw::connect(srv.port).await;
    let c = io.io_session(1, cntlid, DISK0).await;
    assert!(c.ok(), "{c:?}");
    assert_eq!(c.dw0 & 0xFFFF, cntlid as u32);
    assert_eq!(c.sqid, 1);
    let (d, c) = io.read(1, 0, 1, 512).await;
    assert!(c.ok());
    assert_eq!(&d[..17], b"hello from netget");
    assert!(d[17..].iter().all(|b| *b == 0));
    let (d, _) = io.read(1, 8, 1, 512).await;
    assert!(d.iter().all(|b| *b == 0xAB), "the fill at 4096");
    let (d, _) = io.read(2, 0, 1, 4096).await;
    assert_eq!(&d[..4], &[0xde, 0xad, 0xbe, 0xef]);
    // 256 KiB in one command: C2HData in 128 KiB PDUs.
    let before = io.transcript.len();
    let (d, c) = io.read(1, 0, 512, 512).await;
    assert!(c.ok());
    assert_eq!(d.len(), 256 * 1024);
    assert_eq!(&d[..17], b"hello from netget");
    assert!(io.transcript.len() > before);
    // Failures the description names, and the bounds of the namespace.
    let (_, c) = io.read(1, 1024, 8, 512).await;
    assert_eq!(c.sc(), UNRECOVERED_READ, "the medium error at 512 KiB");
    let (_, c) = io.read(1, 2047, 2, 512).await;
    assert_eq!(c.sc(), LBA_OUT_OF_RANGE);
    let (_, c) = io.read(3, 0, 1, 512).await;
    assert_eq!(c.sc(), INVALID_NAMESPACE);
    let (_, c) = io
        .cmd(&Sqe::new(0x02, 1).range(0, 2).transport(512), &[])
        .await;
    assert_eq!(
        c.sc(),
        SGL_LENGTH_INVALID,
        "an SGL shorter than the blocks asked for"
    );
    let (_, c) = io
        .cmd(&Sqe::new(0x02, 2).range(0, 512).transport(512 * 4096), &[])
        .await;
    assert_eq!(c.sc(), INVALID_FIELD, "a read over MDTS");
    let (_, c) = io
        .cmd(&Sqe::new(0x02, 1).range(0, 1).in_capsule(512), &[])
        .await;
    assert_eq!(c.sc(), SGL_TYPE_INVALID, "an in-capsule SGL on a read");

    // Writes: in the capsule, and solicited by R2T in two H2CData PDUs per R2T.
    let c = io
        .write_in_capsule(1, 100, &pad(b"written in the capsule", 512), 512)
        .await;
    assert!(c.ok(), "{c:?}");
    let big: Vec<u8> = (0..160 * 1024).map(|i| (i % 251) as u8).collect();
    let (r2ts, c) = io.write_solicited(1, 200, &big, 512, 96 * 1024).await;
    assert!(c.ok(), "{c:?}");
    assert_eq!(
        r2ts,
        [(0, 128 * 1024), (128 * 1024, 32 * 1024)],
        "R2Ts of MAXH2CDATA"
    );
    let c = io.write_in_capsule(2, 0, &[0u8; 4096], 4096).await;
    assert_eq!(c.sc(), WRITE_PROTECTED);
    let c = io.write_in_capsule(1, 1024, &[1u8; 512], 512).await;
    assert_eq!(c.sc(), WRITE_FAULT, "a write into the error region");
    let (_, c) = io.cmd(&Sqe::new(0x08, 1).range(8, 1), &[]).await;
    assert!(c.ok(), "Write Zeroes");
    let (_, c) = io.cmd(&Sqe::new(0x08, 2).range(0, 1), &[]).await;
    assert_eq!(c.sc(), WRITE_PROTECTED);
    let (_, c) = io.cmd(&Sqe::new(0x00, 1), &[]).await;
    assert!(c.ok(), "Flush");
    let mut range = vec![0u8; 16];
    range[4..8].copy_from_slice(&8u32.to_le_bytes());
    range[8..16].copy_from_slice(&16u64.to_le_bytes());
    let (_, c) = io
        .cmd(
            &Sqe::new(0x09, 1).cdw(10, 0).cdw(11, 4).in_capsule(16),
            &range,
        )
        .await;
    assert!(c.ok(), "Dataset Management (deallocate)");
    let (_, c) = io.cmd(&Sqe::new(0x7E, 1), &[]).await;
    assert_eq!(c.sc(), INVALID_OPCODE);

    // A second I/O queue of the same controller reads what the first wrote.
    let mut io2 = Raw::connect(srv.port).await;
    let c = io2.io_session(2, cntlid, DISK0).await;
    assert!(c.ok(), "{c:?}");
    let (d, _) = io2.read(1, 100, 1, 512).await;
    assert_eq!(&d[..22], b"written in the capsule");
    let (d, _) = io2.read(1, 200, 320, 512).await;
    assert_eq!(d, big, "the solicited write read back");
    let (d, _) = io2.read(1, 8, 1, 512).await;
    assert!(d.iter().all(|b| *b == 0), "Write Zeroes replaced the fill");

    // The health log counts what was done.
    let (smart, c) = admin.get_log(0x02, 0, 512).await;
    assert!(c.ok());
    assert!(
        le64(&smart, 64) >= 6,
        "host read commands: {}",
        le64(&smart, 64)
    );
    assert_eq!(le64(&smart, 80), 2, "host write commands");
    assert!(le64(&smart, 160) >= 1, "media errors");
    let (_, c) = admin.get_log(0x05, 0, 4096).await;
    assert_eq!(c.sc(), INVALID_LOG_PAGE);
    // An Asynchronous Event Request is held; the fifth is over AERL.
    for _ in 0..4 {
        admin.capsule(&Sqe::new(0x0C, 0), &[]).await;
    }
    assert!(
        admin
            .recv_within(Duration::from_millis(500))
            .await
            .is_none(),
        "AERs are held, not completed"
    );
    let (_, c) = admin.cmd(&Sqe::new(0x0C, 0), &[]).await;
    assert_eq!(c.sc(), AER_LIMIT);
    assert_eq!(
        events(&srv.state, srv.id, "nvme_tcp_connect").await.len(),
        1,
        "one model call for the whole association"
    );

    admin.oracle().also_named("nvme").assert_clean();
    io.oracle().also_named("nvme").assert_clean();
    let models = tshark_values(&admin, "nvme.cmd.identify.ctrl.mn");
    assert!(models.iter().any(|m| m == "NETGET-BOOT"), "{models:?}");
    let nsze = tshark_values(&admin, "nvme.cmd.identify.ns.nsze");
    assert!(nsze.iter().any(|n| number(n) == Some(2048)), "{nsze:?}");
    let r2t = tshark_values(&io, "nvme-tcp.r2t.length");
    assert!(r2t.iter().any(|l| number(l) == Some(131072)), "{r2t:?}");
    let slba = tshark_values(&io, "nvme.cmd.slba");
    assert!(slba.iter().any(|l| number(l) == Some(200)), "{slba:?}");

    // When the admin queue goes, the controller and its I/O queues go, with the writes.
    drop(admin);
    assert!(io.closed().await, "an I/O queue outlives no controller");
    assert!(io2.closed().await);
    let (mut admin, cntlid2) = disk0_admin(srv.port).await;
    let mut io = Raw::connect(srv.port).await;
    assert!(io.io_session(1, cntlid2, DISK0).await.ok());
    let (d, _) = io.read(1, 100, 1, 512).await;
    assert!(
        d.iter().all(|b| *b == 0),
        "a new association sees only the description"
    );
    let mut stale = Raw::connect(srv.port).await;
    let c = stale.io_session(3, cntlid, DISK0).await;
    assert_eq!(c.sc(), CONNECT_INVALID_PARAMS, "the old controller is gone");
    assert_eq!(c.dw0, 16 | 1 << 16, "IPO: CNTLID in the data");
    let _ = admin.prop_set(0x14, 0).await;
}

fn pad(b: &[u8], to: usize) -> Vec<u8> {
    let mut v = b.to_vec();
    v.resize(to, 0);
    v
}

#[tokio::test]
async fn connects_fail_closed_and_expose_no_controller() {
    // Only discovery has a handler: a connect falls through to the unreachable model.
    let handlers = Some(vec![
        json!({"event_pattern":"nvme_tcp_discovery","handler":{"type":"script","language":"python","code":POLICY}}),
    ]);
    let srv = start(handlers, None).await;
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    let c = raw
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
        .await;
    assert_eq!(c.sc(), INTERNAL_ERROR, "the backend failed: {c:?}");
    assert!(!c.dnr(), "a backend failure may be retried");
    let (_, c) = raw.identify(1, 0).await;
    assert_eq!(
        c.sc(),
        SEQUENCE_ERROR,
        "no controller: still waiting for a Connect"
    );

    let srv = start(policy(POLICY), None).await;
    for (subnqn, host, status, dw0) in [
        ("nqn.2026-10.net.netget:silent", HOST, INTERNAL_ERROR, 0),
        ("nqn.2026-10.net.netget:invalid", HOST, INTERNAL_ERROR, 0),
        (
            "nqn.2026-10.net.netget:nothing",
            HOST,
            CONNECT_INVALID_PARAMS,
            256 | 1 << 16,
        ),
        (
            DISK0,
            "nqn.2026-10.org.example:denied",
            CONNECT_INVALID_HOST,
            512 | 1 << 16,
        ),
    ] {
        let mut raw = Raw::connect(srv.port).await;
        raw.icreq(0, 0).await;
        let c = raw
            .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, subnqn, host))
            .await;
        assert_eq!((c.sc(), c.dw0), (status, dw0), "{subnqn} {host}");
        assert!(c.dnr());
        // No controller exists: an I/O queue naming CNTLID 1 finds nothing.
        let mut io = Raw::connect(srv.port).await;
        let c = io.io_session(1, 1, subnqn).await;
        assert_eq!(c.sc(), CONNECT_INVALID_PARAMS, "{subnqn}: no controller");
    }
    assert_eq!(
        events(&srv.state, srv.id, "nvme_tcp_connect").await.len(),
        4,
        "each admin Connect asked the model once, and no I/O queue did"
    );
}

#[tokio::test]
async fn io_queue_connects_are_checked_against_the_association() {
    let srv = start(policy(POLICY), None).await;
    // An admin Connect naming a controller (this target's controllers are dynamic), a record
    // format that is not 0, a zero or oversized SQSIZE.
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    let c = raw
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 7, DISK0, HOST))
        .await;
    assert_eq!((c.sc(), c.dw0), (CONNECT_INVALID_PARAMS, 16 | 1 << 16));
    let sqe = Sqe::fabrics(0x01)
        .u16_at(40, 1)
        .u16_at(44, 31)
        .in_capsule(1024);
    let (_, c) = raw
        .cmd(&sqe, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
        .await;
    assert_eq!(c.sc(), CONNECT_FORMAT, "RECFMT 1");
    for sqsize in [0u16, 8, 128] {
        let c = raw
            .connect_queue(0, sqsize, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
            .await;
        assert_eq!(
            (c.sc(), c.dw0),
            (CONNECT_INVALID_PARAMS, 44),
            "SQSIZE {sqsize}"
        );
    }
    let mut bad = connect_data(&HOSTID, 0xFFFF, DISK0, HOST);
    bad[512..516].copy_from_slice(b"host");
    let c = raw.connect_queue(0, 31, 0, 0, &bad).await;
    assert_eq!(
        (c.sc(), c.dw0),
        (CONNECT_INVALID_PARAMS, 512 | 1 << 16),
        "not an NQN"
    );
    assert!(events(&srv.state, srv.id, "nvme_tcp_connect")
        .await
        .is_empty());

    // The admin queue Connects; I/O queues before CC.EN, past the grant, twice, for another
    // host or ID, and with an oversized SQSIZE are refused.
    let mut admin = Raw::connect(srv.port).await;
    admin.icreq(0, 0).await;
    let c = admin
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
        .await;
    assert!(c.ok());
    let cntlid = (c.dw0 & 0xFFFF) as u16;
    let c = admin
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
        .await;
    assert_eq!(
        c.sc(),
        SEQUENCE_ERROR,
        "a second Connect on a connected queue"
    );
    let mut io = Raw::connect(srv.port).await;
    assert_eq!(
        io.io_session(1, cntlid, DISK0).await.sc(),
        SEQUENCE_ERROR,
        "before CC.EN"
    );
    admin.enable().await;
    let (_, c) = admin
        .cmd(&Sqe::new(0x09, 0).cdw(10, 0x07).cdw(11, 0), &[])
        .await;
    assert_eq!(c.dw0, 0, "one I/O queue granted");
    let mut io = Raw::connect(srv.port).await;
    let c = io.io_session(2, cntlid, DISK0).await;
    assert_eq!(
        (c.sc(), c.dw0),
        (CONNECT_INVALID_PARAMS, 42),
        "QID past the grant"
    );
    let mut io = Raw::connect(srv.port).await;
    io.icreq(0, 0).await;
    let c = io
        .connect_queue(
            1,
            31,
            0,
            0,
            &connect_data(&HOSTID, cntlid, DISK0, "nqn.2026-10.org.example:other"),
        )
        .await;
    assert_eq!(
        (c.sc(), c.dw0),
        (CONNECT_INVALID_PARAMS, 16 | 1 << 16),
        "another host"
    );
    let c = io
        .connect_queue(1, 31, 0, 0, &connect_data(&[9u8; 16], cntlid, DISK0, HOST))
        .await;
    assert_eq!(c.sc(), CONNECT_INVALID_PARAMS, "another host ID");
    let c = io
        .connect_queue(1, 200, 0, 0, &connect_data(&HOSTID, cntlid, DISK0, HOST))
        .await;
    assert_eq!(
        (c.sc(), c.dw0),
        (CONNECT_INVALID_PARAMS, 44),
        "SQSIZE past MQES"
    );
    let c = io
        .connect_queue(1, 31, 0, 0, &connect_data(&HOSTID, cntlid, DISK0, HOST))
        .await;
    assert!(c.ok());
    let mut dup = Raw::connect(srv.port).await;
    assert_eq!(
        dup.io_session(1, cntlid, DISK0).await.sc(),
        SEQUENCE_ERROR,
        "QID 1 twice"
    );
    let (_, c) = admin
        .cmd(&Sqe::new(0x09, 0).cdw(10, 0x07).cdw(11, 3 | 3 << 16), &[])
        .await;
    assert_eq!(
        c.sc(),
        SEQUENCE_ERROR,
        "Number of Queues after an I/O queue exists"
    );
    // Admin commands are not I/O commands, and the other way round.
    let (_, c) = io.identify(1, 0).await;
    assert_eq!(
        c.sc(),
        INVALID_OPCODE,
        "opcode 06h on an I/O queue is not Identify"
    );
    let (_, c) = admin.read(1, 0, 1, 512).await;
    assert_eq!(
        c.sc(),
        INVALID_LOG_PAGE,
        "opcode 02h on the admin queue is Get Log Page"
    );
    // A controller reset (CC.EN 1 → 0) ends its I/O queues.
    assert!(admin.prop_set(0x14, 0).await.ok());
    assert_eq!(admin.prop_get(0x1C, false).await.dw0 & 1, 0, "not ready");
    assert!(io.closed().await, "the I/O queue ends with the reset");
    // Discovery controllers take no I/O queues.
    let mut disc = Raw::connect(srv.port).await;
    let dc = disc.admin_session(DISCOVERY, HOST, 0).await;
    let mut io = Raw::connect(srv.port).await;
    let c = io.io_session(1, dc, DISCOVERY).await;
    assert_eq!((c.sc(), c.dw0), (CONNECT_INVALID_PARAMS, 42));
}

#[tokio::test]
async fn bounds_refuse_before_anything_is_buffered() {
    let srv = start(policy(POLICY), None).await;
    // The first PDU must be an ICReq.
    let mut raw = Raw::connect(srv.port).await;
    raw.send(CMD, 0, &[0u8; 64], &[]).await;
    let t = raw.recv().await;
    assert_eq!(t.term().0, 0x02, "PDU sequence error");
    assert!(raw.closed().await);
    // An ICReq with the wrong PLEN, PFV or HPDA.
    let mut raw = Raw::connect(srv.port).await;
    let mut b = raw.frame(ICREQ, 0, &[0u8; 120], &[]);
    b[4..8].copy_from_slice(&132u32.to_le_bytes());
    raw.write(&b).await;
    assert_eq!(raw.recv().await.term(), (0x01, 4), "PLEN");
    for (at, value, fei) in [(8usize, 1u8, 8u32), (10, 32, 10)] {
        let mut raw = Raw::connect(srv.port).await;
        let mut psh = [0u8; 120];
        psh[at - 8] = value;
        raw.send(ICREQ, 0, &psh, &[]).await;
        assert_eq!(raw.recv().await.term(), (0x06, fei), "ICReq byte {at}");
        assert!(raw.closed().await);
    }
    // A capsule declaring a gigabyte of in-capsule data is refused from its header.
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    let mut b = raw.frame(CMD, 0, &[0u8; 64], &[]);
    b[3] = 72;
    b[4..8].copy_from_slice(&(1u32 << 30).to_le_bytes());
    raw.write(&b).await;
    let t = raw.recv().await;
    assert_eq!(t.term(), (0x01, 4), "PLEN over the in-capsule data allowed");
    assert_eq!(&t.data[..8], &b[..8], "the offending header comes back");
    assert!(raw.closed().await);
    // The in-capsule bound itself: 8 KiB passes the header check, 8 KiB + 4 does not.
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    raw.send(CMD, 0, &[0u8; 64], &vec![0u8; 8196]).await;
    assert_eq!(raw.recv().await.term(), (0x01, 4));
    // A wrong HLEN.
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    let mut b = raw.frame(CMD, 0, &[0u8; 64], &[]);
    b[2] = 24;
    raw.write(&b).await;
    assert_eq!(raw.recv().await.term(), (0x01, 2), "HLEN");
    // A host-to-controller type the controller sends.
    let mut raw = Raw::connect(srv.port).await;
    raw.icreq(0, 0).await;
    raw.send(R2T, 0, &[0u8; 16], &[]).await;
    assert_eq!(raw.recv().await.term().0, 0x02, "R2T from the host");

    // H2CData: over MAXH2CDATA, for no command, with the wrong TTAG or offset.
    let (mut admin, cntlid) = disk0_admin(srv.port).await;
    let mut io = Raw::connect(srv.port).await;
    assert!(io.io_session(1, cntlid, DISK0).await.ok());
    let cid = io
        .capsule(&Sqe::new(0x01, 1).range(0, 512).transport(256 * 1024), &[])
        .await;
    let r2t = io.recv().await;
    assert_eq!(r2t.kind(), R2T);
    let ttag = le16(&r2t.header, 10);
    io.h2c(cid, ttag, 0, &vec![0u8; 128 * 1024 + 4], true).await;
    assert_eq!(io.recv().await.term().0, 0x05, "H2CData over MAXH2CDATA");
    assert!(io.closed().await);
    for (cccid_delta, ttag_delta, offset, fes, fei) in [
        (1u16, 0u16, 0u32, 0x01u16, 8u32),
        (0, 1, 0, 0x01, 10),
        (0, 0, 512, 0x04, 0),
    ] {
        let mut io = Raw::connect(srv.port).await;
        assert!(
            io.io_session(1, cntlid, DISK0).await.ok(),
            "QID 1 is free again"
        );
        let cid = io
            .capsule(&Sqe::new(0x01, 1).range(0, 8).transport(4096), &[])
            .await;
        let r2t = io.recv().await;
        let ttag = le16(&r2t.header, 10);
        io.h2c(
            cid.wrapping_add(cccid_delta),
            ttag.wrapping_add(ttag_delta),
            offset,
            &[0u8; 512],
            false,
        )
        .await;
        let t = io.recv().await;
        assert_eq!(t.term().0, fes, "{cccid_delta} {ttag_delta} {offset}");
        if fes == 0x01 {
            assert_eq!(t.term().1, fei);
        }
        assert!(io.closed().await);
    }
    // A command ID already outstanding (a write waiting for its data).
    let mut io = Raw::connect(srv.port).await;
    assert!(io.io_session(1, cntlid, DISK0).await.ok());
    let cid = io
        .capsule(&Sqe::new(0x01, 1).range(0, 8).transport(4096), &[])
        .await;
    let _r2t = io.recv().await;
    io.cid = cid - 1;
    let (_, c) = io.cmd(&Sqe::new(0x00, 1), &[]).await;
    assert_eq!(c.sc(), CID_CONFLICT);
    // Nothing was written by any of the refused transfers.
    let (d, _) = io.read(1, 0, 1, 512).await;
    assert_eq!(&d[..17], b"hello from netget");
    let _ = admin.prop_set(0x14, 0).await;
}

#[tokio::test]
async fn crc32c_digests_are_negotiated_and_checked() {
    let srv = start(policy(POLICY), None).await;
    let mut admin = Raw::connect(srv.port).await;
    let ic = admin.icreq(0, 3).await;
    assert_eq!(ic.header[11], 3, "both digests enabled");
    let c = admin
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, DISK0, HOST))
        .await;
    assert!(c.ok(), "{c:?}");
    let cntlid = (c.dw0 & 0xFFFF) as u16;
    admin.enable().await;
    let mut io = Raw::connect(srv.port).await;
    io.icreq(0, 3).await;
    let c = io
        .connect_queue(1, 31, 0, 0, &connect_data(&HOSTID, cntlid, DISK0, HOST))
        .await;
    assert!(c.ok());
    // Every PDU the target sends carries digests the raw host checks itself.
    let (d, _) = io.read(1, 0, 1, 512).await;
    assert_eq!(&d[..17], b"hello from netget");
    let (r2ts, c) = io.write_solicited(1, 300, &[7u8; 8192], 512, 4096).await;
    assert!(c.ok() && r2ts.len() == 1);
    // A bad data digest on a write capsule: that command fails, the queue goes on.
    let sqe = Sqe::new(0x01, 1).range(400, 1).in_capsule(512);
    let mut b = io.frame(
        CMD,
        0,
        &{
            let mut s = sqe.0;
            s[2..4].copy_from_slice(&0x77u16.to_le_bytes());
            s
        },
        &[5u8; 512],
    );
    let n = b.len();
    b[n - 1] ^= 0xFF;
    io.write(&b).await;
    let c = io.recv().await.cqe();
    assert_eq!((c.cid, c.sc()), (0x77, TRANSIENT_TRANSPORT));
    let (d, _) = io.read(1, 400, 1, 512).await;
    assert!(d.iter().all(|b| *b == 0), "nothing was written");
    // A bad header digest: C2HTermReq and the queue closes.
    let mut b = io.frame(CMD, 0, &Sqe::new(0x00, 1).0, &[]);
    b[72] ^= 0xFF;
    io.write(&b).await;
    assert_eq!(io.recv().await.term().0, 0x03, "header digest error");
    assert!(io.closed().await);
    // A header digest flag that disagrees with what was negotiated.
    let mut io = Raw::connect(srv.port).await;
    io.icreq(0, 0).await;
    io.hdgst = true;
    io.send(CMD, 0, &Sqe::new(0x00, 0).0, &[]).await;
    io.hdgst = false;
    assert_eq!(
        io.recv().await.term(),
        (0x01, 1),
        "HDGSTF when none was negotiated"
    );
    admin.oracle().also_named("nvme").assert_clean();

    // A target that requires digests refuses a host that does not ask; one that refuses
    // them enables none.
    let strict = start(policy(POLICY), Some(json!({"digests": "crc32c"}))).await;
    let mut raw = Raw::connect(strict.port).await;
    raw.send(ICREQ, 0, &[0u8; 120], &[]).await;
    assert_eq!(raw.recv().await.term(), (0x06, 11));
    let none = start(policy(POLICY), Some(json!({"digests": "none"}))).await;
    let mut raw = Raw::connect(none.port).await;
    assert_eq!(raw.icreq(0, 3).await.header[11], 0);
}

#[tokio::test]
async fn keep_alive_expiry_ends_the_controller() {
    let srv = start(policy(POLICY), None).await;
    let mut admin = Raw::connect(srv.port).await;
    let cntlid = admin.admin_session(DISK0, HOST, 1000).await;
    let mut io = Raw::connect(srv.port).await;
    assert!(io.io_session(1, cntlid, DISK0).await.ok());
    // Traffic on the I/O queue keeps the association alive past KATO.
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_millis(3500) {
        let (_, c) = io.read(1, 0, 1, 512).await;
        assert!(c.ok());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Then silence: KATO (1 s) plus the grace (2 s), and both queues close.
    let quiet = std::time::Instant::now();
    assert!(
        admin.closed().await,
        "the admin queue ends when keep-alive expires"
    );
    assert!(io.closed().await, "and its I/O queues with it");
    assert!(
        quiet.elapsed() >= Duration::from_secs(2),
        "{:?}",
        quiet.elapsed()
    );
    let mut again = Raw::connect(srv.port).await;
    assert_eq!(
        again.io_session(1, cntlid, DISK0).await.sc(),
        CONNECT_INVALID_PARAMS,
        "the controller is gone"
    );
}

#[tokio::test]
async fn disabled_sq_flow_control_ends_reads_with_success() {
    let srv = start(policy(POLICY), None).await;
    let (_admin, cntlid) = disk0_admin(srv.port).await;
    let mut io = Raw::connect(srv.port).await;
    io.icreq(0, 0).await;
    let c = io
        .connect_queue(1, 31, 0, 0x04, &connect_data(&HOSTID, cntlid, DISK0, HOST))
        .await;
    assert!(c.ok());
    assert_eq!(c.sqhd, 0xFFFF, "SQHD is not reported");
    let cid = io
        .capsule(&Sqe::new(0x02, 1).range(0, 1).transport(512), &[])
        .await;
    let g = io.recv().await;
    assert_eq!(g.kind(), C2H_DATA);
    assert_eq!(le16(&g.header, 8), cid);
    assert_eq!(g.flags() & 0x0C, 0x0C, "LAST_PDU and SUCCESS");
    assert!(
        io.recv_within(Duration::from_millis(300)).await.is_none(),
        "no CapsuleResp follows SUCCESS"
    );
    // A failed read still completes with a CapsuleResp.
    let (_, c) = io.read(1, 4096, 1, 512).await;
    assert_eq!(c.sc(), LBA_OUT_OF_RANGE);
    assert_eq!(c.sqhd, 0xFFFF);
    io.oracle().also_named("nvme").assert_clean();
    let success = tshark_values(&io, "nvme-tcp.flags.pdu.data_success");
    assert!(
        success.iter().any(|v| v == "1" || v == "True"),
        "{success:?}"
    );
}

#[tokio::test]
async fn sq_head_advances_and_wraps() {
    let srv = start(policy(POLICY), None).await;
    let (_admin, cntlid) = disk0_admin(srv.port).await;
    let mut io = Raw::connect(srv.port).await;
    io.icreq(0, 0).await;
    let c = io
        .connect_queue(1, 3, 0, 0, &connect_data(&HOSTID, cntlid, DISK0, HOST))
        .await;
    assert!(c.ok());
    assert_eq!(c.sqhd, 1, "the Connect took the first slot");
    let mut heads = Vec::new();
    for _ in 0..5 {
        heads.push(io.cmd(&Sqe::new(0x00, 1), &[]).await.1.sqhd);
    }
    assert_eq!(heads, [2, 3, 0, 1, 2], "a four-entry queue wraps");
}
