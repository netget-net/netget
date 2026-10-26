//! Compare, Verify, Copy and persistent reservations on NetGet's NVMe/TCP target, driven by the
//! raw host of `support.rs` (every SQE and data structure from the specification's offsets).
//! The python policy plays the model: it describes the namespaces, allows reservation changes,
//! refuses a preempt-and-abort, and on namespace 3 answers silently (host A) or with something
//! that is not a reservation decision (host B), which must change nothing.
use super::support::*;

const SUBSYS: &str = "nqn.2026-10.net.netget:cmds";
const HOST_B: &str = "nqn.2026-10.org.example:raw-host-b";
const HOSTID_B: [u8; 16] = [0xB0; 16];

const CMD_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='nvme_tcp_connect':
  a=[{'type':'nvme_tcp_accept_connect','namespaces':[
    {'nsid':1,'size':1048576,'writable':True,
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}],
     'errors':[{'offset':524288,'length':4096,'error':'medium_error'}]},
    {'nsid':2,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]},
    {'nsid':3,'size':1048576,'writable':True}]}]
elif t=='nvme_tcp_reservation':
  if e['nsid']==3 and e['host_nqn'].endswith('-b'):
    a=[{'type':'nvme_tcp_discovery_entries','subsystems':[]}]
  elif e['nsid']==3:
    a=[]
  elif e['operation']=='preempt_and_abort':
    a=[{'type':'nvme_tcp_refuse_reservation'}]
  else:
    a=[{'type':'nvme_tcp_allow_reservation'}]
else:
  a=[]
print(json.dumps({'actions':a}))"#;

fn block(text: &[u8], bs: usize) -> Vec<u8> {
    let mut b = text.to_vec();
    b.resize(bs, 0);
    b
}

/// An admin and an I/O queue for a host: (admin, io).
async fn host(port: u16, hostnqn: &str, hostid: &[u8; 16]) -> (Raw, Raw) {
    let mut admin = Raw::connect(port).await;
    let cntlid = admin.admin_session_as(SUBSYS, hostnqn, hostid).await;
    let mut io = Raw::connect(port).await;
    let c = io.io_session_as(cntlid, SUBSYS, hostnqn, hostid).await;
    assert!(c.ok(), "I/O Connect: {c:?}");
    (admin, io)
}

async fn compare(io: &mut Raw, nsid: u32, slba: u64, data: &[u8], bs: u32) -> Cqe {
    let sqe = Sqe::new(0x05, nsid)
        .range(slba, data.len() as u32 / bs)
        .in_capsule(data.len() as u32);
    io.cmd(&sqe, data).await.1
}

/// A command whose data the target asks for by R2T, sent in one H2CData per R2T.
async fn solicited(io: &mut Raw, sqe: Sqe, data: &[u8]) -> Cqe {
    let sqe = sqe.transport(data.len() as u32);
    let cid = io.capsule(&sqe, &[]).await;
    loop {
        let g = io.recv().await;
        match g.kind() {
            R2T => {
                let (ttag, off, len) = (
                    le16(&g.header, 10),
                    le32(&g.header, 12) as usize,
                    le32(&g.header, 16) as usize,
                );
                io.h2c(cid, ttag, off as u32, &data[off..off + len], true)
                    .await;
            }
            RESP => return g.cqe(),
            k => panic!("unexpected PDU {k:#x}"),
        }
    }
}

async fn verify(io: &mut Raw, nsid: u32, slba: u64, blocks: u32) -> Cqe {
    let sqe = Sqe::new(0x0C, nsid).range(slba, blocks).transport(0);
    io.cmd(&sqe, &[]).await.1
}

fn ranges(r: &[(u64, u32)]) -> Vec<u8> {
    let mut d = Vec::new();
    for (slba, blocks) in r {
        let mut e = [0u8; 32];
        e[8..16].copy_from_slice(&slba.to_le_bytes());
        e[16..18].copy_from_slice(&((blocks - 1) as u16).to_le_bytes());
        d.extend(e);
    }
    d
}

fn copy_sqe(nsid: u32, dest: u64, n: usize) -> Sqe {
    Sqe::new(0x19, nsid)
        .u64_at(40, dest)
        .cdw(12, (n - 1) as u32)
}

async fn copy(io: &mut Raw, nsid: u32, dest: u64, r: &[(u64, u32)]) -> Cqe {
    let d = ranges(r);
    io.cmd(
        &copy_sqe(nsid, dest, r.len()).in_capsule(d.len() as u32),
        &d,
    )
    .await
    .1
}

/// Reservation Register: action 0/1/2, IEKEY, CRKEY, NRKEY.
async fn register(io: &mut Raw, nsid: u32, action: u32, iekey: bool, cr: u64, nr: u64) -> Cqe {
    let mut d = cr.to_le_bytes().to_vec();
    d.extend(nr.to_le_bytes());
    let sqe = Sqe::new(0x0D, nsid)
        .cdw(10, action | (iekey as u32) << 3)
        .in_capsule(16);
    io.cmd(&sqe, &d).await.1
}

/// Reservation Acquire: action 0 acquire, 1 preempt, 2 preempt and abort.
async fn acquire(io: &mut Raw, nsid: u32, action: u32, rtype: u32, cr: u64, pr: u64) -> Cqe {
    let mut d = cr.to_le_bytes().to_vec();
    d.extend(pr.to_le_bytes());
    let sqe = Sqe::new(0x11, nsid)
        .cdw(10, action | rtype << 8)
        .in_capsule(16);
    io.cmd(&sqe, &d).await.1
}

/// Reservation Release: action 0 release, 1 clear.
async fn release(io: &mut Raw, nsid: u32, action: u32, rtype: u32, cr: u64) -> Cqe {
    let sqe = Sqe::new(0x15, nsid)
        .cdw(10, action | rtype << 8)
        .in_capsule(8);
    io.cmd(&sqe, &cr.to_le_bytes()).await.1
}

/// Reservation Report of `len` bytes, extended (EDS) or not.
async fn report(io: &mut Raw, nsid: u32, len: u32, eds: bool) -> (Vec<u8>, Cqe) {
    let sqe = Sqe::new(0x0E, nsid)
        .cdw(10, len / 4 - 1)
        .cdw(11, eds as u32)
        .transport(len);
    io.cmd(&sqe, &[]).await
}

/// (generation, type, registrants, [(CNTLID, holds, key, host id)]) of an extended report.
fn parse_report(b: &[u8]) -> (u32, u8, u16, Vec<(u16, u8, u64, [u8; 16])>) {
    let n = le16(b, 5);
    let entries = (0..n as usize)
        .map(|i| {
            let e = &b[64 + i * 64..128 + i * 64];
            (le16(e, 0), e[2], le64(e, 8), e[16..32].try_into().unwrap())
        })
        .collect();
    (le32(b, 0), b[4], n, entries)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compare_verify_and_copy_are_answered_from_the_namespace() {
    let srv = start(policy(CMD_POLICY), None).await;
    let (mut admin, mut io) = host(srv.port, HOST, &HOSTID).await;

    // What the controller and namespace say they support.
    let (id, _) = admin.identify(1, 0).await;
    assert_eq!(
        le16(&id, 520) & 0x1AD,
        0x1AD,
        "ONCS: Compare, DSM, Write Zeroes, Reservations, Verify, Copy"
    );
    assert_eq!(le16(&id, 534) & 1, 1, "OCFS: Copy format 0");
    let (ns, _) = admin.identify(0, 1).await;
    assert_eq!(ns[31], 0xFE, "RESCAP: types 1-6 and IEKEY");
    assert_eq!(le16(&ns, 74), 8192, "MSSRL: 4 MiB of 512-byte blocks");
    assert_eq!(le32(&ns, 76), 8192, "MCL");
    assert_eq!(ns[80], 127, "MSRC: 128 ranges");

    // Compare against the description.
    let first = block(b"hello from netget", 512);
    assert!(compare(&mut io, 1, 0, &first, 512).await.ok());
    let mut wrong = first.clone();
    wrong[3] ^= 0x20;
    let c = compare(&mut io, 1, 0, &wrong, 512).await;
    assert_eq!(c.sc(), COMPARE_FAILURE);
    assert!(c.dnr());
    // 16 KiB by R2T: the fill block and zeroes after it.
    let mut fill = vec![0xABu8; 512];
    fill.resize(16384, 0);
    assert!(solicited(&mut io, Sqe::new(0x05, 1).range(8, 32), &fill)
        .await
        .ok());
    fill[16383] = 1;
    assert_eq!(
        solicited(&mut io, Sqe::new(0x05, 1).range(8, 32), &fill)
            .await
            .sc(),
        COMPARE_FAILURE
    );
    // A medium error, and the controller's own writes.
    assert_eq!(
        compare(&mut io, 1, 1024, &[0u8; 512], 512).await.sc(),
        UNRECOVERED_READ
    );
    let written = block(b"written by the host", 512);
    assert!(io.write_in_capsule(1, 100, &written, 512).await.ok());
    assert!(compare(&mut io, 1, 100, &written, 512).await.ok());
    // A fused command is not supported.
    let mut fused = Sqe::new(0x05, 1).range(0, 1).in_capsule(512);
    fused.0[1] |= 0x01;
    assert_eq!(io.cmd(&fused, &first).await.1.sc(), INVALID_FIELD);

    // Verify: readable is all it checks.
    assert!(verify(&mut io, 1, 0, 32).await.ok());
    assert_eq!(verify(&mut io, 1, 1020, 8).await.sc(), UNRECOVERED_READ);
    assert_eq!(verify(&mut io, 1, 2047, 2).await.sc(), LBA_OUT_OF_RANGE);

    // Copy: two sources to one destination, then an overlapping copy.
    assert!(copy(&mut io, 1, 200, &[(0, 1), (8, 1)]).await.ok());
    let (d, _) = io.read(1, 200, 2, 512).await;
    assert_eq!(&d[..512], first.as_slice());
    assert!(d[512..].iter().all(|b| *b == 0xAB));
    assert!(copy(&mut io, 1, 201, &[(200, 2)]).await.ok());
    let (d, _) = io.read(1, 200, 3, 512).await;
    assert_eq!(&d[..512], first.as_slice(), "block 200 unchanged");
    assert_eq!(&d[512..1024], first.as_slice(), "block 201 is the old 200");
    assert!(
        d[1024..].iter().all(|b| *b == 0xAB),
        "block 202 is the old 201"
    );
    // By R2T.
    let d = ranges(&[(100, 1)]);
    assert!(solicited(&mut io, copy_sqe(1, 300, 1), &d).await.ok());
    let (d, _) = io.read(1, 300, 1, 512).await;
    assert_eq!(d, written);
    // Refusals.
    assert_eq!(copy(&mut io, 2, 10, &[(0, 1)]).await.sc(), WRITE_PROTECTED);
    assert_eq!(
        copy(&mut io, 1, 0, &[(0, 8193)]).await.sc(),
        SIZE_LIMIT,
        "past MSSRL"
    );
    assert_eq!(
        copy(&mut io, 1, 0, &[(0, 5000), (0, 5000)]).await.sc(),
        SIZE_LIMIT,
        "past MCL"
    );
    let many: Vec<(u64, u32)> = (0..129).map(|i| (i, 1)).collect();
    assert_eq!(
        copy(&mut io, 1, 400, &many).await.sc(),
        SIZE_LIMIT,
        "past MSRC"
    );
    assert_eq!(
        copy(&mut io, 1, 0, &[(1020, 8)]).await.sc(),
        UNRECOVERED_READ
    );
    assert_eq!(
        copy(&mut io, 1, 2047, &[(0, 2)]).await.sc(),
        LBA_OUT_OF_RANGE
    );
    assert_eq!(
        copy(&mut io, 1, 0, &[(2047, 2)]).await.sc(),
        LBA_OUT_OF_RANGE
    );
    let d = ranges(&[(0, 1)]);
    let mut sqe = copy_sqe(1, 0, 1).in_capsule(32);
    sqe = sqe.cdw(12, 1 << 8);
    assert_eq!(
        io.cmd(&sqe, &d).await.1.sc(),
        INVALID_FIELD,
        "descriptor format 1"
    );

    // tshark reads the opcodes.
    io.oracle().also_named("nvme").assert_clean();
    let ops: Vec<u64> = tshark_values(&io, "nvme.cmd.opc")
        .iter()
        .filter_map(|v| number(v))
        .collect();
    for op in [0x05, 0x0C, 0x19] {
        assert!(ops.contains(&op), "tshark reads opcode {op:#x}: {ops:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reservations_follow_the_rules_and_the_models_decisions() {
    let srv = start(policy(CMD_POLICY), None).await;
    let (_a_admin, mut a) = host(srv.port, HOST, &HOSTID).await;
    let (_b_admin, mut b) = host(srv.port, HOST_B, &HOSTID_B).await;
    let data = block(b"from a", 512);
    let resv_events = || async { events(&srv.state, srv.id, "nvme_tcp_reservation").await };

    // A registers; the same key again changes nothing, another key conflicts. Only the change
    // reached the model.
    assert!(register(&mut a, 1, 0, false, 0, 0xA1).await.ok());
    assert!(register(&mut a, 1, 0, false, 0, 0xA1).await.ok());
    assert_eq!(
        register(&mut a, 1, 0, false, 0, 0xA2).await.sc(),
        RESERVATION_CONFLICT
    );
    assert_eq!(resv_events().await.len(), 1);
    // A takes a Write Exclusive reservation (with the wrong key first).
    assert_eq!(
        acquire(&mut a, 1, 0, 1, 0xFF, 0).await.sc(),
        RESERVATION_CONFLICT
    );
    assert!(acquire(&mut a, 1, 0, 1, 0xA1, 0).await.ok());
    assert!(
        acquire(&mut a, 1, 0, 1, 0xA1, 0).await.ok(),
        "acquiring what it holds"
    );
    assert_eq!(resv_events().await.len(), 2);

    // B reads and compares; it may not write, zero, copy or flush.
    assert!(b.read(1, 0, 1, 512).await.1.ok());
    assert!(
        compare(&mut b, 1, 0, &block(b"hello from netget", 512), 512)
            .await
            .ok()
    );
    assert_eq!(
        b.write_in_capsule(1, 50, &data, 512).await.sc(),
        RESERVATION_CONFLICT
    );
    let wz = Sqe::new(0x08, 1).range(50, 1);
    assert_eq!(b.cmd(&wz, &[]).await.1.sc(), RESERVATION_CONFLICT);
    assert_eq!(
        copy(&mut b, 1, 60, &[(0, 1)]).await.sc(),
        RESERVATION_CONFLICT
    );
    assert_eq!(
        b.cmd(&Sqe::new(0x00, 1), &[]).await.1.sc(),
        RESERVATION_CONFLICT
    );
    // The other namespace is not reserved; the holder writes.
    assert!(b.write_in_capsule(3, 50, &data, 512).await.ok());
    assert!(a.write_in_capsule(1, 50, &data, 512).await.ok());

    // The report: fabrics need the extended structure.
    assert_eq!(
        report(&mut a, 1, 4096, false).await.1.sc(),
        HOST_ID_INCONSISTENT
    );
    let (r, c) = report(&mut a, 1, 4096, true).await;
    assert!(c.ok());
    let (generation, rtype, n, entries) = parse_report(&r);
    assert_eq!((rtype, n), (1, 1));
    assert!(generation >= 1);
    assert_eq!(entries[0], (0xFFFF, 1, 0xA1, HOSTID));

    // B registers; under Write Exclusive only the holder writes, and B cannot acquire.
    assert!(register(&mut b, 1, 0, false, 0, 0xB2).await.ok());
    assert_eq!(
        b.write_in_capsule(1, 50, &data, 512).await.sc(),
        RESERVATION_CONFLICT
    );
    assert_eq!(
        acquire(&mut b, 1, 0, 1, 0xB2, 0).await.sc(),
        RESERVATION_CONFLICT
    );
    // The model refuses B's preempt-and-abort: nothing changes.
    assert_eq!(
        acquire(&mut b, 1, 2, 3, 0xB2, 0xA1).await.sc(),
        RESERVATION_CONFLICT
    );
    let (r, _) = report(&mut b, 1, 4096, true).await;
    let (_, rtype, n, entries) = parse_report(&r);
    assert_eq!((rtype, n), (1, 2));
    assert!(
        entries.iter().any(|e| e.3 == HOSTID && e.1 == 1),
        "A still holds it"
    );
    // It allows B's preempt: B holds a Write Exclusive - Registrants Only reservation and A's
    // registration is gone.
    assert!(acquire(&mut b, 1, 1, 3, 0xB2, 0xA1).await.ok());
    let (r, _) = report(&mut b, 1, 4096, true).await;
    let (_, rtype, n, entries) = parse_report(&r);
    assert_eq!((rtype, n), (3, 1));
    assert_eq!(entries[0], (0xFFFF, 1, 0xB2, HOSTID_B));
    assert_eq!(
        a.write_in_capsule(1, 50, &data, 512).await.sc(),
        RESERVATION_CONFLICT
    );
    assert!(a.read(1, 0, 1, 512).await.1.ok());
    assert!(b.write_in_capsule(1, 50, &data, 512).await.ok());
    // Release with the wrong type is INVALID FIELD; with the right one the namespace is free.
    assert_eq!(release(&mut b, 1, 0, 1, 0xB2).await.sc(), INVALID_FIELD);
    assert!(release(&mut b, 1, 0, 3, 0xB2).await.ok());
    assert!(a.write_in_capsule(1, 50, &data, 512).await.ok());
    // Replace, unregister with the wrong key, clear.
    assert!(register(&mut b, 1, 2, false, 0xB2, 0xB3).await.ok());
    assert_eq!(
        register(&mut b, 1, 1, false, 0xB2, 0).await.sc(),
        RESERVATION_CONFLICT
    );
    assert!(release(&mut b, 1, 1, 0, 0xB3).await.ok());
    let (r, _) = report(&mut a, 1, 4096, true).await;
    assert_eq!(parse_report(&r).2, 0, "cleared");

    let e = resv_events().await;
    let ops: Vec<&str> = e.iter().map(|e| e["operation"].as_str().unwrap()).collect();
    assert_eq!(
        ops,
        [
            "register",
            "acquire",
            "register",
            "preempt_and_abort",
            "preempt",
            "release",
            "replace",
            "clear"
        ],
        "each change, and only changes, reached the model"
    );
    assert_eq!(e[1]["type"], "write_exclusive");
    assert_eq!(e[4]["holder"]["type"], "write_exclusive");
    assert!(e[4]["effect"].as_str().unwrap().contains("preempts"));

    // Fail closed: a silent model and an answer that is not a decision change nothing.
    let c = register(&mut a, 3, 0, false, 0, 0xC1).await;
    assert_eq!(c.sc(), INTERNAL_ERROR);
    assert!(c.dnr());
    assert_eq!(
        register(&mut b, 3, 0, false, 0, 0xC2).await.sc(),
        INTERNAL_ERROR
    );
    let (r, _) = report(&mut a, 3, 4096, true).await;
    assert_eq!(parse_report(&r).2, 0, "nothing registered on namespace 3");

    // The table goes with the subsystem's last controller.
    assert!(register(&mut a, 1, 0, false, 0, 0xA1).await.ok());
    drop((a, b, _a_admin, _b_admin));
    // The old queues close as the target reads their end; a new association made after that
    // finds no registrations.
    let mut registered = u16::MAX;
    for _ in 0..100 {
        let (_c_admin, mut c) = host(srv.port, HOST, &HOSTID).await;
        let (r, _) = report(&mut c, 1, 4096, true).await;
        registered = parse_report(&r).2;
        if registered == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        registered, 0,
        "a new association starts with no registrations"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_registrant_table_is_bounded() {
    let srv = start(policy(CMD_POLICY), None).await;
    let (_keep_admin, mut keep) = host(srv.port, HOST, &HOSTID).await;
    assert!(register(&mut keep, 1, 0, false, 0, 1).await.ok());
    for i in 0..63u8 {
        let mut id = [0x40u8; 16];
        id[15] = i;
        let nqn = format!("nqn.2026-10.org.example:bound-{i}");
        let (_admin, mut io) = host(srv.port, &nqn, &id).await;
        assert!(
            register(&mut io, 1, 0, false, 0, 100 + i as u64).await.ok(),
            "registrant {}",
            i + 2
        );
    }
    let mut id = [0x41u8; 16];
    id[15] = 0xFF;
    let (_admin, mut io) = host(srv.port, "nqn.2026-10.org.example:bound-65", &id).await;
    assert_eq!(
        register(&mut io, 1, 0, false, 0, 999).await.sc(),
        RESERVATION_CONFLICT,
        "the 65th registrant"
    );
    let (r, _) = report(&mut keep, 1, 8192, true).await;
    assert_eq!(parse_report(&r).2, 64);
}
