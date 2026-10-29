//! `netget::server::nvme_tcp` — everything the NVMe/TCP target and host run on what a peer
//! sends: PDU framing in both directions (the common header checked before anything else is
//! believed, with and without CRC32C digests), the 64-byte submission queue entries and Connect
//! data a target decodes, the completions a host decodes, and the data structures a host reads
//! back (Identify Controller and Namespace, the active namespace list, namespace identification
//! descriptors, the discovery log page and its entries, the SMART / health log), the
//! DH-HMAC-CHAP messages of Authentication Send and Receive and the `DHHC-1` secret text, the
//! reservation commands' data and the Reservation Report, Copy's source ranges, and the TLS
//! secure channel's `NVMeTLSkey-1` key text and the PSK identity a host sends in its ClientHello,
//! which the target parses before any key has been agreed.
//!
//! What parses is checked to stay within its bound: a decoded PDU's data never longer than the
//! limit it was read under nor than its PLEN claims, a namespace list never more than 1024
//! IDs, a descriptor walk never more than 64 entries, an authentication message's values never
//! longer than the buffer (and anything decoded encodes to something that decodes), a report
//! never more entries than REGCTL. The input also drives the reservation rules
//! (`resv::Table::apply`) through a sequence of operations, and the table must keep its
//! invariants whatever the sequence. None of these decoders recurses, so the corpus carries the
//! long and repetitive inputs instead: a train of back-to-back H2CData PDUs, a PLEN claiming a
//! gigabyte, `depth_bomb`, a descriptor list of thousands of one-byte entries that a recursive
//! walker would descend through one by one, and `auth_long_values`, a challenge whose HL and
//! DHVLEN claim far more than it carries.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::nvme_tcp::{auth, nvme, pdu, resv, tls_psk};

fuzz_target!(|data: &[u8]| {
    let target_side = pdu::Limits::types(&[
        pdu::kind::CAPSULE_CMD,
        pdu::kind::H2C_DATA,
        pdu::kind::H2C_TERM_REQ,
    ]);
    let host_side = pdu::Limits::types(&[
        pdu::kind::CAPSULE_RESP,
        pdu::kind::C2H_DATA,
        pdu::kind::R2T,
        pdu::kind::C2H_TERM_REQ,
    ]);
    let handshake = pdu::Limits::types(&[pdu::kind::IC_REQ, pdu::kind::IC_RESP]);
    for accepted in [target_side, host_side, handshake] {
        for digests in [
            pdu::Digests::default(),
            pdu::Digests {
                header: true,
                data: true,
            },
        ] {
            let limits = pdu::Limits {
                accepted,
                digests,
                max_capsule_data: 8192,
                max_data_pdu: 128 * 1024,
            };
            let mut rest = data;
            for _ in 0..64 {
                match pdu::decode(rest, &limits) {
                    Ok(Some((p, used))) => {
                        assert!(used > 0 && used <= rest.len());
                        assert!(p.data.len() <= limits.max_data_pdu.max(8192));
                        assert!(p.header.len() == pdu::kind::hlen(p.kind()).unwrap());
                        payload(&p);
                        rest = &rest[used..];
                    }
                    Ok(None) => break,
                    Err(pdu::ReadError::Fatal(e, header)) => {
                        assert!(e.fes >= 1 && e.fes <= 6);
                        assert!(header.len() <= 128);
                        let term = pdu::term_req(pdu::kind::C2H_TERM_REQ, &e, &header);
                        assert!(term.data.len() <= pdu::TERM_REQ_MAX_DATA);
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    // The data on its own, as each structure a host decodes.
    structures(data);
});

fn payload(p: &pdu::Pdu) {
    match p.kind() {
        pdu::kind::CAPSULE_CMD => {
            let sqe = nvme::Sqe(p.header[8..72].try_into().unwrap());
            let _ = (sqe.sgl(), sqe.lba_range(), sqe.fctype(), sqe.psdt());
            for admin_queue in [true, false] {
                assert!(!nvme::command_name(admin_queue, &sqe).is_empty());
            }
            let _ = auth::command_fields(&sqe);
            if sqe.opcode() == nvme::admin::FABRICS && sqe.fctype() == nvme::fctype::AUTH_SEND {
                auth_message(&p.data);
            }
            match sqe.opcode() {
                nvme::io::RESV_REGISTER => reservation(resv::Op::register(sqe.cdw(10), &p.data)),
                nvme::io::RESV_ACQUIRE => reservation(resv::Op::acquire(sqe.cdw(10), &p.data)),
                nvme::io::RESV_RELEASE => reservation(resv::Op::release(sqe.cdw(10), &p.data)),
                nvme::io::COPY => {
                    let ranges = nvme::copy_ranges(&p.data);
                    assert!(
                        ranges.len() <= 256 && ranges.len() <= p.data.len() / nvme::COPY_RANGE_LEN
                    );
                    assert!(ranges.iter().all(|r| (1..=65536).contains(&r.1)));
                }
                _ => {}
            }
            if let Some(c) = nvme::ConnectRequest::decode(&sqe, &p.data) {
                if let Ok(n) = &c.subnqn {
                    assert!(nvme::valid_nqn(n));
                }
                if let Ok(n) = &c.hostnqn {
                    assert!(n.len() <= nvme::MAX_NQN);
                }
                let _ = nvme::uuid_text(&c.hostid);
            }
        }
        pdu::kind::CAPSULE_RESP => {
            let c = nvme::Cqe::decode(&p.header[8..24]).unwrap();
            let _ = c.status().describe();
            let _ = c.result64();
        }
        _ => structures(&p.data),
    }
}

fn structures(d: &[u8]) {
    let _ = nvme::ControllerInfo::decode(d).map(|c| c.controller_type());
    if let Some(n) = nvme::NamespaceInfo::decode(d) {
        assert!(n.block_size == 0 || n.block_size.is_power_of_two());
    }
    assert!(nvme::parse_ns_list(d).len() <= 1024);
    assert!(nvme::parse_ns_descriptors(d).len() <= 64);
    let _ = nvme::discovery_header(d);
    for e in d
        .chunks_exact(nvme::DISCOVERY_RECORD_LEN)
        .filter_map(nvme::DiscoveryEntry::decode)
    {
        let _ = (e.trtype_name(), e.adrfam_name(), e.subtype_name());
        // Characters, not bytes: a byte that is not UTF-8 is shown as U+FFFD, three bytes long.
        assert!(e.subnqn.chars().count() <= 256 && e.traddr.chars().count() <= 256);
    }
    let _ = nvme::Smart::decode(d);
    let _ = nvme::text_field(&d[..d.len().min(256)]);
    // DH-HMAC-CHAP: every message both roles decode, and the secret text a startup parameter
    // carries.
    auth_message(d);
    if let Ok(text) = std::str::from_utf8(d) {
        if let Ok(s) = auth::Secret::parse(text) {
            assert!(matches!(s.len(), 32 | 48 | 64));
            let _ = s.transformed("nqn.2026-10.net.netget:fuzz");
        }
        // The TLS key text, and an identity as the target receives it: whatever parses must
        // name a hash the key could have and print back as itself.
        if let Ok(k) = tls_psk::ConfiguredKey::parse(text) {
            assert!(matches!(k.retained("nqn.2026-10.net.netget:fuzz").len(), 32 | 48));
        }
        let fixed = tls_psk::ConfiguredKey::parse(&tls_psk::ConfiguredKey::text(&[7; 32], None))
            .expect("a key of NetGet's own making parses");
        if let Ok((id, psk)) = tls_psk::target_psk(&fixed, text) {
            assert_eq!((id.text(), psk.len()), (text.to_string(), 32));
        }
        if let Ok(id) = tls_psk::Identity::parse(text) {
            assert_eq!(id.text(), text, "an identity prints back as it parsed");
        }
    }
    // A Reservation Report as a host reads it: never more entries than REGCTL or the buffer.
    if let Some(r) = resv::Report::decode(d) {
        assert!(r.entries.len() <= r.registered as usize);
        assert!(r.entries.len() <= (d.len() - resv::REPORT_HEADER) / resv::REPORT_ENTRY);
    }
    reservation_rules(d);
}

/// An authentication message: what decodes is bounded by what was given, and can be sent back.
fn auth_message(d: &[u8]) {
    let Ok(m) = auth::Message::decode(d) else {
        return;
    };
    match &m {
        auth::Message::Negotiate(n) => {
            assert!(n.hashes.len() <= auth::MAX_IDS && n.groups.len() <= auth::MAX_IDS);
        }
        auth::Message::Challenge(c) => {
            assert_eq!(c.cval.len(), c.hl as usize);
            assert!(16 + c.cval.len() + c.dhv.len() <= d.len());
        }
        auth::Message::Reply(r) => {
            assert!(r.rval.len() == r.hl as usize && r.cval.len() == r.hl as usize);
            assert!(16 + 2 * r.rval.len() + r.dhv.len() <= d.len());
        }
        auth::Message::Success1(s) => assert!(s.rval.len() <= d.len()),
        _ => {}
    }
    let again = auth::Message::decode(&m.encode());
    assert!(again.is_ok(), "{} does not decode once encoded", m.name());
}

/// A reservation command decoded from a capsule: an Ok is one of the operations it names.
fn reservation(op: Result<resv::Op, nvme::Status>) {
    if let Ok(op) = op {
        let _ = op.name();
        if let Some(t) = op.rtype() {
            assert!((1..=6).contains(&t) || matches!(op, resv::Op::Release { .. }));
        }
    }
}

/// The reservation rules driven by the input: each 19 bytes are a host (1 byte, of 8), an
/// operation (1 byte) and two keys. Whatever the sequence, the table keeps its invariants: at
/// most 64 registrants, each host once, a holder that is registered, and a refused operation
/// changes nothing.
fn reservation_rules(d: &[u8]) {
    let mut t = resv::Table::default();
    for c in d.chunks_exact(19).take(512) {
        let host = [c[0] % 8; 16];
        let k1 = u64::from_le_bytes(c[3..11].try_into().unwrap()) % 4;
        let k2 = u64::from_le_bytes(c[11..19].try_into().unwrap()) % 4;
        let rt = 1 + c[2] % 6;
        let op = match c[1] % 7 {
            0 => resv::Op::Register { new_key: k1 },
            1 => resv::Op::Unregister {
                key: k1,
                ignore_key: c[2] & 0x80 != 0,
            },
            2 => resv::Op::Replace {
                key: k1,
                new_key: k2,
                ignore_key: c[2] & 0x80 != 0,
            },
            3 => resv::Op::Acquire { key: k1, rtype: rt },
            4 => resv::Op::Preempt {
                key: k1,
                preempt_key: k2,
                rtype: rt,
                abort: c[2] & 0x80 != 0,
            },
            5 => resv::Op::Release { key: k1, rtype: rt },
            _ => resv::Op::Clear { key: k1 },
        };
        let before = t.clone();
        if t.apply(host, &op).is_err() {
            assert_eq!(t, before, "a refused {} changed the table", op.name());
        }
        assert!(t.registrants.len() <= resv::MAX_REGISTRANTS);
        for (i, r) in t.registrants.iter().enumerate() {
            assert!(t.registrants[..i].iter().all(|o| o.hostid != r.hostid));
        }
        if let Some((h, _)) = t.holder {
            assert!(t.registered(&h), "the holder is registered");
        }
        for h in 0..8u8 {
            let _ = (t.allows(&[h; 16], true), t.allows(&[h; 16], false));
        }
    }
}
