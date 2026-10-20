//! `netget::server::nvme_tcp` — everything the NVMe/TCP target and host run on what a peer
//! sends: PDU framing in both directions (the common header checked before anything else is
//! believed, with and without CRC32C digests), the 64-byte submission queue entries and Connect
//! data a target decodes, the completions a host decodes, and the data structures a host reads
//! back (Identify Controller and Namespace, the active namespace list, namespace identification
//! descriptors, the discovery log page and its entries, the SMART / health log).
//!
//! What parses is checked to stay within its bound: a decoded PDU's data never longer than the
//! limit it was read under nor than its PLEN claims, a namespace list never more than 1024
//! IDs, a descriptor walk never more than 64 entries. None of these decoders recurses, so the
//! corpus carries the long and repetitive inputs instead: a train of back-to-back H2CData
//! PDUs, a PLEN claiming a gigabyte, and `depth_bomb`, a descriptor list of thousands of
//! one-byte entries that a recursive walker would descend through one by one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::nvme_tcp::{nvme, pdu};

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
}
