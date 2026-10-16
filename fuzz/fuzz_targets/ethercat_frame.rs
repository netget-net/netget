//! `netget::server::ethercat` — every decoder the EtherCAT slave and master run on what a peer
//! sends: the Ethernet framing around an EtherCAT payload, the frame header and its chain of
//! datagrams, the emulated ESC processing arbitrary datagrams (register and process memory
//! writes, SyncManager and FMMU programming, AL control, the SII interface, logical commands),
//! the mailbox header, CoE SDO requests and responses and the SDO server answering them, and
//! the SII parser a master reads a slave's EEPROM with.
//!
//! What round-trips is checked to round-trip, and processing must never change a frame's
//! length or the commands in it. Nothing here recurses; the corpus carries the inputs that make
//! the walks long instead — a frame at the 64-datagram bound (`max_datagrams`), a header that
//! declares more than it carries (`length_lie`), and an SII whose category chain runs to its
//! bound (`sii_chain`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::ethercat::{coe, device, esc, frame, sdo, sii};

fuzz_target!(|data: &[u8]| {
    let _ = frame::ethernet_payload_offset(data);
    if let Ok(ds) = frame::decode(data) {
        let again = frame::encode(&ds).expect("decoded datagrams encode");
        assert_eq!(
            frame::decode(&again).expect("re-encoded frame decodes"),
            ds,
            "encode then decode changed the datagrams"
        );
        let mut chain: Vec<esc::Esc> = (0..2)
            .map(|i| esc::Esc::new(i, 2, device::default_device(i), sii::DEFAULT_MAILBOX))
            .collect();
        let mut buf = data.to_vec();
        esc::process_frame(&mut chain, &mut buf).expect("a frame that decodes is processed");
        assert_eq!(
            buf.len(),
            data.len(),
            "processing changed the frame's length"
        );
        let after = frame::decode(&buf).expect("a processed frame still decodes");
        assert_eq!(after.len(), ds.len());
        for (a, b) in after.iter().zip(&ds) {
            assert_eq!((a.cmd, a.idx, a.data.len()), (b.cmd, b.idx, b.data.len()));
        }
        for e in chain.iter_mut() {
            let _ = e.take_events();
        }
    }
    if let Ok(m) = coe::Mailbox::parse(data) {
        let enc = m.encode(0);
        assert_eq!(
            coe::Mailbox::parse(&enc).expect("re-encoded mailbox parses"),
            m
        );
        if let Ok(req) = coe::parse_request(&m.data) {
            let dev = device::default_device(0);
            let mut server = sdo::SdoServer::default();
            let _ = server.handle(&dev, req, sii::DEFAULT_MAILBOX, &[1], &[2]);
        }
        let _ = coe::parse_response(&m.data);
    }
    let _ = coe::parse_request(data);
    let _ = coe::parse_response(data);
    if sii::chain_end(data).is_ok() {
        if let Ok(info) = sii::parse(data) {
            let _ = sii::image_of(&info.txpdos);
            let _ = sii::image_of(&info.rxpdos);
        }
    }
});
