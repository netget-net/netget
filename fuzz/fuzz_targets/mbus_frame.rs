//! `netget::server::mbus` — every decoder the M-Bus slave and master run on what a peer sends:
//! the link-layer frame parser (single character, short, control and long frames, checksum,
//! stop byte, resynchronisation past garbage), the variable data header, and the DIF/DIFE/
//! VIF/VIFE record walk in every coding (integers, BCD with its sign nibble, reals, dates,
//! LVAR text and numbers, plain-text units, the 0xFB/0xFD extension tables).
//!
//! What parses is checked to re-encode to the same bytes, and the parser never claims more
//! bytes than it was given. Nothing here recurses: DIFE and VIFE chains are loops bounded at
//! ten, so the corpus carries the long walks instead — a record at both chain bounds
//! (`dife_vife_chains`), a telegram at the 64-record bound (`max_records`), and a long frame
//! whose L field is the largest one byte allows (`max_l`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::mbus::{frame, records};

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while !rest.is_empty() {
        match frame::parse(rest) {
            frame::Parsed::Incomplete(n) => {
                assert!(n > 0 && rest.len() + n <= frame::MAX_FRAME_LEN);
                break;
            }
            frame::Parsed::Invalid { skip, .. } => {
                assert!(skip > 0 && skip <= frame::MAX_FRAME_LEN);
                rest = &rest[skip.min(rest.len())..];
            }
            frame::Parsed::Frame(f, used) => {
                assert!(used > 0 && used <= rest.len() && used <= frame::MAX_FRAME_LEN);
                let again = f.encode().expect("a parsed frame encodes");
                assert_eq!(&again[..], &rest[..used], "encode changed a parsed frame");
                if let (Some(ci), data) = (f.ci(), f.data()) {
                    if let Ok((h, d)) = records::decode_response(ci, data) {
                        assert!(d.records.len() <= records::MAX_RECORDS_PER_TELEGRAM);
                        let _ = records::header_json(&h);
                    }
                    let _ = records::decode_records(data);
                }
                rest = &rest[used..];
            }
        }
    }
    let d = records::decode_records(data);
    if let Ok(d) = d {
        assert!(d.records.len() <= records::MAX_RECORDS_PER_TELEGRAM);
    }
    if data.len() >= 8 {
        let mut mask = [0u8; 8];
        mask.copy_from_slice(&data[..8]);
        if let Ok(a) = frame::SecondaryAddress::from_bytes(&data[..8]) {
            assert!(a.matches(&a.bytes()), "an address must match itself");
            assert!(
                a.matches(&[0xFF; 8]),
                "the all-wildcard mask matches everything"
            );
            let _ = a.matches(&mask);
        }
    }
});
