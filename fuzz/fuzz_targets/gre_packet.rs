//! `netget::utils::gre` — the GRE header codec (RFC 2784 with RFC 2890's key and sequence
//! number) shared by `gre` on IP protocol 47 and vxlan's GRE-in-UDP, and what each hands its
//! payload to: `frame::parse_frame` (gretap, 0x6558), `frame::parse_ipv4_packet` (gre,
//! 0x0800), and the `gre` server's keepalive check.
//!
//! All of it is reachable before any authentication: a raw protocol-47 socket takes whatever
//! any host sends to the address, and the peer allowlist is optional. GRE does not nest in
//! anything here (a keepalive's inner GRE header is decoded once, never recursively), so there
//! is no depth bomb; what a peer controls is the flags that announce optional fields, and the
//! lengths of the inner IPv4 and UDP headers. The seeds sit on each.
//!
//! Beyond not crashing, a decoded header must re-encode to a packet that decodes to the same
//! header and payload: the checksum the encoder writes has to verify.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::gre::keepalive;
use netget::server::vxlan::frame;
use netget::utils::gre;
use std::net::Ipv4Addr;

const US: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

fuzz_target!(|data: &[u8]| {
    if let Ok((header, payload)) = gre::decode(data) {
        let again = gre::encode(&header, payload);
        let (back, back_payload) = gre::decode(&again).expect("a re-encoded packet decodes");
        assert_eq!(back, header);
        assert_eq!(back_payload, payload);
        match header.protocol {
            gre::PROTO_TEB => {
                let _ = frame::parse_frame(payload);
            }
            gre::PROTO_IPV4 => {
                let _ = keepalive(payload, PEER, US);
                let _ = frame::parse_ipv4_packet(payload);
            }
            _ => {}
        }
    }
    // Stamping is infallible by signature: any length, any flags.
    let mut copy = data.to_vec();
    if gre::stamp_sequence(&mut copy, 0x0102_0304) && gre::decode(data).is_ok() {
        let (h, _) = gre::decode(&copy).expect("a stamped packet still decodes");
        assert_eq!(h.sequence, Some(0x0102_0304));
    }
    let _ = keepalive(data, PEER, US);
});
