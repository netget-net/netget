//! The GRE codec shared by `gre` and vxlan's gretap (`netget::utils::gre`), and the server's
//! keepalive check, without a socket: runs anywhere, unprivileged. Each refusal is a packet
//! that would otherwise decode; each check was removed once to watch the test fail.
use netget::server::gre::keepalive;
use netget::server::vxlan::frame;
use netget::utils::gre::{self, Header};
use std::net::Ipv4Addr;

const PAYLOAD: &[u8] = b"\x45an inner packet, any bytes";

fn all_headers(protocol: u16) -> Vec<Header> {
    let mut out = Vec::new();
    for key in [None, Some(0), Some(0xdead_beef)] {
        for checksum in [false, true] {
            for sequence in [None, Some(0), Some(u32::MAX)] {
                out.push(Header {
                    protocol,
                    key,
                    checksum,
                    sequence,
                });
            }
        }
    }
    out
}

#[test]
fn every_combination_of_fields_round_trips() {
    for protocol in [gre::PROTO_TEB, gre::PROTO_IPV4, gre::PROTO_KEEPALIVE] {
        for h in all_headers(protocol) {
            let packet = gre::encode(&h, PAYLOAD);
            let expected_len = 4
                + 4 * usize::from(h.checksum)
                + 4 * usize::from(h.key.is_some())
                + 4 * usize::from(h.sequence.is_some());
            assert_eq!(packet.len(), expected_len + PAYLOAD.len(), "{h:?}");
            let (back, payload) = gre::decode(&packet).unwrap_or_else(|e| panic!("{h:?}: {e}"));
            assert_eq!((back, payload), (h, PAYLOAD), "{h:?}");
        }
    }
}

/// The RFC 2784 byte layout, written out by hand: C, K and S set; checksum, then key, then
/// sequence number; the checksum is the one's complement of the sum over the whole packet.
#[test]
fn the_layout_is_rfc_2784_and_2890() {
    let h = Header {
        protocol: 0x0800,
        key: Some(0x0102_0304),
        checksum: true,
        sequence: Some(0x0a0b_0c0d),
    };
    let p = gre::encode(&h, b"");
    assert_eq!(p[0], 0x80 | 0x20 | 0x10);
    assert_eq!(p[1], 0);
    assert_eq!(&p[2..4], &[0x08, 0x00]);
    assert_eq!(&p[6..8], &[0, 0], "reserved1");
    assert_eq!(&p[8..12], &[1, 2, 3, 4]);
    assert_eq!(&p[12..16], &[0x0a, 0x0b, 0x0c, 0x0d]);
    // Sum of 16-bit words: 0xb000 + 0x0800 + 0x0102 + 0x0304 + 0x0a0b + 0x0c0d.
    let sum: u32 = 0xb000 + 0x0800 + 0x0102 + 0x0304 + 0x0a0b + 0x0c0d;
    let folded = ((sum & 0xffff) + (sum >> 16)) as u16;
    assert_eq!(u16::from_be_bytes([p[4], p[5]]), !folded);
}

#[test]
fn malformed_packets_are_refused() {
    let full = Header {
        protocol: gre::PROTO_TEB,
        key: Some(7),
        checksum: true,
        sequence: Some(3),
    };
    let good = gre::encode(&full, PAYLOAD);
    assert!(gre::decode(&good).is_ok());
    let refused = |what: &str, p: &[u8], needle: &str| {
        let e = gre::decode(p).expect_err(what).to_string();
        assert!(e.contains(needle), "{what}: {e}");
    };
    let mut version1 = gre::encode(&Header::default(), PAYLOAD);
    version1[1] |= 1;
    refused("version 1", &version1, "version 1");
    for bit in [0x40, 0x08, 0x04] {
        let mut p = gre::encode(&Header::default(), PAYLOAD);
        p[0] |= bit;
        refused("an RFC 1701 bit", &p, "RFC 1701");
    }
    refused("three bytes", &good[..3], "no GRE header");
    refused("inside the checksum", &good[..6], "checksum");
    refused("inside the key", &good[..10], "key");
    refused("inside the sequence number", &good[..14], "sequence number");
    let mut bad_sum = good.clone();
    bad_sum[5] ^= 1;
    refused("a checksum one bit off", &bad_sum, "bad GRE checksum");
    let mut bad_payload = good.clone();
    *bad_payload.last_mut().unwrap() ^= 0x80;
    refused(
        "a payload changed under its checksum",
        &bad_payload,
        "bad GRE checksum",
    );
    // A checksum of zero is a checksum, not an absent one.
    let mut zero = good.clone();
    zero[4..6].copy_from_slice(&[0, 0]);
    refused("a zero checksum", &zero, "bad GRE checksum");
}

#[test]
fn stamping_a_sequence_number_keeps_the_checksum_right() {
    for h in all_headers(gre::PROTO_IPV4) {
        let mut p = gre::encode(&h, PAYLOAD);
        let stamped = gre::stamp_sequence(&mut p, 0x0102_0304);
        assert_eq!(stamped, h.sequence.is_some(), "{h:?}");
        let (back, payload) = gre::decode(&p).unwrap_or_else(|e| panic!("{h:?}: {e}"));
        assert_eq!(payload, PAYLOAD);
        assert_eq!(
            back.sequence,
            h.sequence.map(|_| 0x0102_0304),
            "{h:?} stamped"
        );
    }
    assert!(!gre::stamp_sequence(&mut [0x10, 0, 8, 0], 1), "truncated");
}

/// A Cisco keepalive as a router sends it: through the tunnel (outer src = peer, outer dst =
/// us), an IPv4 packet from us back to the peer carrying a bare GRE header.
fn keepalive_packet(src: Ipv4Addr, dst: Ipv4Addr, inner_gre: &[u8]) -> Vec<u8> {
    frame::ipv4(src, dst, gre::IP_PROTOCOL, 1, inner_gre)
}

#[test]
fn only_a_keepalive_back_to_its_sender_is_reflected() {
    let (us, peer, other) = (
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(198, 18, 0, 2),
        Ipv4Addr::new(203, 0, 113, 9),
    );
    let bare = gre::encode(
        &Header {
            protocol: gre::PROTO_KEEPALIVE,
            ..Default::default()
        },
        &[],
    );
    let ok = keepalive_packet(us, peer, &bare);
    assert_eq!(keepalive(&ok, peer, us), Some((peer, &bare[..])));
    // Addressed to someone else: reflecting it would let anyone use us to send GRE there.
    assert_eq!(
        keepalive(&keepalive_packet(us, other, &bare), peer, us),
        None
    );
    // Not from our address: our kernel would write a different source than it claims.
    assert_eq!(
        keepalive(&keepalive_packet(other, peer, &bare), peer, us),
        None
    );
    // Not GRE inside.
    assert_eq!(
        keepalive(&frame::ipv4(us, peer, 17, 1, &bare), peer, us),
        None
    );
    let mut bad_header = ok.clone();
    bad_header[10] ^= 1;
    assert_eq!(
        keepalive(&bad_header, peer, us),
        None,
        "IPv4 header checksum"
    );
    let mut not_gre = ok.clone();
    not_gre[21] = 1; // inner GRE version 1
    assert_eq!(keepalive(&not_gre, peer, us), None, "inner GRE version");
    assert_eq!(keepalive(&ok[..19], peer, us), None, "truncated");
}
