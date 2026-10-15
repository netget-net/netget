//! The NDP packet codec, against literal specification bytes.
//!
//! This is the file the protocol's maturity rating rests on. The raw ICMPv6 transport needs root
//! or `CAP_NET_RAW` and has never been executed anywhere, so the only thing about NDP that *can*
//! be proven in this environment is the packet format — and it is proven the way
//! `bluetooth_ble_beacon`'s payload is: **every expected byte string is written out literally and
//! derived from the published layout, not from the implementation.**
//!
//! Round-tripping the encoder through the decoder would prove only that one function inverts the
//! other. The root `CLAUDE.md` names that circular evidence, so it appears here exactly once, at
//! the end, as a consistency check and not as the argument.
//!
//! Sources for every literal below:
//!
//! * RFC 4861 §4.1 (Router Solicitation), §4.2 (Router Advertisement), §4.3 (Neighbour
//!   Solicitation), §4.4 (Neighbour Advertisement), §4.5 (Redirect), §4.6 (option format and the
//!   8-octet length unit), §4.6.1 (Source/Target Link-Layer Address), §4.6.2 (Prefix
//!   Information), §4.6.4 (MTU), §11.2 (the Hop Limit 255 rule).
//! * RFC 4443 §2.1 (the ICMPv6 header) and §2.3 (the checksum).
//! * RFC 8200 §8.1 (the IPv6 pseudo-header the checksum is computed over).
//! * RFC 8106 §5.1 (the RDNSS option).
//! * RFC 4291 §2.7.1 (solicited-node multicast addresses).
//!
//! **The checksums are the part worth being careful about.** Each expected value was produced by
//! an independent one's-complement implementation written directly from RFC 8200 §8.1 — the
//! pseudo-header laid out by hand, next header 58, upper-layer length as a 32-bit field — and is
//! embedded here as a literal. The smallest of them is also checked arithmetically in
//! `the_checksum_is_reproducible_by_hand`, so a reader can confirm the whole scheme without
//! running anything.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ndp \
//!       --test server ndp::codec_test -- --test-threads=100

#![cfg(unix)]

use netget::server::ndp::codec::{
    self, NdpMessage, NdpOption, PrefixInformation, RouterAdvertisement, SendRequest,
};
use serde_json::json;
use std::net::Ipv6Addr;

fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("a literal IPv6 address")
}

const OUR_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

// =============================================================================================
// The option length unit — RFC 4861 §4.6
// =============================================================================================

/// **Option length is in units of 8 octets, not octets.** This is the classic NDP implementation
/// error: a Prefix Information option occupies 32 octets on the wire and its length field reads
/// `4`. Writing `32` produces an option every receiver walks 256 octets for, straight past the
/// end of the packet, and the symptom is a stack that ignores the advertisement entirely.
///
/// Asserted for every option type this codec can produce, because the arithmetic differs for
/// each one and only RDNSS's is variable.
#[test]
fn option_length_is_in_units_of_eight_octets() {
    let cases: Vec<(NdpOption, u8, usize)> = vec![
        // (option, expected length field, expected octets on the wire)
        (NdpOption::SourceLinkLayerAddress(OUR_MAC), 1, 8),
        (NdpOption::TargetLinkLayerAddress(OUR_MAC), 1, 8),
        (
            NdpOption::PrefixInformation(PrefixInformation {
                prefix: addr("2001:db8:1::"),
                prefix_length: 64,
                on_link: true,
                autonomous: true,
                valid_lifetime: 2_592_000,
                preferred_lifetime: 604_800,
            }),
            4,
            32,
        ),
        (NdpOption::Mtu(1500), 1, 8),
        // RDNSS is 8 octets of header plus 16 per address, so 1 + 2n units.
        (
            NdpOption::Rdnss {
                lifetime: 600,
                servers: vec![addr("2001:db8:1::53")],
            },
            3,
            24,
        ),
        (
            NdpOption::Rdnss {
                lifetime: 600,
                servers: vec![addr("2001:db8:1::53"), addr("2001:db8:1::54")],
            },
            5,
            40,
        ),
        (
            NdpOption::Rdnss {
                lifetime: 600,
                servers: vec![
                    addr("2001:db8:1::53"),
                    addr("2001:db8:1::54"),
                    addr("2001:db8:1::55"),
                ],
            },
            7,
            56,
        ),
    ];

    for (option, expected_units, expected_octets) in cases {
        let bytes = option.encode().expect("the option encodes");
        assert_eq!(
            bytes.len(),
            expected_octets,
            "option type {} should occupy {expected_octets} octets",
            option.option_type()
        );
        assert_eq!(
            bytes[0],
            option.option_type(),
            "the first octet is the option type"
        );
        assert_eq!(
            bytes[1], expected_units,
            "option type {} declares its length in 8-octet units: {} octets is {expected_units} \
             units, NOT {}",
            bytes[0], expected_octets, expected_octets
        );
        assert_eq!(
            bytes.len() % 8,
            0,
            "every NDP option is a whole number of 8-octet units"
        );
    }
}

/// The Source and Target Link-Layer Address options differ *only* in their type octet — 1 and 2.
/// Getting them the wrong way round produces a message that parses and means something else.
#[test]
fn link_layer_address_options_match_rfc_4861_bytes() {
    assert_eq!(
        NdpOption::SourceLinkLayerAddress(OUR_MAC).encode().unwrap(),
        vec![0x01, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    );
    assert_eq!(
        NdpOption::TargetLinkLayerAddress(OUR_MAC).encode().unwrap(),
        vec![0x02, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    );
}

/// RFC 4861 §4.6.2. Thirty-two octets: type, length, prefix length, flags, valid lifetime,
/// preferred lifetime, four reserved octets, then the 16-octet prefix. The two flags are the
/// high bits of the fourth octet — `L` on-link is 0x80, `A` autonomous is 0x40 — and `0xc0` is
/// both, which is what a router handing out a SLAAC prefix sends.
#[test]
fn prefix_information_matches_rfc_4861_bytes() {
    let option = NdpOption::PrefixInformation(PrefixInformation {
        prefix: addr("2001:db8:1::"),
        prefix_length: 64,
        on_link: true,
        autonomous: true,
        valid_lifetime: 2_592_000,   // 30 days  = 0x00278d00
        preferred_lifetime: 604_800, // 7 days = 0x00093a80
    });
    assert_eq!(
        option.encode().unwrap(),
        vec![
            0x03, 0x04, 0x40, 0xc0, // type 3, 4 units, /64, L|A
            0x00, 0x27, 0x8d, 0x00, // valid lifetime 2592000
            0x00, 0x09, 0x3a, 0x80, // preferred lifetime 604800
            0x00, 0x00, 0x00, 0x00, // Reserved2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2001:db8:1::
        ],
    );

    // On-link only: 0x80, and a /48 is legal precisely because it is not autonomous.
    let on_link_only = NdpOption::PrefixInformation(PrefixInformation {
        prefix: addr("2001:db8::"),
        prefix_length: 48,
        on_link: true,
        autonomous: false,
        valid_lifetime: 0,
        preferred_lifetime: 0,
    });
    assert_eq!(
        &on_link_only.encode().unwrap()[..4],
        &[0x03, 0x04, 0x30, 0x80]
    );

    // Neither flag: a prefix that is announced and does nothing.
    let neither = NdpOption::PrefixInformation(PrefixInformation {
        prefix: addr("2001:db8::"),
        prefix_length: 48,
        on_link: false,
        autonomous: false,
        valid_lifetime: 0,
        preferred_lifetime: 0,
    });
    assert_eq!(&neither.encode().unwrap()[..4], &[0x03, 0x04, 0x30, 0x00]);
}

/// RFC 4861 §4.6.4: type, length, **two reserved octets**, then a 32-bit MTU. The reserved pair
/// is the piece that is easy to leave out, and doing so shifts the MTU by two octets.
#[test]
fn mtu_option_matches_rfc_4861_bytes() {
    assert_eq!(
        NdpOption::Mtu(1500).encode().unwrap(),
        vec![0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc],
    );
    // A jumbo link, to show the field really is 32 bits.
    assert_eq!(
        NdpOption::Mtu(9000).encode().unwrap(),
        vec![0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x23, 0x28],
    );
}

/// RFC 8106 §5.1: type 25, length `1 + 2n`, two reserved octets, a 32-bit lifetime, then the
/// addresses. `0xffffffff` is the "for ever" lifetime.
#[test]
fn rdnss_option_matches_rfc_8106_bytes() {
    let option = NdpOption::Rdnss {
        lifetime: 600,
        servers: vec![addr("2001:db8:1::53")],
    };
    assert_eq!(
        option.encode().unwrap(),
        vec![
            0x19, 0x03, 0x00, 0x00, // type 25, 3 units (24 octets), Reserved
            0x00, 0x00, 0x02, 0x58, // lifetime 600
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, // 2001:db8:1::53
        ],
    );

    let none = NdpOption::Rdnss {
        lifetime: 600,
        servers: vec![],
    };
    assert!(
        none.encode().is_err(),
        "an RDNSS option with no servers is not expressible and must be refused"
    );
}

// =============================================================================================
// The checksum and its pseudo-header — RFC 4443 §2.3, RFC 8200 §8.1
// =============================================================================================

/// The smallest possible NDP message, worked out by hand so the whole scheme can be checked
/// without running anything.
///
/// Message: `85 00 0000 00000000` — a Router Solicitation with the checksum zeroed.
/// Source `::`, destination `ff02::2`.
///
/// ```text
/// pseudo-header source ::            all sixteen octets zero  ->  0x0000
/// pseudo-header dest   ff02::2       0xff02 + 0x0002          ->  0xff04
/// upper-layer length   8             0x0000 + 0x0008          ->  0x0008
/// zero(3) + next header 58                                    ->  0x003a
/// message                            0x8500 + 0 + 0 + 0       ->  0x8500
///                                                    total    ->  0x18446
/// fold                               0x8446 + 0x0001          ->  0x8447
/// complement                                                  ->  0x7bb8
/// ```
///
/// Two things fall out of that arithmetic, and both are the classic ways to get this wrong:
/// the `0x003a` term is the whole reason the next header must be **58** and not whatever the
/// preceding IPv6 extension header says, and the `0xff04` term is why the checksum cannot be
/// computed from the ICMPv6 bytes alone.
#[test]
fn the_checksum_is_reproducible_by_hand() {
    let message = [0x85u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        codec::icmpv6_checksum(addr("::"), addr("ff02::2"), &message),
        0x7bb8,
    );
}

/// The same ICMPv6 octets, sent between different addresses, must produce different checksums.
///
/// This is the property that makes the pseudo-header load-bearing, and an implementation that
/// omitted it would pass every "does the checksum look plausible" test while failing this one.
#[test]
fn the_checksum_depends_on_both_addresses() {
    let message = [0x85u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let a = codec::icmpv6_checksum(addr("::"), addr("ff02::2"), &message);
    let b = codec::icmpv6_checksum(addr("fe80::1"), addr("ff02::2"), &message);
    let c = codec::icmpv6_checksum(addr("::"), addr("ff02::1"), &message);

    assert_eq!(a, 0x7bb8);
    assert_ne!(a, b, "changing the source address must change the checksum");
    assert_ne!(
        a, c,
        "changing the destination address must change the checksum"
    );

    // And a checksum computed over the message alone — the mistake this is guarding against —
    // is a completely different number.
    let without_pseudo_header = {
        let mut sum: u32 = 0;
        for pair in message.chunks_exact(2) {
            sum += ((pair[0] as u32) << 8) | pair[1] as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    };
    assert_ne!(
        a, without_pseudo_header,
        "a checksum over the ICMPv6 message alone is not an ICMPv6 checksum"
    );
}

/// A message carrying the wrong checksum is rejected, and the error says what was expected —
/// which is what makes the failure debuggable rather than a silent drop.
#[test]
fn verify_checksum_rejects_a_message_computed_without_the_pseudo_header() {
    let source = addr("fe80::1");
    let destination = addr("ff02::2");
    let mut message = vec![0x85u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    codec::write_checksum(&mut message, source, destination).unwrap();
    codec::verify_checksum(&message, source, destination)
        .expect("a message checksummed for these addresses verifies");

    // The same octets claimed to have travelled between different addresses.
    assert!(codec::verify_checksum(&message, source, addr("ff02::1")).is_err());
    assert!(codec::verify_checksum(&message, addr("fe80::9"), destination).is_err());

    // A checksum of zero — what an implementation that forgot to compute one leaves behind.
    message[2] = 0;
    message[3] = 0;
    let err = codec::verify_checksum(&message, source, destination)
        .expect_err("a zero checksum is not correct for this message");
    assert!(
        format!("{err:#}").contains("pseudo-header"),
        "the error should name what was actually computed: {err:#}"
    );
}

/// `write_checksum` must zero the field before computing, so calling it twice is idempotent.
/// The alternative — summing over a field that already holds a checksum — is a bug that only
/// shows up when a message is re-sent.
#[test]
fn write_checksum_is_idempotent() {
    let source = addr("fe80::1");
    let destination = addr("fe80::2");
    let mut message = vec![0x88u8, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00];
    let first = codec::write_checksum(&mut message, source, destination).unwrap();
    let second = codec::write_checksum(&mut message, source, destination).unwrap();
    assert_eq!(first, second);
}

// =============================================================================================
// Whole messages, byte for byte
// =============================================================================================

/// RFC 4861 §4.3. Type 135, code 0, four reserved octets, the 16-octet target, then options.
///
/// Sent to the target's solicited-node multicast group, which is what makes NDP's address
/// resolution unicast-ish where ARP's is a broadcast.
#[test]
fn neighbor_solicitation_matches_rfc_4861_bytes() {
    let message = NdpMessage::NeighborSolicitation {
        target: addr("fe80::2"),
        options: vec![NdpOption::SourceLinkLayerAddress(OUR_MAC)],
    };
    let bytes = message
        .encode(addr("fe80::1"), addr("ff02::1:ff00:2"))
        .unwrap();

    assert_eq!(
        bytes,
        vec![
            0x87, 0x00, 0x15, 0xff, // type 135, code 0, checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // target fe80::2
            0x01, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source link-layer address
        ],
    );
}

/// Duplicate Address Detection: the same solicitation sent from `::`, because the node does not
/// yet own an address. No Source Link-Layer Address option is permitted, since there is nothing
/// to associate it with (RFC 4861 §4.3), and the checksum changes because the source did.
#[test]
fn a_duplicate_address_detection_solicitation_comes_from_the_unspecified_address() {
    let message = NdpMessage::NeighborSolicitation {
        target: addr("fe80::2"),
        options: vec![],
    };
    let bytes = message.encode(addr("::"), addr("ff02::1:ff00:2")).unwrap();

    assert_eq!(
        bytes,
        vec![
            0x87, 0x00, 0x7c, 0x23, // type 135, code 0, checksum
            0x00, 0x00, 0x00, 0x00, //
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ],
    );
}

/// RFC 4861 §4.4. The flags are the **top three bits of a 32-bit field**, not three octets and
/// not the low bits: R = 0x80000000, S = 0x40000000, O = 0x20000000. Solicited plus override —
/// the ordinary answer to a solicitation — is therefore `0x60000000`, which appears on the wire
/// as `60 00 00 00`.
#[test]
fn neighbor_advertisement_matches_rfc_4861_bytes() {
    let message = NdpMessage::NeighborAdvertisement {
        router: false,
        solicited: true,
        override_flag: true,
        target: addr("fe80::2"),
        options: vec![NdpOption::TargetLinkLayerAddress(OUR_MAC)],
    };
    let bytes = message.encode(addr("fe80::2"), addr("fe80::1")).unwrap();

    assert_eq!(
        bytes,
        vec![
            0x88, 0x00, 0xb3, 0x82, // type 136, code 0, checksum
            0x60, 0x00, 0x00, 0x00, // S|O
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // target fe80::2
            0x02, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // target link-layer address
        ],
    );
}

/// Each Neighbour Advertisement flag on its own, so a swapped pair cannot hide behind the
/// combined case above.
#[test]
fn each_neighbor_advertisement_flag_occupies_its_own_bit() {
    let make = |router, solicited, override_flag| {
        NdpMessage::NeighborAdvertisement {
            router,
            solicited,
            override_flag,
            target: addr("fe80::2"),
            options: vec![],
        }
        .encode_without_checksum()
        .unwrap()[4..8]
            .to_vec()
    };

    assert_eq!(make(false, false, false), vec![0x00, 0x00, 0x00, 0x00]);
    assert_eq!(make(true, false, false), vec![0x80, 0x00, 0x00, 0x00], "R");
    assert_eq!(make(false, true, false), vec![0x40, 0x00, 0x00, 0x00], "S");
    assert_eq!(make(false, false, true), vec![0x20, 0x00, 0x00, 0x00], "O");
    assert_eq!(
        make(true, true, true),
        vec![0xe0, 0x00, 0x00, 0x00],
        "R|S|O"
    );
}

/// RFC 4861 §4.2, and the message this whole protocol exists to let a model author.
///
/// Sixteen octets of header — type, code, checksum, current hop limit, flags, router lifetime,
/// reachable time, retransmit timer — then the options. Note `40` for hop limit 64 and `07 08`
/// for a router lifetime of 1800 seconds, and that the flags octet is `00` because neither M nor
/// O is set.
#[test]
fn router_advertisement_matches_rfc_4861_bytes() {
    let message = NdpMessage::RouterAdvertisement(RouterAdvertisement {
        cur_hop_limit: 64,
        managed: false,
        other: false,
        router_lifetime: 1800,
        reachable_time: 0,
        retrans_timer: 0,
        options: vec![
            NdpOption::PrefixInformation(PrefixInformation {
                prefix: addr("2001:db8:1::"),
                prefix_length: 64,
                on_link: true,
                autonomous: true,
                valid_lifetime: 2_592_000,
                preferred_lifetime: 604_800,
            }),
            NdpOption::Mtu(1500),
            NdpOption::Rdnss {
                lifetime: 600,
                servers: vec![addr("2001:db8:1::53")],
            },
        ],
    });
    let bytes = message.encode(addr("fe80::1"), addr("ff02::1")).unwrap();

    assert_eq!(
        bytes,
        vec![
            0x86, 0x00, 0xa7, 0x72, // type 134, code 0, checksum
            0x40, 0x00, 0x07, 0x08, // hop limit 64, flags none, lifetime 1800
            0x00, 0x00, 0x00, 0x00, // reachable time 0
            0x00, 0x00, 0x00, 0x00, // retransmit timer 0
            0x03, 0x04, 0x40, 0xc0, // Prefix Information, 4 units, /64, on-link+autonomous
            0x00, 0x27, 0x8d, 0x00, //   valid 2592000
            0x00, 0x09, 0x3a, 0x80, //   preferred 604800
            0x00, 0x00, 0x00, 0x00, //   Reserved2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   2001:db8:1::
            0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, // MTU 1500
            0x19, 0x03, 0x00, 0x00, // RDNSS, 3 units
            0x00, 0x00, 0x02, 0x58, //   lifetime 600
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, //   2001:db8:1::53
        ],
    );
    assert_eq!(bytes.len(), 80);
}

/// The M and O flags, a zero router lifetime, and an infinite RDNSS lifetime.
///
/// `0xc0` is M|O — "get your address and everything else from DHCPv6". A router lifetime of 0
/// says "I am not a default router", which is how a router withdraws itself while still handing
/// out DNS servers: a combination worth pinning because it looks like an empty message and is
/// not.
#[test]
fn a_router_advertisement_can_withdraw_itself_and_still_configure_dns() {
    let message = NdpMessage::RouterAdvertisement(RouterAdvertisement {
        cur_hop_limit: 0,
        managed: true,
        other: true,
        router_lifetime: 0,
        reachable_time: 30_000,
        retrans_timer: 1_000,
        options: vec![NdpOption::Rdnss {
            lifetime: 0xffff_ffff,
            servers: vec![addr("2001:db8:1::53"), addr("2001:db8:1::54")],
        }],
    });
    let bytes = message.encode(addr("fe80::1"), addr("ff02::1")).unwrap();

    assert_eq!(
        bytes,
        vec![
            0x86, 0x00, 0x8d, 0x0e, // type 134, code 0, checksum
            0x00, 0xc0, 0x00, 0x00, // hop limit unspecified, M|O, lifetime 0
            0x00, 0x00, 0x75, 0x30, // reachable time 30000ms
            0x00, 0x00, 0x03, 0xe8, // retransmit timer 1000ms
            0x19, 0x05, 0x00, 0x00, // RDNSS, 5 units (two addresses)
            0xff, 0xff, 0xff, 0xff, //   lifetime infinite
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, //   2001:db8:1::53
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, //   2001:db8:1::54
        ],
    );
}

/// RFC 4861 §4.1. The smallest NDP message there is: eight octets, four of them reserved.
#[test]
fn router_solicitation_matches_rfc_4861_bytes() {
    let bare = NdpMessage::RouterSolicitation { options: vec![] };
    assert_eq!(
        bare.encode(addr("::"), addr("ff02::2")).unwrap(),
        vec![0x85, 0x00, 0x7b, 0xb8, 0x00, 0x00, 0x00, 0x00],
    );

    let with_option = NdpMessage::RouterSolicitation {
        options: vec![NdpOption::SourceLinkLayerAddress([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ])],
    };
    assert_eq!(
        with_option
            .encode(addr("fe80::10"), addr("ff02::2"))
            .unwrap(),
        vec![
            0x85, 0x00, 0x7a, 0x14, 0x00, 0x00, 0x00, 0x00, //
            0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ],
    );
}

/// RFC 4861 §4.5. Two addresses, in this order: the better first hop, then the destination it
/// applies to. Swapping them produces a message that decodes cleanly and reroutes the wrong
/// thing, which is why the order is asserted against literal octets rather than by round-trip.
#[test]
fn redirect_matches_rfc_4861_bytes() {
    let message = NdpMessage::Redirect {
        target: addr("fe80::3"),
        destination: addr("2001:db8:2::9"),
        options: vec![],
    };
    assert_eq!(
        message.encode(addr("fe80::1"), addr("fe80::2")).unwrap(),
        vec![
            0x89, 0x00, 0x4d, 0x50, // type 137, code 0, checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // target   fe80::3
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, // dest 2001:db8:2::9
        ],
    );
}

// =============================================================================================
// Decoding literal frames
// =============================================================================================

/// A Router Advertisement written out as octets and read back into fields. The literal is the
/// same one asserted above, so this direction is checked against the specification too and not
/// against the encoder.
#[test]
fn a_literal_router_advertisement_decodes_into_its_fields() {
    let bytes = vec![
        0x86, 0x00, 0xa7, 0x72, 0x40, 0x00, 0x07, 0x08, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, //
        0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x00, //
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, //
        0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x58, //
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
    ];

    // The checksum on those literal octets really is right for these two addresses.
    codec::verify_checksum(&bytes, addr("fe80::1"), addr("ff02::1"))
        .expect("the literal checksum verifies against the pseudo-header");

    let NdpMessage::RouterAdvertisement(ra) = NdpMessage::decode(&bytes).unwrap() else {
        panic!("type 134 must decode as a Router Advertisement");
    };
    assert_eq!(ra.cur_hop_limit, 64);
    assert!(!ra.managed);
    assert!(!ra.other);
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.reachable_time, 0);
    assert_eq!(ra.retrans_timer, 0);
    assert_eq!(ra.options.len(), 3);

    assert_eq!(
        ra.options[0],
        NdpOption::PrefixInformation(PrefixInformation {
            prefix: addr("2001:db8:1::"),
            prefix_length: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 2_592_000,
            preferred_lifetime: 604_800,
        })
    );
    assert_eq!(ra.options[1], NdpOption::Mtu(1500));
    assert_eq!(
        ra.options[2],
        NdpOption::Rdnss {
            lifetime: 600,
            servers: vec![addr("2001:db8:1::53")],
        }
    );
}

/// A Neighbour Solicitation and a Neighbour Advertisement, from literal octets.
#[test]
fn literal_neighbor_messages_decode_into_their_fields() {
    let ns = NdpMessage::decode(&[
        0x87, 0x00, 0x15, 0xff, 0x00, 0x00, 0x00, 0x00, //
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, //
        0x01, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ])
    .unwrap();
    let NdpMessage::NeighborSolicitation { target, .. } = &ns else {
        panic!("type 135 must decode as a Neighbour Solicitation");
    };
    assert_eq!(*target, addr("fe80::2"));
    assert_eq!(ns.source_link_layer(), Some(OUR_MAC));
    assert_eq!(ns.target_link_layer(), None, "an NS carries no TLLA");

    let na = NdpMessage::decode(&[
        0x88, 0x00, 0xb3, 0x82, 0x60, 0x00, 0x00, 0x00, //
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, //
        0x02, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ])
    .unwrap();
    let NdpMessage::NeighborAdvertisement {
        router,
        solicited,
        override_flag,
        target,
        ..
    } = &na
    else {
        panic!("type 136 must decode as a Neighbour Advertisement");
    };
    assert!(!router);
    assert!(solicited);
    assert!(override_flag);
    assert_eq!(*target, addr("fe80::2"));
    assert_eq!(na.target_link_layer(), Some(OUR_MAC));
    assert_eq!(na.source_link_layer(), None, "an NA carries no SLLA");
}

/// A Redirect, from literal octets — checking specifically that target and destination did not
/// swap places.
#[test]
fn a_literal_redirect_keeps_target_and_destination_apart() {
    let message = NdpMessage::decode(&[
        0x89, 0x00, 0x4d, 0x50, 0x00, 0x00, 0x00, 0x00, //
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, //
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    ])
    .unwrap();
    let NdpMessage::Redirect {
        target,
        destination,
        ..
    } = message
    else {
        panic!("type 137 must decode as a Redirect");
    };
    assert_eq!(target, addr("fe80::3"), "the better first hop comes first");
    assert_eq!(destination, addr("2001:db8:2::9"));
}

// =============================================================================================
// Decoding refuses what the RFC says to refuse
// =============================================================================================

/// RFC 4861 §4: every NDP message uses ICMPv6 code 0, and a receiver discards anything else.
#[test]
fn a_non_zero_icmpv6_code_is_refused() {
    let mut bytes = vec![0x85, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = NdpMessage::decode(&bytes).expect_err("code 7 is not a Router Solicitation");
    assert!(format!("{err:#}").contains("code 0"), "{err:#}");

    bytes[1] = 0;
    assert!(NdpMessage::decode(&bytes).is_ok());
}

/// RFC 4861 §4.6: "Nodes MUST silently discard an ND packet that contains an option with length
/// zero." That is not pedantry — a zero length is an infinite loop in a naive option walker, and
/// it is how a hostile neighbour wedges a stack.
#[test]
fn an_option_with_length_zero_is_refused() {
    let bytes = vec![
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SLLA claiming length 0
    ];
    let err = NdpMessage::decode(&bytes).expect_err("a zero-length option must be refused");
    assert!(format!("{err:#}").contains("length 0"), "{err:#}");
}

/// An option that claims more octets than remain, and a message too short for its own fixed
/// fields. Both are what a truncated capture or a hostile sender produces.
#[test]
fn truncated_messages_and_options_are_refused() {
    // A Neighbour Solicitation with only eight of its twenty required octets.
    assert!(NdpMessage::decode(&[0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());

    // A Router Solicitation whose option declares 4 units (32 octets) but carries 8.
    let err = NdpMessage::decode(&[
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x00, 0x00,
    ])
    .expect_err("an option cannot be longer than the packet");
    assert!(format!("{err:#}").contains("only"), "{err:#}");

    // A stray odd octet after a complete message: not a whole option header.
    assert!(NdpMessage::decode(&[0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]).is_err());
}

/// ICMPv6 carries far more than Neighbour Discovery — echo requests, packet-too-big, MLD — and a
/// raw socket delivers all of it. Anything that is not one of the five is refused by name.
#[test]
fn an_icmpv6_type_that_is_not_neighbour_discovery_is_refused() {
    // 128 = Echo Request, 130 = Multicast Listener Query, 138 = Router Renumbering.
    for icmpv6_type in [128u8, 129, 130, 138, 1, 3] {
        let err = NdpMessage::decode(&[icmpv6_type, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .expect_err("only 133-137 are Neighbour Discovery");
        assert!(
            format!("{err:#}").contains("Neighbour Discovery"),
            "{err:#}"
        );
    }
}

/// An option this codec does not model must be **walked over**, not treated as fatal — RFC 4861
/// §4.6 requires a receiver to ignore what it does not recognise. The test puts a recognised
/// option *after* an unrecognised one, so a walk that resumed at the wrong offset fails.
#[test]
fn unrecognised_options_are_skipped_and_the_walk_resumes() {
    let bytes = vec![
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Router Solicitation
        0x1f, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // option type 31, 2 units (16 octets)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   ... its second unit
        0x01, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SLLA, after it
    ];
    let message = NdpMessage::decode(&bytes).expect("an unknown option is not fatal");
    assert_eq!(message.options().len(), 2);
    assert_eq!(
        message.options()[0],
        NdpOption::Other {
            option_type: 31,
            length_units: 2
        }
    );
    assert_eq!(
        message.source_link_layer(),
        Some(OUR_MAC),
        "the option after an unknown one must still be found"
    );
}

/// A known option type carrying an impossible length is recorded as unrecognised rather than
/// rejected: the mandatory fields of the message are still intact and the peer is still worth
/// reporting.
#[test]
fn a_known_option_with_the_wrong_length_degrades_rather_than_failing() {
    let bytes = vec![
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x03, 0x01, 0x40, 0xc0, 0x00, 0x00, 0x00, 0x00, // Prefix Information claiming 1 unit
    ];
    let message = NdpMessage::decode(&bytes).unwrap();
    assert_eq!(
        message.options()[0],
        NdpOption::Other {
            option_type: 3,
            length_units: 1
        }
    );
}

// =============================================================================================
// Solicited-node multicast — RFC 4291 §2.7.1
// =============================================================================================

/// `ff02::1:ff00:0/104` with the target's low 24 bits. This is where a solicitation for an
/// address we do not know goes, and getting it wrong means nobody hears the question.
#[test]
fn solicited_node_multicast_takes_the_low_twenty_four_bits() {
    for (target, expected) in [
        ("fe80::2", "ff02::1:ff00:2"),
        ("2001:db8:1::dead:beef", "ff02::1:ffad:beef"),
        ("::1", "ff02::1:ff00:1"),
        ("fe80::211:22ff:fe33:4455", "ff02::1:ff33:4455"),
    ] {
        assert_eq!(
            codec::solicited_node_multicast(addr(target)),
            addr(expected),
            "solicited-node group for {target}"
        );
    }
}

// =============================================================================================
// Validation: what the model is refused, and why
// =============================================================================================

/// RFC 4861 §4.6.2 and RFC 4862: SLAAC appends a 64-bit interface identifier, so an autonomous
/// prefix that is not a `/64` leaves no room and every host ignores it. Refusing here tells the
/// model; accepting would produce an advertisement that silently configures nobody.
#[test]
fn an_autonomous_prefix_must_be_a_slash_64() {
    let bad = NdpOption::PrefixInformation(PrefixInformation {
        prefix: addr("2001:db8::"),
        prefix_length: 48,
        on_link: true,
        autonomous: true,
        valid_lifetime: 100,
        preferred_lifetime: 100,
    });
    let err = bad.encode().expect_err("an autonomous /48 is not usable");
    assert!(format!("{err:#}").contains("/64"), "{err:#}");

    // The same prefix, on-link only, is perfectly legal.
    let good = NdpOption::PrefixInformation(PrefixInformation {
        autonomous: false,
        ..match bad {
            NdpOption::PrefixInformation(p) => p,
            _ => unreachable!(),
        }
    });
    assert!(good.encode().is_ok());
}

/// RFC 4861 §4.6.2 requires a host to ignore the whole option when the preferred lifetime
/// exceeds the valid lifetime, so producing one is a silent no-op.
#[test]
fn a_preferred_lifetime_may_not_exceed_the_valid_lifetime() {
    let option = NdpOption::PrefixInformation(PrefixInformation {
        prefix: addr("2001:db8:1::"),
        prefix_length: 64,
        on_link: true,
        autonomous: true,
        valid_lifetime: 100,
        preferred_lifetime: 200,
    });
    let err = option.encode().expect_err("preferred > valid is refused");
    assert!(format!("{err:#}").contains("preferred_lifetime"), "{err:#}");
}

// =============================================================================================
// Action -> message
// =============================================================================================

/// The Router Advertisement a model would actually write, with every default left implicit.
///
/// The defaults are the interesting part: hop limit 64, router lifetime 1800, a /64 that is both
/// on-link and autonomous, 30-day valid and 7-day preferred lifetimes, and a 600-second RDNSS
/// lifetime. They are the values a real router hands out, so an under-specified action still
/// produces a usable advertisement rather than one a host discards.
#[test]
fn a_router_advertisement_action_fills_in_router_like_defaults() {
    let request = SendRequest::from_action(&json!({
        "type": "send_router_advertisement",
        "prefixes": [{"prefix": "2001:db8:1::"}],
        "rdnss": ["2001:db8:1::53"],
        "mtu": 1500
    }))
    .expect("a minimal advertisement is accepted");

    let NdpMessage::RouterAdvertisement(ra) = &request.message else {
        panic!("send_router_advertisement builds a Router Advertisement");
    };
    assert_eq!(ra.cur_hop_limit, 64);
    assert_eq!(ra.router_lifetime, 1800);
    assert!(!ra.managed);
    assert!(!ra.other);
    assert_eq!(
        ra.options[0],
        NdpOption::PrefixInformation(PrefixInformation {
            prefix: addr("2001:db8:1::"),
            prefix_length: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 2_592_000,
            preferred_lifetime: 604_800,
        })
    );
    assert_eq!(ra.options[1], NdpOption::Mtu(1500));
    assert_eq!(
        ra.options[2],
        NdpOption::Rdnss {
            lifetime: 600,
            servers: vec![addr("2001:db8:1::53")]
        }
    );

    // And it produces exactly the bytes the literal test above pins.
    assert_eq!(
        request
            .message
            .encode(addr("fe80::1"), addr("ff02::1"))
            .unwrap()
            .len(),
        80
    );
}

/// A model will write `2001:db8:1::/64`, because that is how prefixes are written everywhere
/// else. Refusing it over a slash would be pedantry; an explicit `length` still wins.
#[test]
fn cidr_notation_is_accepted_and_an_explicit_length_wins() {
    let cidr = SendRequest::from_action(&json!({
        "type": "send_router_advertisement",
        "prefixes": [{"prefix": "2001:db8:1::/64"}]
    }))
    .unwrap();
    let NdpMessage::RouterAdvertisement(ra) = &cidr.message else {
        unreachable!()
    };
    assert!(matches!(
        ra.options[0],
        NdpOption::PrefixInformation(PrefixInformation {
            prefix_length: 64,
            ..
        })
    ));

    let explicit = SendRequest::from_action(&json!({
        "type": "send_router_advertisement",
        "prefixes": [{"prefix": "2001:db8::/48", "length": 48, "autonomous": false}]
    }))
    .unwrap();
    let NdpMessage::RouterAdvertisement(ra) = &explicit.message else {
        unreachable!()
    };
    assert!(matches!(
        ra.options[0],
        NdpOption::PrefixInformation(PrefixInformation {
            prefix_length: 48,
            autonomous: false,
            ..
        })
    ));
}

/// A Neighbour Advertisement defaults to solicited and override, because that is what an answer
/// to a solicitation is. `router` defaults to false: claiming to be a router is a decision.
#[test]
fn a_neighbor_advertisement_action_defaults_to_an_authoritative_answer() {
    let request = SendRequest::from_action(&json!({
        "type": "send_neighbor_advertisement",
        "target": "2001:db8:1::1"
    }))
    .unwrap();
    let NdpMessage::NeighborAdvertisement {
        router,
        solicited,
        override_flag,
        target,
        options,
    } = &request.message
    else {
        panic!("send_neighbor_advertisement builds a Neighbour Advertisement");
    };
    assert!(!router);
    assert!(solicited);
    assert!(override_flag);
    assert_eq!(*target, addr("2001:db8:1::1"));
    assert!(
        options.is_empty(),
        "the action named no link-layer address, so none is invented here"
    );

    // The server supplies its own, because it — not the model — knows its hardware address.
    let with_default = request.with_default_link_layer(OUR_MAC);
    assert_eq!(with_default.message.target_link_layer(), Some(OUR_MAC));

    // And an explicit one is left alone.
    let explicit = SendRequest::from_action(&json!({
        "type": "send_neighbor_advertisement",
        "target": "2001:db8:1::1",
        "target_link_layer": "aa:bb:cc:dd:ee:ff"
    }))
    .unwrap()
    .with_default_link_layer(OUR_MAC);
    assert_eq!(
        explicit.message.target_link_layer(),
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

/// Where each message goes when the action names no destination.
///
/// The unspecified-source case is the one worth pinning: a node doing duplicate address
/// detection has no address, so a unicast reply cannot reach it and the answer must be
/// multicast.
#[test]
fn default_destinations_follow_rfc_4861() {
    let na = SendRequest::from_action(&json!({
        "type": "send_neighbor_advertisement", "target": "2001:db8:1::1"
    }))
    .unwrap();
    assert_eq!(
        na.default_destination(Some(addr("fe80::9"))),
        addr("fe80::9"),
        "an answer goes back to whoever asked"
    );
    assert_eq!(
        na.default_destination(Some(addr("::"))),
        addr("ff02::1"),
        "a node doing DAD has no address to receive a unicast reply on"
    );
    assert_eq!(na.default_destination(None), addr("ff02::1"));

    let ns = SendRequest::from_action(&json!({
        "type": "send_neighbor_solicitation", "target": "2001:db8:1::53"
    }))
    .unwrap();
    assert_eq!(
        ns.default_destination(Some(addr("fe80::9"))),
        addr("ff02::1:ff00:53"),
        "a solicitation goes to the TARGET's solicited-node group, not back to the peer"
    );

    let ra = SendRequest::from_action(&json!({"type": "send_router_advertisement"})).unwrap();
    assert_eq!(
        ra.default_destination(Some(addr("fe80::9"))),
        addr("fe80::9")
    );
    assert_eq!(ra.default_destination(None), addr("ff02::1"));
}

/// Everything a model can get wrong, refused with a message that says what to do instead.
#[test]
fn unusable_actions_are_refused_by_name() {
    for (action, needle) in [
        (
            json!({"type": "send_neighbor_advertisement"}),
            "'target' is required",
        ),
        (
            json!({"type": "send_neighbor_advertisement", "target": "not-an-address"}),
            "not an IPv6 address",
        ),
        (
            json!({"type": "send_neighbor_advertisement", "target": "::1",
                   "target_link_layer": "zz"}),
            "link-layer address",
        ),
        (
            json!({"type": "send_router_advertisement", "mtu": 576}),
            "1280",
        ),
        (
            json!({"type": "send_router_advertisement", "router_lifetime": 70000}),
            "0-65535",
        ),
        (
            json!({"type": "send_router_advertisement", "hop_limit": 300}),
            "0-255",
        ),
        (
            json!({"type": "send_router_advertisement",
                   "prefixes": [{"prefix": "2001:db8::", "length": 48}]}),
            "/64",
        ),
        (
            json!({"type": "send_router_advertisement", "rdnss": ["not-an-address"]}),
            "not an IPv6 address",
        ),
        (
            json!({"type": "send_router_advertisement", "managed": "yes"}),
            "true or false",
        ),
        (
            json!({"type": "send_redirect", "target": "::1"}),
            "does not",
        ),
    ] {
        let err =
            SendRequest::from_action(&action).expect_err(&format!("{action} must be refused"));
        assert!(
            format!("{err:#}").contains(needle),
            "the refusal for {action} should mention '{needle}': {err:#}"
        );
    }
}

// =============================================================================================
// Nothing byte-shaped reaches the model
// =============================================================================================

/// The rule the whole protocol design hangs on: no key or value in event data is octets, hex or
/// base64. Addresses are IPv6 strings, link-layer addresses are colon-separated, flags are
/// booleans, lifetimes are numbers.
#[test]
fn event_data_carries_no_octets_anywhere() {
    let messages = vec![
        NdpMessage::RouterSolicitation {
            options: vec![NdpOption::SourceLinkLayerAddress(OUR_MAC)],
        },
        NdpMessage::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 64,
            managed: true,
            other: false,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![
                NdpOption::PrefixInformation(PrefixInformation {
                    prefix: addr("2001:db8:1::"),
                    prefix_length: 64,
                    on_link: true,
                    autonomous: true,
                    valid_lifetime: 2_592_000,
                    preferred_lifetime: 604_800,
                }),
                NdpOption::Mtu(1500),
                NdpOption::Rdnss {
                    lifetime: 600,
                    servers: vec![addr("2001:db8:1::53")],
                },
                NdpOption::Other {
                    option_type: 31,
                    length_units: 2,
                },
            ],
        }),
        NdpMessage::NeighborSolicitation {
            target: addr("fe80::2"),
            options: vec![NdpOption::SourceLinkLayerAddress(OUR_MAC)],
        },
        NdpMessage::NeighborAdvertisement {
            router: true,
            solicited: true,
            override_flag: false,
            target: addr("fe80::2"),
            options: vec![NdpOption::TargetLinkLayerAddress(OUR_MAC)],
        },
        NdpMessage::Redirect {
            target: addr("fe80::3"),
            destination: addr("2001:db8:2::9"),
            options: vec![],
        },
    ];

    fn walk(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let lowered = key.to_ascii_lowercase();
                    assert!(
                        !(lowered.ends_with("_hex")
                            || lowered.ends_with("_raw")
                            || lowered.ends_with("_bytes")
                            || lowered == "data"
                            || lowered == "payload"),
                        "{path}.{key} looks like a byte field"
                    );
                    walk(child, &format!("{path}.{key}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"));
                }
            }
            serde_json::Value::String(s) => {
                let hexish =
                    s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit()) && !s.contains(':');
                assert!(!hexish, "{path} = '{s}' looks like a hex blob");
            }
            _ => {}
        }
    }

    for message in &messages {
        let data = serde_json::Value::Object(message.to_event_data());
        walk(&data, message.type_name());
    }

    // And the decoded Router Advertisement really does hand the model the useful fields by name.
    let ra_data = messages[1].to_event_data();
    assert_eq!(ra_data["managed"], json!(true));
    assert_eq!(ra_data["router_lifetime"], json!(1800));
    assert_eq!(ra_data["mtu"], json!(1500));
    assert_eq!(ra_data["rdnss"], json!(["2001:db8:1::53"]));
    assert_eq!(ra_data["prefixes"][0]["prefix"], json!("2001:db8:1::"));
    assert_eq!(ra_data["prefixes"][0]["on_link"], json!(true));

    // Absent things are absent, not null, so a script can test with a plain `in`.
    let rs_data = messages[0].to_event_data();
    assert!(!rs_data.contains_key("mtu"));
    assert!(!rs_data.contains_key("target_address"));
    assert_eq!(rs_data["source_link_layer"], json!("00:11:22:33:44:55"));
}

// =============================================================================================
// The UDP test transport's framing
// =============================================================================================

/// The test transport carries `source(16) || destination(16) || message`, which is exactly the
/// part of the IPv6 header the checksum depends on. That is the whole reason it exists in this
/// shape: a transport that carried only the ICMPv6 bytes could not verify a checksum, so the
/// single most error-prone part of the protocol would go unexercised end to end.
#[test]
fn the_test_transport_carries_the_two_addresses_the_checksum_needs() {
    let source = addr("fe80::1");
    let destination = addr("ff02::1");
    let message = NdpMessage::RouterSolicitation { options: vec![] }
        .encode(source, destination)
        .unwrap();

    let datagram = codec::encode_addressed(source, destination, &message);
    assert_eq!(datagram.len(), 32 + message.len());
    assert_eq!(&datagram[0..16], &source.octets());
    assert_eq!(&datagram[16..32], &destination.octets());

    let (s, d, m) = codec::decode_addressed(&datagram).unwrap();
    assert_eq!(s, source);
    assert_eq!(d, destination);
    codec::verify_checksum(m, s, d).expect("the checksum verifies from the datagram alone");

    // Too short to hold two addresses and an ICMPv6 header.
    assert!(codec::decode_addressed(&[0u8; 20]).is_err());
}

// =============================================================================================
// Consistency check, and NOT the argument
// =============================================================================================

/// Encoder and decoder agree with each other. This proves only that one inverts the other — the
/// root `CLAUDE.md` names that circular evidence — so it appears once, here, deliberately last.
/// Everything above is checked against the published layout instead.
#[test]
fn encode_and_decode_are_consistent_which_is_a_weaker_claim_than_the_tests_above() {
    let messages = vec![
        NdpMessage::RouterSolicitation {
            options: vec![NdpOption::SourceLinkLayerAddress(OUR_MAC)],
        },
        NdpMessage::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 255,
            managed: true,
            other: true,
            router_lifetime: 65535,
            reachable_time: 1234,
            retrans_timer: 5678,
            options: vec![
                NdpOption::PrefixInformation(PrefixInformation {
                    prefix: addr("2001:db8:abcd::"),
                    prefix_length: 64,
                    on_link: false,
                    autonomous: true,
                    valid_lifetime: u32::MAX,
                    preferred_lifetime: u32::MAX,
                }),
                NdpOption::Mtu(9000),
                NdpOption::Rdnss {
                    lifetime: 0,
                    servers: vec![addr("2001:db8::53"), addr("2001:db8::54")],
                },
                NdpOption::SourceLinkLayerAddress(OUR_MAC),
            ],
        }),
        NdpMessage::NeighborSolicitation {
            target: addr("2001:db8::1"),
            options: vec![],
        },
        NdpMessage::NeighborAdvertisement {
            router: true,
            solicited: false,
            override_flag: true,
            target: addr("2001:db8::1"),
            options: vec![NdpOption::TargetLinkLayerAddress(OUR_MAC)],
        },
        NdpMessage::Redirect {
            target: addr("fe80::3"),
            destination: addr("2001:db8:2::9"),
            options: vec![NdpOption::TargetLinkLayerAddress(OUR_MAC)],
        },
    ];

    for message in messages {
        let bytes = message.encode(addr("fe80::1"), addr("ff02::1")).unwrap();
        codec::verify_checksum(&bytes, addr("fe80::1"), addr("ff02::1")).unwrap();
        assert_eq!(NdpMessage::decode(&bytes).unwrap(), message);
    }
}
