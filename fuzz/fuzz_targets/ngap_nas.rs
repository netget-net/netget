//! `netget::server::ngap` — everything the AMF and the gNB run on what a peer sends: the NGAP
//! PDU framing and every procedure's IE decoder (NG Setup, Initial UE Message, NAS transport,
//! Initial Context Setup, PDU Session Resource Setup and both of its transfers, PDU Session
//! Resource Release and Modify with all four of their transfers, Paging, UE Context Release
//! Request), the 5GMM decoder the model's events are built from, every structured
//! 5GMM and 5GSM parser the security procedures act on, the security-protected NAS path
//! (header, COUNT estimate, MAC check, deciphering) in both directions with every NIA/NEA
//! pair, the Service Request with its NAS message container, the 5GSM release and modification
//! parser, the PDU address, the user plane's ICMP/ICMPv6 echo and Router Advertisement builders
//! on whatever a gNB tunnels, and SUCI deconcealment of both ECIES profiles.
//!
//! What is checked: nothing panics, a decoded PDU re-encodes within the PDU bound, a protected
//! message that does not verify leaves the context's COUNT where it was, a Service Request and a
//! Service Accept that parse re-encode to the same fields, a PDU address that parses re-encodes
//! to itself, and every echo reply and Router Advertisement the user plane would send carries a
//! checksum that verifies and is no longer than what came in (the Advertisement, which answers a
//! solicitation, has its own fixed size). Nothing
//! here recurses — a 5GSM message inside a 5GMM container is decoded by a different function
//! that never calls back — and the corpus carries the shapes that would find out if that
//! stopped being true: `nested_security_headers` (a protected message inside a protected
//! message, sixty deep), `nested_nas_transport` (an UL NAS Transport whose payload is another,
//! repeatedly), `sm_ie_bomb` (a 5GSM request of thousands of one-octet optional IEs) and
//! `aper_list_bomb` (a PDU Session Resource Setup list declaring 256 items). `release_command`
//! (a valid PDU Session Resource Release Command) and `paging_max_tais` (a Paging whose
//! TAIListForPaging declares 16 items, the most its SIZE(1..16) allows) seed the release and
//! paging decoders with well-formed starting points; `service_request`, `modification_command`
//! and `router_solicitation` do the same for the Service Request, the 5GSM procedure parser and
//! the user plane, and `flow_description_bomb` (64 KiB of QoS flow descriptions each declaring
//! 63 parameters) tests that parser's per-description and per-parameter bounds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::ngap::{codec, nas, security, sm, suci, upf};

fuzz_target!(|data: &[u8]| {
    // NGAP.
    if let Ok(pdu) = codec::decode_pdu(data) {
        let _ = codec::parse_ng_setup_request(&pdu);
        let _ = codec::parse_ng_setup_response(&pdu);
        let _ = codec::parse_cause_message(&pdu);
        let _ = codec::parse_initial_ue_message(&pdu);
        let _ = codec::parse_nas_transport(&pdu);
        let _ = codec::parse_initial_context_setup_request(&pdu);
        let _ = codec::parse_initial_context_setup_response(&pdu);
        let _ = codec::parse_pdu_session_resource_setup_request(&pdu);
        let _ = codec::parse_pdu_session_resource_setup_response(&pdu);
        let _ = codec::parse_ue_context_release_request(&pdu);
        let _ = codec::parse_pdu_session_resource_release_command(&pdu);
        let _ = codec::parse_pdu_session_resource_release_response(&pdu);
        let _ = codec::parse_pdu_session_resource_modify_request(&pdu);
        let _ = codec::parse_pdu_session_resource_modify_response(&pdu);
        let _ = codec::parse_paging(&pdu);
        if let Ok(again) = codec::encode_pdu(&pdu) {
            assert!(again.len() <= codec::MAX_PDU_LEN);
        }
    }
    let _ = codec::decode_setup_request_transfer(data);
    let _ = codec::decode_setup_response_transfer(data);
    let _ = codec::decode_unsuccessful_transfer(data);
    let _ = codec::decode_release_command_transfer(data);
    let _ = codec::decode_release_response_transfer(data);
    let _ = codec::decode_modify_request_transfer(data);
    let _ = codec::decode_modify_response_transfer(data);

    // 5GMM and 5GSM as the model sees them, and as Rust acts on them.
    let _ = nas::decode(data);
    let _ = nas::message_type(data);
    let _ = nas::decode_mobile_identity(data);
    let _ = nas::parse_registration_request(data);
    let _ = nas::parse_authentication_request(data);
    let _ = nas::parse_authentication_response(data);
    let _ = nas::parse_authentication_failure(data);
    let _ = nas::parse_security_mode_command(data);
    let _ = nas::parse_security_mode_complete(data);
    let _ = nas::parse_registration_accept(data);
    let _ = nas::parse_deregistration_request(data);
    let _ = nas::parse_ul_nas_transport(data);
    let _ = nas::parse_dl_nas_transport(data);
    let _ = nas::parse_nssai(data);
    let _ = nas::parse_suci(data);
    let _ = nas::msin_from_bcd(data);
    let _ = sm::decode(data);
    let _ = sm::parse_establishment_request(data);
    let _ = sm::parse_establishment_accept(data);
    let _ = sm::parse_procedure(data);
    if let Ok(r) = nas::parse_service_request(data) {
        assert_eq!(nas::parse_service_request(&nas::service_request(&r)), Ok(r));
    }
    if let Ok(a) = nas::parse_service_accept(data) {
        assert_eq!(nas::parse_service_accept(&nas::service_accept(&a)), Ok(a));
    }
    if let Some(a) = sm::PduAddress::parse(data) {
        assert_eq!(sm::PduAddress::parse(&a.octets()), Some(a));
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sm::parse_iid(s);
    }

    // The user plane's answers to what a gNB tunnels.
    if let Some(reply) = upf::echo_reply(data) {
        let ihl = (reply[0] & 0x0F) as usize * 4;
        assert!(reply.len() <= data.len());
        assert_eq!(upf::checksum(&reply[..ihl]), 0);
        assert_eq!(upf::checksum(&reply[ihl..]), 0);
    }
    let v6 = |p: &[u8]| -> (std::net::Ipv6Addr, std::net::Ipv6Addr) {
        let a = |r: &[u8]| std::net::Ipv6Addr::from(<[u8; 16]>::try_from(r).unwrap());
        (a(&p[8..24]), a(&p[24..40]))
    };
    if let Some(reply) = upf::echo_reply_v6(data) {
        assert!(reply.len() <= data.len());
        let (src, dst) = v6(&reply);
        assert_eq!(upf::icmpv6_checksum(&src, &dst, &reply[40..]), 0);
    }
    if let Some(ra) = upf::router_advertisement(data, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]) {
        let (src, dst) = v6(&ra);
        assert_eq!(src, upf::ROUTER_LINK_LOCAL);
        assert_eq!(upf::icmpv6_checksum(&src, &dst, &ra[40..]), 0);
    }

    // The protected path, both directions, every algorithm pair NetGet implements.
    for (ia, ea) in [
        (security::NIA2, security::NEA0),
        (security::NIA2, security::NEA2),
        (security::NIA1, security::NEA1),
        (security::NIA3, security::NEA3),
    ] {
        for direction in [security::UPLINK, security::DOWNLINK] {
            let mut ctx = security::NasContext::new(0, [7u8; 32], ia, ea, direction);
            let before = ctx.counts.rx_last;
            match ctx.unprotect(data) {
                Ok((plain, count, _)) => {
                    let _ = nas::decode(&plain);
                    // A Service Request's container, deciphered as the AMF does.
                    if let Ok(r) = nas::parse_service_request(&plain) {
                        if let Some(mut c) = r.nas_container {
                            ctx.cipher_at(count, direction ^ 1, &mut c);
                            let _ = nas::parse_service_request(&c);
                        }
                    }
                }
                Err(_) => assert_eq!(ctx.counts.rx_last, before),
            }
        }
    }

    // SUCI deconcealment of whatever follows the first octet.
    if let Some((first, rest)) = data.split_first() {
        let profile = if first & 1 == 0 {
            suci::PROFILE_A
        } else {
            suci::PROFILE_B
        };
        let _ = suci::deconceal(profile, &[0x11; 32], rest);
    }
});
