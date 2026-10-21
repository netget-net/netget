//! `netget::server::ngap` — everything the AMF and the gNB run on what a peer sends: the NGAP
//! PDU framing and every procedure's IE decoder (NG Setup, Initial UE Message, NAS transport,
//! Initial Context Setup, PDU Session Resource Setup and both of its transfers, UE Context
//! Release Request), the 5GMM decoder the model's events are built from, every structured
//! 5GMM and 5GSM parser the security procedures act on, the security-protected NAS path
//! (header, COUNT estimate, MAC check, deciphering) in both directions with NEA0 and NEA2, and
//! SUCI deconcealment of both ECIES profiles.
//!
//! What is checked: nothing panics, a decoded PDU re-encodes within the PDU bound, and a
//! protected message that does not verify leaves the context's COUNT where it was. Nothing
//! here recurses — a 5GSM message inside a 5GMM container is decoded by a different function
//! that never calls back — and the corpus carries the shapes that would find out if that
//! stopped being true: `nested_security_headers` (a protected message inside a protected
//! message, sixty deep), `nested_nas_transport` (an UL NAS Transport whose payload is another,
//! repeatedly), `sm_ie_bomb` (a 5GSM request of thousands of one-octet optional IEs) and
//! `aper_list_bomb` (a PDU Session Resource Setup list declaring 256 items).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::ngap::{codec, nas, security, sm, suci};

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
        if let Ok(again) = codec::encode_pdu(&pdu) {
            assert!(again.len() <= codec::MAX_PDU_LEN);
        }
    }
    let _ = codec::decode_setup_request_transfer(data);
    let _ = codec::decode_setup_response_transfer(data);
    let _ = codec::decode_unsuccessful_transfer(data);

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

    // The protected path, both directions, both ciphers.
    for ea in [security::NEA0, security::NEA2] {
        for direction in [security::UPLINK, security::DOWNLINK] {
            let mut ctx = security::NasContext::new(0, [7u8; 32], security::NIA2, ea, direction);
            let before = ctx.counts.rx_last;
            match ctx.unprotect(data) {
                Ok((plain, _, _)) => {
                    let _ = nas::decode(&plain);
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
