//! The NGAP codec against octets NetGet did not write: a captured UERANSIM NG Setup Request
//! (asn1c's APER), and vectors derived by hand from X.691 and TS 38.413 with the field decode in
//! the comment. Round trips are not evidence here — an encoder and decoder can agree on a wrong
//! alignment rule forever — so every encode is compared with literal octets.
//!
//! Then the decode bounds, each checked by removing it (see `AGENTS.md`), and the 5GMM subset
//! against literal TS 24.501 octets. The last test hands NetGet's own PDUs to tshark's ngap
//! dissector inside SCTP DATA chunks with PPID 60.
use super::support::{assert_ngap_clean, unhex};
use netget::server::ngap::aper::{Reader, Writer};
use netget::server::ngap::codec::{self, Cause, CauseGroup, Criticality, Ie, Pdu, PduKind, Plmn};
use netget::server::ngap::nas;
use serde_json::json;

/// UERANSIM v3.2.7's `nr-gnb` NG Setup Request for MCC 001 / MNC 01, gNB ID 1 (32 bits), name
/// "UERANSIM-gnb-1-1-1", TAC 1, slice SST 1 SD 010203, paging DRX v128 — captured off an SCTP
/// association on Linux.
const UERANSIM_NG_SETUP: &str = "00150041000004001b00090000f1105000000001005240140880554552414e53494d2d676e622d312d312d310066001000000000010000f110000010080102030015400140";

fn plmn() -> Plmn {
    Plmn {
        mcc: "001".into(),
        mnc: "01".into(),
    }
}

#[test]
fn ueransims_ng_setup_request_decodes() {
    let pdu = codec::decode_pdu(&unhex(UERANSIM_NG_SETUP)).unwrap();
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.procedure_code, codec::PROC_NG_SETUP);
    assert_eq!(pdu.criticality, Criticality::Reject);
    let v = codec::parse_ng_setup_request(&pdu).unwrap();
    assert_eq!(
        v["global_ran_node_id"],
        json!({"type": "gnb", "plmn": {"mcc": "001", "mnc": "01"}, "gnb_id": 1, "gnb_id_bits": 32})
    );
    assert_eq!(v["ran_node_name"], "UERANSIM-gnb-1-1-1");
    assert_eq!(
        v["supported_ta_list"],
        json!([{"tac": 1, "broadcast_plmns": [{"plmn": {"mcc": "001", "mnc": "01"},
                "slices": [{"sst": 1, "sd": "010203"}]}]}])
    );
    assert_eq!(v["default_paging_drx"], "v128");
}

#[test]
fn netgets_ng_setup_request_matches_ueransims_octets() {
    // Built from the same fields, NetGet's encoder must write asn1c's octets exactly.
    let ta = vec![
        json!({"tac": 1, "broadcast_plmns": [{"plmn": {"mcc": "001", "mnc": "01"},
                         "slices": [{"sst": 1, "sd": "010203"}]}]}),
    ];
    let bytes =
        codec::ng_setup_request(&plmn(), 1, 32, Some("UERANSIM-gnb-1-1-1"), &ta, "v128").unwrap();
    assert_eq!(hex::encode(&bytes), UERANSIM_NG_SETUP);
}

#[test]
fn a_short_ran_node_name_without_sd_is_hand_derived() {
    // 00 15 00 2f       initiatingMessage, NGSetup(21), reject, open type 47 octets
    // 00 00 04          ext 0 + padding, 4 IEs (0..65535: two aligned octets)
    // 00 1b 00 09 ...   GlobalRANNodeID: choice gNB, plmn 00f110, gNB-ID len 32 (1010 in 4 bits ->
    //                   0x50), 00000001
    // 00 52 40 05 01 00 67 6e 62   RANNodeName "gnb": ext 0, len-1=2 in 8 unaligned bits (0x01
    //                   0x00), then the characters aligned
    // 00 66 00 0d 00 00 00 00 01 00 00 f1 10 00 00 00 08   one TA, TAC 000001, one PLMN, one slice
    //                   (0..1024: two octets), then item ext, item opt, S-NSSAI ext, sd, opt
    //                   (five zero bits) and SST 01 unaligned: 00000 000|00001 -> 00 08
    // 00 15 40 01 40    DefaultPagingDRX v128: ext 0, index 2 in 2 bits
    let expect = "00 15 00 2f 00 00 04 00 1b 00 09 00 00 f1 10 50 00 00 00 01 \
                  00 52 40 05 01 00 67 6e 62 \
                  00 66 00 0d 00 00 00 00 01 00 00 f1 10 00 00 00 08 \
                  00 15 40 01 40";
    let ta =
        vec![json!({"tac": 1, "broadcast_plmns": [{"plmn": "001-01", "slices": [{"sst": 1}]}]})];
    let bytes = codec::ng_setup_request(&plmn(), 1, 32, Some("gnb"), &ta, "v128").unwrap();
    assert_eq!(bytes, unhex(expect));
    let back = codec::parse_ng_setup_request(&codec::decode_pdu(&bytes).unwrap()).unwrap();
    assert_eq!(back["ran_node_name"], "gnb");
    assert_eq!(
        back["supported_ta_list"][0]["broadcast_plmns"][0]["slices"],
        json!([{"sst": 1}])
    );
}

#[test]
fn ng_setup_failure_is_hand_derived() {
    // 40 15 00 0d       unsuccessfulOutcome (index 2: 0 10 -> 0x40), NGSetup, reject, 13 octets
    // 00 00 02          two IEs
    // 00 0f 40 01 88    Cause, ignore. Cause is a CHOICE of six *root* alternatives (the sixth
    //                   is choice-Extensions) with no extension marker, so: misc = 4 in 3 bits
    //                   (100), then CauseMisc, which is extensible: ext 0, unknown-PLMN-or-SNPN = 4
    //                   in 3 bits (range 6): 100 0 100 -> 0x88
    // 00 6b 40 01 30    TimeToWait v10s: ext 0, index 3 in 3 bits -> 0x30
    let cause = Cause::from_json(&json!("misc/unknown-PLMN-or-SNPN")).unwrap();
    let bytes = codec::ng_setup_failure(&cause, Some("v10s")).unwrap();
    assert_eq!(
        bytes,
        unhex("40 15 00 0d 00 00 02 00 0f 40 01 88 00 6b 40 01 30")
    );
    let pdu = codec::decode_pdu(&bytes).unwrap();
    assert_eq!(
        codec::parse_cause_message(&pdu).unwrap()["cause"],
        json!({"group": "misc", "value": "unknown-PLMN-or-SNPN"})
    );
}

#[test]
fn downlink_nas_transport_is_hand_derived() {
    // 00 04 40 18       initiatingMessage, DownlinkNASTransport(4), ignore, 24 octets
    // 00 00 03          three IEs
    // 00 0a 00 02 00 01 AMF-UE-NGAP-ID 1: 0..2^40-1 is the indefinite case, (octets-1)=0 in 3 bits
    // 00 55 00 02 00 01 RAN-UE-NGAP-ID 1: (octets-1)=0 in 2 bits
    // 00 26 00 05 04 7e 00 44 03   NAS-PDU: Registration Reject, cause #3
    let nas = nas::encode(
        &json!({"message": "registration_reject", "cause": "illegal_ue"}),
        nas::DOWNLINK_MESSAGES,
    )
    .unwrap();
    let bytes = codec::downlink_nas_transport(1, 1, &nas).unwrap();
    assert_eq!(
        bytes,
        unhex(
            "00 04 40 18 00 00 03 00 0a 00 02 00 01 00 55 00 02 00 01 00 26 00 05 04 7e 00 44 03"
        )
    );
}

#[test]
fn large_ue_ids_use_the_octet_count_field() {
    // AMF-UE-NGAP-ID 2^40-1: five octets, (5-1)=4 in 3 bits -> 100 -> 0x80, then ff x5.
    let ie = codec::amf_ue_ngap_id_ie(codec::MAX_AMF_UE_NGAP_ID, Criticality::Reject).unwrap();
    assert_eq!(ie.value, unhex("80 ff ff ff ff ff"));
    // RAN-UE-NGAP-ID 0x10000: three octets, (3-1)=2 in 2 bits -> 10 -> 0x80.
    let ie = codec::ran_ue_ngap_id_ie(0x10000, Criticality::Reject).unwrap();
    assert_eq!(ie.value, unhex("80 01 00 00"));
    assert_eq!(codec::decode_ran_ue_ngap_id(&ie).unwrap(), 0x10000);
}

#[test]
fn aper_constrained_whole_numbers_follow_x691() {
    // range <= 255: minimum bits, unaligned; 256: one aligned octet; <= 64K: two aligned octets.
    let mut w = Writer::new();
    w.bit(true);
    w.constrained(5, 0, 7, "t").unwrap(); // 101
    w.constrained(200, 0, 255, "t").unwrap(); // aligned c8
    w.bit(true);
    w.constrained(0x1234, 0, 65_535, "t").unwrap(); // aligned 12 34
    assert_eq!(w.finish(), unhex("d0 c8 80 12 34"));
    let mut r = Reader::new(&[0xd0, 0xc8, 0x80, 0x12, 0x34]);
    assert!(r.bit("t").unwrap());
    assert_eq!(r.constrained(0, 7, "t").unwrap(), 5);
    assert_eq!(r.constrained(0, 255, "t").unwrap(), 200);
    assert!(r.bit("t").unwrap());
    assert_eq!(r.constrained(0, 65_535, "t").unwrap(), 0x1234);
    // A value above the upper bound is refused on decode, not wrapped.
    let mut r = Reader::new(&[0xe0]);
    assert!(
        r.constrained(0, 5, "t").is_err(),
        "7 in 0..5 must be refused"
    );
}

#[test]
fn plmn_tbcd_matches_ts_24_008() {
    assert_eq!(plmn().octets(), [0x00, 0xf1, 0x10]);
    let three = Plmn::from_json(&json!({"mcc": "310", "mnc": "410"})).unwrap();
    assert_eq!(three.octets(), [0x13, 0x00, 0x14]);
    assert_eq!(Plmn::decode_octets(&[0x13, 0x00, 0x14]).unwrap(), three);
    assert!(Plmn::from_json(&json!({"mcc": "01", "mnc": "01"})).is_err());
    assert!(
        Plmn::decode_octets(&[0x0a, 0xf1, 0x10]).is_err(),
        "a non-decimal digit is refused"
    );
}

#[test]
fn causes_are_named_and_refused_when_undefined() {
    let c =
        Cause::from_json(&json!({"group": "radioNetwork", "value": "unknown_local_ue_ngap_id"}))
            .unwrap();
    assert_eq!(c, Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID));
    // Extension values encode with the extension bit.
    let ext = Cause::from_json(&json!("nas/uE-not-in-PLMN-serving-area")).unwrap();
    assert!(ext.extended);
    assert_eq!(ext.group, CauseGroup::Nas);
    let ie = codec::cause_ie(&ext, Criticality::Ignore).unwrap();
    assert_eq!(codec::decode_cause(&ie).unwrap(), ext);
    assert!(Cause::from_json(&json!("misc/no-such-cause")).is_err());
    assert!(
        Cause::from_json(&json!("unspecified")).is_err(),
        "ambiguous across groups"
    );
}

// ----------------------------------------------------------------------------------------------
// Bounds: refused before anything reaches the model
// ----------------------------------------------------------------------------------------------

fn ie_container(count: usize) -> Vec<u8> {
    // A message with `count` copies of distinct empty-ish IEs.
    let ies = (0..count)
        .map(|i| Ie::new(1000 + i as u16, Criticality::Ignore, vec![0]))
        .collect::<Vec<_>>();
    let mut w = Writer::new();
    w.bit(false);
    w.size(ies.len(), 0, 65_535, "c").unwrap();
    for ie in &ies {
        w.constrained(ie.id as u64, 0, 65_535, "id").unwrap();
        w.constrained(1, 0, 2, "crit").unwrap();
        w.open_type(&ie.value, "v").unwrap();
    }
    let content = w.finish();
    let mut outer = Writer::new();
    outer.bit(false);
    outer.constrained(0, 0, 2, "pdu").unwrap();
    outer.constrained(9, 0, 255, "code").unwrap();
    outer.constrained(1, 0, 2, "crit").unwrap();
    outer.open_type(&content, "msg").unwrap();
    outer.finish()
}

#[test]
fn ie_count_is_bounded() {
    assert!(codec::decode_pdu(&ie_container(codec::MAX_IES)).is_ok());
    let err = codec::decode_pdu(&ie_container(codec::MAX_IES + 1)).unwrap_err();
    assert_eq!(
        err.cause,
        Cause::protocol(codec::PROTOCOL_TRANSFER_SYNTAX_ERROR),
        "{err}"
    );
}

#[test]
fn malformed_framing_is_refused_with_transfer_syntax_error() {
    let good = unhex(UERANSIM_NG_SETUP);
    // Truncated: the open type promises more than arrives.
    let err = codec::decode_pdu(&good[..good.len() - 5]).unwrap_err();
    assert_eq!(
        err.cause,
        Cause::protocol(codec::PROTOCOL_TRANSFER_SYNTAX_ERROR)
    );
    // A fragmented length determinant (11xxxxxx) is refused, not buffered.
    let err = codec::decode_pdu(&unhex("00 15 00 c1 00")).unwrap_err();
    assert!(err.detail.contains("fragmented"), "{err}");
    // Trailing octets after the PDU.
    let mut long = good.clone();
    long.push(0);
    assert!(codec::decode_pdu(&long).is_err());
    // Larger than the bound, refused before decoding begins.
    let huge = vec![0u8; codec::MAX_PDU_LEN + 1];
    assert!(codec::decode_pdu(&huge)
        .unwrap_err()
        .detail
        .contains("exceeds"));
}

#[test]
fn a_duplicated_ie_is_a_falsely_constructed_message() {
    let ie = Ie::new(85, Criticality::Reject, vec![0, 1]);
    let pdu = Pdu::new(
        PduKind::Initiating,
        15,
        Criticality::Ignore,
        vec![ie.clone(), ie],
    );
    let bytes = codec::encode_pdu(&pdu).unwrap();
    assert_eq!(
        codec::decode_pdu(&bytes).unwrap_err().cause,
        Cause::protocol(5)
    );
}

#[test]
fn a_missing_mandatory_ie_is_an_abstract_syntax_error() {
    let mut pdu = codec::decode_pdu(&unhex(UERANSIM_NG_SETUP)).unwrap();
    pdu.ies.retain(|ie| ie.id != codec::IE_SUPPORTED_TA_LIST);
    let err = codec::parse_ng_setup_request(&pdu).unwrap_err();
    assert_eq!(
        err.cause,
        Cause::protocol(codec::PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT)
    );
}

#[test]
fn nested_lists_share_one_element_budget() {
    // One TA, one PLMN, 1024 slices: within every 38.413 constraint, but 1026 elements in total,
    // over the per-PDU budget of 1024. The budget is what keeps 256 x 12 x 1024 from reaching the
    // model however a peer nests its lists.
    let slices: Vec<_> = (0..1024).map(|i| json!({"sst": i % 256})).collect();
    let ta = vec![json!({"tac": 1, "broadcast_plmns": [{"plmn": "001-01", "slices": slices}]})];
    let bytes = codec::ng_setup_request(&plmn(), 1, 32, None, &ta, "v128").unwrap();
    let err = codec::parse_ng_setup_request(&codec::decode_pdu(&bytes).unwrap()).unwrap_err();
    assert!(err.detail.contains("list elements"), "{err}");
    // 1022 slices fit: 1 + 1 + 1022.
    let slices: Vec<_> = (0..1022).map(|i| json!({"sst": i % 256})).collect();
    let ta = vec![json!({"tac": 1, "broadcast_plmns": [{"plmn": "001-01", "slices": slices}]})];
    let bytes = codec::ng_setup_request(&plmn(), 1, 32, None, &ta, "v128").unwrap();
    assert!(codec::parse_ng_setup_request(&codec::decode_pdu(&bytes).unwrap()).is_ok());
}

#[test]
fn nas_pdu_size_is_bounded_both_ways() {
    assert!(codec::nas_pdu_ie(&vec![0x7e; codec::MAX_NAS_PDU_LEN]).is_ok());
    assert!(codec::nas_pdu_ie(&vec![0x7e; codec::MAX_NAS_PDU_LEN + 1]).is_err());
    // Decode: an Uplink NAS Transport whose NAS-PDU declares more than the bound.
    let mut w = Writer::new();
    w.general_length(codec::MAX_NAS_PDU_LEN + 1, "n").unwrap();
    w.octets_aligned(&vec![0x7e; codec::MAX_NAS_PDU_LEN + 1]);
    let big = Ie::new(codec::IE_NAS_PDU, Criticality::Reject, w.finish());
    assert!(codec::decode_nas_pdu(&big)
        .unwrap_err()
        .detail
        .contains("bound"));
}

#[test]
fn printable_strings_are_checked_both_ways() {
    assert!(
        codec::name_ie(codec::IE_AMF_NAME, Criticality::Reject, "amf_1").is_err(),
        "_ is not printable"
    );
    assert!(codec::name_ie(codec::IE_AMF_NAME, Criticality::Reject, &"a".repeat(151)).is_err());
    let mut ie = codec::name_ie(codec::IE_AMF_NAME, Criticality::Reject, "amf").unwrap();
    let last = ie.value.len() - 1;
    ie.value[last] = 0x07; // BEL
    assert!(codec::decode_name(&ie).is_err());
}

#[test]
fn constraints_are_enforced_on_encode() {
    // A 33-bit gNB ID, an 11-bit AMF Set ID, a capacity of 256: none reach the wire.
    assert!(codec::global_gnb_id_ie(&plmn(), 1 << 32, 32).is_err());
    assert!(codec::global_gnb_id_ie(&plmn(), 1, 21).is_err());
    let g = json!([{"plmn": "001-01", "amf_region_id": 1, "amf_set_id": 1024, "amf_pointer": 0}]);
    assert!(codec::served_guami_list_ie(g.as_array().unwrap()).is_err());
    assert!(codec::relative_amf_capacity_ie(256).is_err());
    assert!(
        codec::supported_ta_list_ie(&[]).is_err(),
        "SupportedTAList is SIZE(1..256)"
    );
}

// ----------------------------------------------------------------------------------------------
// 5GMM (TS 24.501)
// ----------------------------------------------------------------------------------------------

/// Registration Request, initial, follow-on, ngKSI 7 (no key), SUCI IMSI 001-01, routing
/// indicator 0000, null scheme, MSIN 0000000001, UE security capability EA0-3/IA0-3.
const REGISTRATION_REQUEST: &str =
    "7e 00 41 79 00 0d 01 00 f1 10 00 00 00 00 00 00 00 00 10 2e 02 f0 f0";

#[test]
fn a_registration_request_decodes_into_fields() {
    let v = nas::decode(&unhex(REGISTRATION_REQUEST));
    assert_eq!(v["message"], "registration_request");
    assert_eq!(v["registration_type"], "initial");
    assert_eq!(v["follow_on_request"], true);
    assert_eq!(v["ngksi"], 7);
    assert_eq!(
        v["mobile_identity"],
        json!({"type": "suci", "supi_format": "imsi", "plmn": {"mcc": "001", "mnc": "01"},
               "routing_indicator": "0000", "protection_scheme": "null", "protection_scheme_id": 0,
               "home_network_public_key_id": 0, "msin": "0000000001"})
    );
    assert_eq!(
        v["ue_security_capability"]["5g_ea"],
        json!(["5G-EA0", "5G-EA1", "5G-EA2", "5G-EA3"])
    );
}

#[test]
fn a_registration_request_encodes_to_the_same_octets() {
    let bytes = nas::encode(
        &json!({"message": "registration_request", "registration_type": "initial",
                "mobile_identity": {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"},
                                    "routing_indicator": "0000", "msin": "0000000001"}}),
        nas::UPLINK_MESSAGES,
    )
    .unwrap();
    assert_eq!(bytes, unhex(REGISTRATION_REQUEST));
}

#[test]
fn downlink_5gmm_messages_are_literal() {
    let enc = |v| nas::encode(&v, nas::DOWNLINK_MESSAGES).unwrap();
    assert_eq!(
        enc(json!({"message": "identity_request", "identity_type": "suci"})),
        unhex("7e 00 5b 01")
    );
    assert_eq!(
        enc(json!({"message": "registration_reject", "cause": 22})),
        unhex("7e 00 44 16")
    );
    assert_eq!(
        enc(json!({"message": "service_reject", "cause": "congestion"})),
        unhex("7e 00 4d 16")
    );
    let rand = "00112233445566778899aabbccddeeff";
    let autn = "ffeeddccbbaa99887766554433221100";
    let a =
        enc(json!({"message": "authentication_request", "ngksi": 1, "rand": rand, "autn": autn}));
    assert_eq!(
        a,
        unhex(&format!("7e 00 56 01 02 00 00 21 {rand} 20 10 {autn}"))
    );
    let back = nas::decode(&a);
    assert_eq!(
        (back["rand"].as_str(), back["autn"].as_str()),
        (Some(rand), Some(autn))
    );
    // Direction is enforced: a downlink encoder will not write an uplink message.
    assert!(nas::encode(
        &json!({"message": "identity_response"}),
        nas::DOWNLINK_MESSAGES
    )
    .is_err());
    assert!(
        nas::encode(
            &json!({"message": "registration_reject", "cause": 4}),
            nas::DOWNLINK_MESSAGES
        )
        .is_err(),
        "#4 is not a 5GMM cause"
    );
}

#[test]
fn uplink_answers_decode() {
    let f = nas::decode(&unhex("7e 00 59 14"));
    assert_eq!(f["message"], "authentication_failure");
    assert_eq!(f["cause"], json!({"value": 20, "name": "mac_failure"}));
    // An Identity Response carrying a 5G-GUTI (TS 24.501 figure 9.11.3.4.1).
    let guti = nas::decode(&unhex("7e 00 5c 00 0b f2 00 f1 10 02 00 40 c0 00 00 01"));
    assert_eq!(
        guti["mobile_identity"],
        json!({"type": "5g_guti", "plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2,
               "amf_set_id": 1, "amf_pointer": 0, "tmsi": 0xc0000001u32})
    );
    // Integrity protected, not ciphered: the inner message is readable and is decoded, the MAC
    // is reported unverified.
    let wrapped = nas::decode(&unhex("7e 01 de ad be ef 05 7e 00 43"));
    assert_eq!(wrapped["security_header"], "integrity_protected");
    assert_eq!(wrapped["mac_verified"], false);
    assert_eq!(wrapped["inner"]["message"], "registration_complete");
    // Garbage is reported, never fatal: NAS is opaque to NGAP.
    assert_eq!(nas::decode(&[0x7e, 0x00])["decoded"], false);
}

#[test]
fn a_5g_guti_identity_round_trips() {
    let id = json!({"type": "5g_guti", "plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2,
                    "amf_set_id": 1, "amf_pointer": 0, "tmsi": 0xc0000001u32});
    let bytes = nas::encode_mobile_identity(&id).unwrap();
    assert_eq!(bytes, unhex("f2 00 f1 10 02 00 40 c0 00 00 01"));
    assert_eq!(nas::decode_mobile_identity(&bytes), id);
}

// ----------------------------------------------------------------------------------------------
// The independent dissector
// ----------------------------------------------------------------------------------------------

#[test]
fn tshark_dissects_netgets_pdus_as_ngap() {
    let ta = vec![
        json!({"tac": 1, "broadcast_plmns": [{"plmn": "001-01", "slices": [{"sst": 1, "sd": "010203"}]}]}),
    ];
    let setup = codec::ng_setup_request(&plmn(), 1, 32, Some("netget-gnb"), &ta, "v128").unwrap();
    let response = codec::ng_setup_response(
        "netget-amf",
        json!([{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}])
            .as_array()
            .unwrap(),
        255,
        json!([{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1, "sd": "010203"}]}])
            .as_array()
            .unwrap(),
    )
    .unwrap();
    let failure =
        codec::ng_setup_failure(&Cause::misc(codec::MISC_UNKNOWN_PLMN), Some("v10s")).unwrap();
    let uli =
        json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}});
    let initial =
        codec::initial_ue_message(1, &unhex(REGISTRATION_REQUEST), &uli, "mo-Signalling").unwrap();
    let auth = nas::encode(
        &json!({"message": "authentication_request", "ngksi": 0}),
        nas::DOWNLINK_MESSAGES,
    )
    .unwrap();
    let dl = codec::downlink_nas_transport(1, 1, &auth).unwrap();
    let ul = codec::uplink_nas_transport(1, 1, &unhex("7e 00 59 14"), &uli).unwrap();
    let release =
        codec::ue_context_release_command(1, Some(1), &Cause::nas(codec::NAS_NORMAL_RELEASE))
            .unwrap();
    let complete = codec::ue_context_release_complete(1, 1).unwrap();
    let error = codec::error_indication(
        Some(1),
        Some(1),
        Some(&Cause::protocol(codec::PROTOCOL_SEMANTIC_ERROR)),
    )
    .unwrap();
    let reset = codec::ng_reset(&Cause::misc(codec::MISC_OM_INTERVENTION), None).unwrap();
    let ack = codec::ng_reset_acknowledge(Some(&[(Some(1), Some(1))])).unwrap();
    assert_ngap_clean(&[
        (false, setup),
        (true, response),
        (true, failure),
        (false, initial),
        (true, dl),
        (false, ul),
        (true, release),
        (false, complete),
        (true, error),
        (true, reset),
        (false, ack),
    ]);
}
