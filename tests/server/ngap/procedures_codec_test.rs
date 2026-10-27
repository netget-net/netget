//! PDU Session Resource Release, PDU Session Resource Modify, Paging and the Initial UE
//! Message's FiveG-S-TMSI against octets NetGet did not write: vectors derived by hand from
//! X.691 and TS 38.413 (field decode in the comment, each one also read back by tshark's ngap
//! dissector before it was written down here), then round trips of the shapes the vectors do not
//! cover, every decode bound, truncation, and NetGet's own PDUs through tshark with the values the
//! dissector read compared to the values NetGet meant.
use super::support::{assert_ngap_clean, sctp_data_packet, unhex};
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::ngap::aper::Writer;
use netget::server::ngap::codec::{
    self, Cause, Criticality, Ie, ModifyItem, ModifyRequestTransfer, ModifyResponseTransfer,
    Paging, Pdu, PduKind, Plmn, QosFlow,
};
use serde_json::json;

fn plmn(mcc: &str, mnc: &str) -> Plmn {
    Plmn {
        mcc: mcc.into(),
        mnc: mnc.into(),
    }
}

fn flow(qfi: u8, five_qi: u8, arp_priority: u8) -> QosFlow {
    QosFlow {
        qfi,
        five_qi,
        arp_priority,
    }
}

/// radioNetwork/unknown-PDU-session-ID (index 26 of CauseRadioNetwork's root).
fn unknown_pdu_session() -> Cause {
    Cause::from_json(&json!("radioNetwork/unknown-PDU-session-ID")).unwrap()
}

/// What tshark's ngap dissector read for `names` in each PDU, one row per PDU, framed as
/// [`assert_ngap_clean`] frames them (SCTP DATA, PPID 60).
fn tshark_fields(pdus: &[Vec<u8>], names: &[&str]) -> Vec<Vec<String>> {
    let mut oracle = PcapOracle::ip_proto("ngap", 132);
    for (i, pdu) in pdus.iter().enumerate() {
        let stream = if codec::is_ue_associated(pdu) { 1 } else { 0 };
        oracle = oracle.frame(&sctp_data_packet(38412, 40001, 1 + i as u32, stream, pdu));
    }
    let rows = oracle.fields(names).expect("tshark reads the capture");
    assert_eq!(rows.len(), pdus.len(), "one row per PDU: {rows:?}");
    rows
}

// ----------------------------------------------------------------------------------------------
// Hand-derived vectors
// ----------------------------------------------------------------------------------------------

/// AMF-UE-NGAP-ID 1 and RAN-UE-NGAP-ID 1, criticality reject: id, crit 00, open type 2 octets,
/// (octets-1)=0 in 3 (resp. 2) bits padded, then 01.
const IDS_REJECT: &str = "00 0a 00 02 00 01 00 55 00 02 00 01";
/// The same with criticality ignore (01 in two bits -> 0x40).
const IDS_IGNORE: &str = "00 0a 40 02 00 01 00 55 40 02 00 01";

#[test]
fn release_command_is_hand_derived() {
    // 00 1c 00 18     initiatingMessage (ext 0, index 00), PDUSessionResourceRelease (28),
    //                 reject, open type of 24 octets
    // 00 00 03        container: ext 0 + padding, three IEs (0..65535: two aligned octets)
    // IDS_REJECT
    // 00 4f 00 05     PDUSessionResourceToReleaseListRelCmd (79), reject, five octets:
    //   00            SIZE(1..256): count-1 = 0 in one aligned octet
    //   00 01         item ext 0, iE-Extensions absent (two bits, padded); pDUSessionID 1 (0..255,
    //                 one aligned octet)
    //   01 10         the ReleaseCommandTransfer as an OCTET STRING of one octet: ext 0, iE-Ext 0,
    //                 Cause CHOICE nas = 2 in three bits (six root alternatives, no extension
    //                 marker), CauseNas ext 0, normal-release = 0 in two bits:
    //                 0 0 010 0 00 -> 0x10
    let expect = format!("00 1c 00 18 00 00 03 {IDS_REJECT} 00 4f 00 05 00 00 01 01 10");
    let normal = Cause::nas(codec::NAS_NORMAL_RELEASE);
    assert_eq!(
        codec::encode_release_command_transfer(&normal).unwrap(),
        vec![0x10]
    );
    assert_eq!(
        codec::decode_release_command_transfer(&[0x10]).unwrap(),
        normal
    );
    let bytes = codec::pdu_session_resource_release_command(1, 1, None, &[(1, normal)]).unwrap();
    assert_eq!(bytes, unhex(&expect));
    let pdu = codec::decode_pdu(&unhex(&expect)).unwrap();
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.procedure_code, codec::PROC_PDU_SESSION_RESOURCE_RELEASE);
    assert_eq!(pdu.criticality, Criticality::Reject);
    let cmd = codec::parse_pdu_session_resource_release_command(&pdu).unwrap();
    assert_eq!(
        cmd,
        codec::ReleaseCommand {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 1,
            nas: None,
            sessions: vec![(1, normal)],
        }
    );
    // The fuzz corpus carries the same octets.
    let corpus = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/ngap_nas/release_command"
    ))
    .unwrap();
    assert_eq!(corpus, unhex(&expect));
}

#[test]
fn release_response_is_hand_derived() {
    // 20 1c 00 18     successfulOutcome (index 01: 0 01 00000 -> 0x20), 28, reject, 24 octets
    // 00 00 03 IDS_IGNORE
    // 00 46 40 05     PDUSessionResourceReleasedListRelRes (70), ignore, five octets:
    //   00 00 01      one item; ext 0, iE-Ext 0, pDUSessionID 1
    //   01 00         ReleaseResponseTransfer, one octet: ext 0, iE-Extensions absent, padding
    let expect = format!("20 1c 00 18 00 00 03 {IDS_IGNORE} 00 46 40 05 00 00 01 01 00");
    let bytes = codec::pdu_session_resource_release_response(1, 1, &[1]).unwrap();
    assert_eq!(bytes, unhex(&expect));
    let pdu = codec::decode_pdu(&unhex(&expect)).unwrap();
    assert_eq!(pdu.kind, PduKind::Successful);
    let res = codec::parse_pdu_session_resource_release_response(&pdu).unwrap();
    assert_eq!(
        res,
        codec::ReleaseResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 1,
            released: vec![1],
        }
    );
}

/// The ModifyRequestTransfer of `modify_request_is_hand_derived`: AMBR 1 Mbit/s down, 500 kbit/s
/// up, one QoS flow QFI 1, 5QI 9, ARP 8.
const MODIFY_REQUEST_TRANSFER: &str = "00 00 02 \
     00 82 00 08 08 0f 42 40 20 07 a1 20 \
     00 87 00 07 01 00 80 00 09 1c 00";

#[test]
fn modify_request_is_hand_derived() {
    // The transfer, a ProtocolIE-Container of 26 octets:
    // 00 00 02        ext 0 + padding, two IEs
    // 00 82 00 08     PDUSessionAggregateMaximumBitRate (130), reject, eight octets:
    //   08 0f 42 40   SEQUENCE ext 0, iE-Ext 0; BitRate ext 0, then 0..4e12 is the indefinite
    //                 case: (octets-1)=2 in three bits (4e12 needs five octets) -> 000 010 + pad
    //                 -> 0x08, then 1000000 = 0f 42 40 aligned
    //   20 07 a1 20   BitRate ext 0, (octets-1)=2 -> 0 010 + pad -> 0x20, then 500000 = 07 a1 20
    // 00 87 00 07     QosFlowAddOrModifyRequestList (135), reject, seven octets:
    //   01 00 80 00   SIZE(1..64) count-1 = 0 in six bits | item ext 0, qosFlowLevelQosParameters
    //                 present 1, e-RAB-ID 0, iE-Ext 0 | QFI ext 0, QFI 1 in six bits |
    //                 QosFlowLevelQosParameters ext 0 + four absent optionals | QosCharacteristics
    //                 CHOICE nonDynamic5QI = 0 of three root alternatives (two bits) |
    //                 NonDynamic5QIDescriptor ext 0 + four absent optionals | fiveQI ext 0, pad:
    //                 000000 0100 0000001 00000 00 00000 0 00 -> 01 00 80 00
    //   09            fiveQI 9 (0..255, one aligned octet)
    //   1c 00         ARP ext 0, iE-Ext 0, priorityLevelARP 8 as 8-1 = 0111 (1..15, four bits),
    //                 pre-emptionCapability ext 0 + 0, pre-emptionVulnerability ext 0 + 0:
    //                 00 0111 00 00 + pad -> 1c 00
    let transfer = ModifyRequestTransfer {
        ambr_dl_bps: Some(1_000_000),
        ambr_ul_bps: Some(500_000),
        qos_flows: vec![flow(1, 9, 8)],
    };
    assert_eq!(
        codec::encode_modify_request_transfer(&transfer).unwrap(),
        unhex(MODIFY_REQUEST_TRANSFER)
    );
    assert_eq!(
        codec::decode_modify_request_transfer(&unhex(MODIFY_REQUEST_TRANSFER)).unwrap(),
        transfer
    );

    // 00 1a 00 31     initiatingMessage, PDUSessionResourceModify (26), reject, 49 octets
    // 00 00 03 IDS_REJECT
    // 00 40 00 1e     PDUSessionResourceModifyListModReq (64), reject, 30 octets:
    //   00            one item
    //   00 05         ext 0, nAS-PDU absent, iE-Ext 0 (three bits, padded); pDUSessionID 5
    //   1a ...        the transfer as an OCTET STRING of 26 octets
    let expect = format!(
        "00 1a 00 31 00 00 03 {IDS_REJECT} 00 40 00 1e 00 00 05 1a {MODIFY_REQUEST_TRANSFER}"
    );
    let item = ModifyItem {
        pdu_session_id: 5,
        nas: None,
        transfer: unhex(MODIFY_REQUEST_TRANSFER),
    };
    let bytes = codec::pdu_session_resource_modify_request(1, 1, &[item]).unwrap();
    assert_eq!(bytes, unhex(&expect));
    let pdu = codec::decode_pdu(&unhex(&expect)).unwrap();
    let (amf, ran, items) = codec::parse_pdu_session_resource_modify_request(&pdu).unwrap();
    assert_eq!((amf, ran, items.len()), (1, 1, 1));
    assert_eq!(items[0].pdu_session_id, 5);
    assert_eq!(items[0].nas, None);
    assert_eq!(items[0].transfer, unhex(MODIFY_REQUEST_TRANSFER));
}

#[test]
fn modify_response_is_hand_derived() {
    // ModifyResponseTransfer with QFI 1: ext 0; dL tunnel 0, uL tunnel 0, response list 1,
    // additional DL 0, failed list 0, iE-Ext 0 | SIZE(1..64) count-1 = 0 in six bits | item ext 0,
    // iE-Ext 0 | QFI ext 0, QFI 1: 0001000 000000 00 0 000001 + pad -> 10 00 04
    let ok = ModifyResponseTransfer { qfis: vec![1] };
    assert_eq!(
        codec::encode_modify_response_transfer(&ok).unwrap(),
        unhex("10 00 04")
    );
    // ModifyUnsuccessfulTransfer, radioNetwork/unknown-PDU-session-ID: ext 0, criticality
    // diagnostics 0, iE-Ext 0 | Cause radioNetwork = 0 in three bits | CauseRadioNetwork ext 0,
    // 26 in six bits (45 root values): 000 000 0 011010 + pad -> 00 d0
    //
    // 20 1a 00 24     successfulOutcome, 26, reject, 36 octets
    // 00 00 04 IDS_IGNORE
    // 00 41 40 07     PDUSessionResourceModifyListModRes (65), ignore: one item, ext/iE-Ext 0,
    //   00 00 05 03 10 00 04      pDUSessionID 5, the three-octet response transfer
    // 00 36 40 06     PDUSessionResourceFailedToModifyListModRes (54), ignore: one item,
    //   00 00 06 02 00 d0         pDUSessionID 6, the two-octet unsuccessful transfer
    let expect = format!(
        "20 1a 00 24 00 00 04 {IDS_IGNORE} 00 41 40 07 00 00 05 03 10 00 04 \
         00 36 40 06 00 00 06 02 00 d0"
    );
    let bytes = codec::pdu_session_resource_modify_response(
        1,
        1,
        &[(5, ok)],
        &[(6, unknown_pdu_session())],
    )
    .unwrap();
    assert_eq!(bytes, unhex(&expect));
    let out = codec::parse_pdu_session_resource_modify_response(
        &codec::decode_pdu(&unhex(&expect)).unwrap(),
    )
    .unwrap();
    assert_eq!((out.amf_ue_ngap_id, out.ran_ue_ngap_id), (1, 1));
    assert_eq!(
        out.modified,
        vec![(5, ModifyResponseTransfer { qfis: vec![1] })]
    );
    assert_eq!(out.failed, vec![(6, unknown_pdu_session())]);
}

/// Paging for 5G-S-TMSI set 1, pointer 2, TMSI c0ffee01, DRX v128, TAI 001-01 / TAC 1.
const PAGING: &str = "00 18 40 1e 00 00 03 \
     00 73 40 07 00 08 40 c0 ff ee 01 \
     00 32 40 01 40 \
     00 67 40 07 00 00 f1 10 00 00 01";

#[test]
fn paging_is_hand_derived() {
    // 00 18 40 1e     initiatingMessage, Paging (24), criticality ignore, 30 octets
    // 00 00 03        three IEs
    // 00 73 40 07     UEPagingIdentity (115), ignore, seven octets. The CHOICE is { fiveG-S-TMSI,
    //                 choice-Extensions } with no extension marker: index 0 in ONE bit, no
    //                 extension bit. Then FiveG-S-TMSI ext 0, iE-Ext 0, aMFSetID 0000000001 (ten
    //                 bits), aMFPointer 000010 (six bits): 0 0 0 0000000001 000010 + pad
    //   00 08 40      -> 00 08 40
    //   c0 ff ee 01   fiveG-TMSI, OCTET STRING (SIZE(4)): longer than two octets, so aligned
    // 00 32 40 01 40  PagingDRX (50), ignore: ext 0, v128 = 2 in two bits -> 0x40
    // 00 67 40 07     TAIListForPaging (103), ignore, seven octets:
    //   00            SIZE(1..16) count-1 = 0 in four bits | item ext 0, iE-Ext 0 | TAI ext 0,
    //                 iE-Ext 0
    //   00 f1 10      pLMNIdentity 001-01, aligned
    //   00 00 01      TAC 1
    let p = Paging {
        amf_set_id: 1,
        amf_pointer: 2,
        tmsi: 0xc0ff_ee01,
        tais: vec![(plmn("001", "01"), 1)],
        paging_drx: Some("v128".into()),
    };
    assert_eq!(codec::paging(&p).unwrap(), unhex(PAGING));
    let pdu = codec::decode_pdu(&unhex(PAGING)).unwrap();
    assert_eq!(pdu.procedure_code, codec::PROC_PAGING);
    assert_eq!(pdu.criticality, Criticality::Ignore);
    assert_eq!(codec::parse_paging(&pdu).unwrap(), p);
}

#[test]
fn initial_ue_message_carries_the_five_g_s_tmsi() {
    let uli =
        json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}});
    let nas = unhex("7e 00 4c 10 00 07 f4 00 42 c0 ff ee 01");
    let without = codec::initial_ue_message(1, &nas, &uli, "mo-Data").unwrap();
    assert_eq!(
        without,
        codec::initial_ue_message_with_tmsi(1, &nas, &uli, "mo-Data", None).unwrap()
    );
    let with =
        codec::initial_ue_message_with_tmsi(1, &nas, &uli, "mo-Data", Some((1, 2, 0xc0ff_ee01)))
            .unwrap();
    let pdu = codec::decode_pdu(&with).unwrap();
    // FiveG-S-TMSI (26), reject, seven octets: ext 0, iE-Ext 0, aMFSetID 0000000001, aMFPointer
    // 000010: 0 0 0000000001 000010 + pad -> 00 10 80; then c0 ff ee 01 aligned.
    let ie = pdu.ie(codec::IE_FIVE_G_S_TMSI).unwrap();
    assert_eq!(ie.criticality, Criticality::Reject);
    assert_eq!(ie.value, unhex("00 10 80 c0 ff ee 01"));
    assert_eq!(
        hex::encode(&with[with.len() - 11..]),
        "001a0007001080c0ffee01"
    );
    let ue = codec::parse_initial_ue_message(&pdu).unwrap();
    assert_eq!(
        ue.five_g_s_tmsi,
        Some(json!({"amf_set_id": 1, "amf_pointer": 2, "tmsi": 0xc0ff_ee01u32}))
    );
    assert_eq!(ue.rrc_establishment_cause, "mo-Data");
    // Out of range identities are refused on the way out.
    assert!(
        codec::initial_ue_message_with_tmsi(1, &nas, &uli, "mo-Data", Some((1024, 0, 0))).is_err()
    );
    assert!(
        codec::initial_ue_message_with_tmsi(1, &nas, &uli, "mo-Data", Some((0, 64, 0))).is_err()
    );
}

// ----------------------------------------------------------------------------------------------
// Round trips of what the vectors do not cover
// ----------------------------------------------------------------------------------------------

/// A DL NAS Transport carrying a 5GSM PDU Session Release Command for PDU session 1, cause #36.
const RELEASE_NAS: &str = "7e 00 68 01 00 05 2e 01 01 d3 24 12 01";
/// A DL NAS Transport carrying a 5GSM PDU Session Modification Command for PDU session 5.
const MODIFY_NAS: &str = "7e 00 68 01 00 04 2e 05 01 cb 12 05";

fn release_command_multi() -> Vec<u8> {
    codec::pdu_session_resource_release_command(
        0x12_3456_789a,
        0x10000,
        Some(&unhex(RELEASE_NAS)),
        &[
            (1, Cause::nas(codec::NAS_NORMAL_RELEASE)),
            (2, Cause::radio(20)),
        ],
    )
    .unwrap()
}

fn modify_request_multi() -> Vec<u8> {
    let first = ModifyRequestTransfer {
        ambr_dl_bps: Some(2_000_000_000),
        ambr_ul_bps: Some(1),
        qos_flows: vec![flow(1, 9, 8), flow(2, 8, 1)],
    };
    let second = ModifyRequestTransfer {
        ambr_dl_bps: None,
        ambr_ul_bps: None,
        qos_flows: vec![flow(3, 7, 15)],
    };
    codec::pdu_session_resource_modify_request(
        7,
        8,
        &[
            ModifyItem {
                pdu_session_id: 5,
                nas: Some(unhex(MODIFY_NAS)),
                transfer: codec::encode_modify_request_transfer(&first).unwrap(),
            },
            ModifyItem {
                pdu_session_id: 6,
                nas: None,
                transfer: codec::encode_modify_request_transfer(&second).unwrap(),
            },
        ],
    )
    .unwrap()
}

fn modify_response_multi() -> Vec<u8> {
    codec::pdu_session_resource_modify_response(
        7,
        8,
        &[
            (5, ModifyResponseTransfer { qfis: vec![1, 2] }),
            (7, ModifyResponseTransfer { qfis: vec![] }),
        ],
        &[(6, unknown_pdu_session())],
    )
    .unwrap()
}

fn paging_multi() -> Paging {
    Paging {
        amf_set_id: 0x3ff,
        amf_pointer: 0x3f,
        tmsi: 0xdead_beef,
        tais: vec![(plmn("001", "01"), 1), (plmn("310", "410"), 0xab_cdef)],
        paging_drx: None,
    }
}

#[test]
fn release_round_trips() {
    let cmd = codec::parse_pdu_session_resource_release_command(
        &codec::decode_pdu(&release_command_multi()).unwrap(),
    )
    .unwrap();
    assert_eq!(cmd.amf_ue_ngap_id, 0x12_3456_789a);
    assert_eq!(cmd.ran_ue_ngap_id, 0x10000);
    assert_eq!(cmd.nas, Some(unhex(RELEASE_NAS)));
    assert_eq!(
        cmd.sessions,
        vec![
            (1, Cause::nas(codec::NAS_NORMAL_RELEASE)),
            (2, Cause::radio(20))
        ]
    );
    // The NAS-PDU rides with criticality ignore and the list with reject (38.413 9.2.1.3).
    let pdu = codec::decode_pdu(&release_command_multi()).unwrap();
    assert_eq!(
        pdu.ie(codec::IE_NAS_PDU).unwrap().criticality,
        Criticality::Ignore
    );
    assert_eq!(
        pdu.ie(codec::IE_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD)
            .unwrap()
            .criticality,
        Criticality::Reject
    );

    let res = codec::pdu_session_resource_release_response(3, 4, &[1, 2, 3]).unwrap();
    let res = codec::parse_pdu_session_resource_release_response(&codec::decode_pdu(&res).unwrap())
        .unwrap();
    assert_eq!(res.released, vec![1, 2, 3]);
    assert_eq!((res.amf_ue_ngap_id, res.ran_ue_ngap_id), (3, 4));
}

#[test]
fn modify_round_trips() {
    let (amf, ran, items) = codec::parse_pdu_session_resource_modify_request(
        &codec::decode_pdu(&modify_request_multi()).unwrap(),
    )
    .unwrap();
    assert_eq!((amf, ran), (7, 8));
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].pdu_session_id, 5);
    assert_eq!(items[0].nas, Some(unhex(MODIFY_NAS)));
    assert_eq!(
        codec::decode_modify_request_transfer(&items[0].transfer).unwrap(),
        ModifyRequestTransfer {
            ambr_dl_bps: Some(2_000_000_000),
            ambr_ul_bps: Some(1),
            qos_flows: vec![flow(1, 9, 8), flow(2, 8, 1)],
        }
    );
    assert_eq!(items[1].pdu_session_id, 6);
    assert_eq!(items[1].nas, None);
    assert_eq!(
        codec::decode_modify_request_transfer(&items[1].transfer).unwrap(),
        ModifyRequestTransfer {
            ambr_dl_bps: None,
            ambr_ul_bps: None,
            qos_flows: vec![flow(3, 7, 15)],
        }
    );

    let out = codec::parse_pdu_session_resource_modify_response(
        &codec::decode_pdu(&modify_response_multi()).unwrap(),
    )
    .unwrap();
    assert_eq!((out.amf_ue_ngap_id, out.ran_ue_ngap_id), (7, 8));
    assert_eq!(
        out.modified,
        vec![
            (5, ModifyResponseTransfer { qfis: vec![1, 2] }),
            (7, ModifyResponseTransfer { qfis: vec![] }),
        ]
    );
    assert_eq!(out.failed, vec![(6, unknown_pdu_session())]);

    // Only failed items; only modified items; neither.
    let failed_only =
        codec::pdu_session_resource_modify_response(1, 2, &[], &[(9, Cause::radio(0))]).unwrap();
    let out = codec::parse_pdu_session_resource_modify_response(
        &codec::decode_pdu(&failed_only).unwrap(),
    )
    .unwrap();
    assert!(out.modified.is_empty());
    assert_eq!(out.failed, vec![(9, Cause::radio(0))]);
    let neither = codec::pdu_session_resource_modify_response(1, 2, &[], &[]).unwrap();
    let out =
        codec::parse_pdu_session_resource_modify_response(&codec::decode_pdu(&neither).unwrap())
            .unwrap();
    assert!(out.modified.is_empty() && out.failed.is_empty());
}

#[test]
fn a_modify_response_transfer_with_tunnels_still_yields_its_qfis() {
    // dL-NGU-UP-TNLInformation present (127.0.0.1, TEID 0x01020304), then the response list
    // with QFIs 4 and 5. Written field by field with the APER writer, independently of
    // encode_modify_response_transfer.
    let mut w = Writer::new();
    w.bit(false); // ext
    w.bit(true); // dL tunnel
    w.bit(false); // uL tunnel
    w.bit(true); // response list
    w.bit(false);
    w.bit(false);
    w.bit(false);
    w.constrained(0, 0, 1, "UPTransportLayerInformation")
        .unwrap(); // gTPTunnel
    w.bit(false); // GTPTunnel ext
    w.bit(false); // iE-Ext
    w.bit(false); // TransportLayerAddress ext
    w.size(32, 1, 160, "address").unwrap();
    w.align();
    w.octets_aligned(&[127, 0, 0, 1]);
    w.fixed_octets(&[1, 2, 3, 4]);
    w.size(2, 1, 64, "list").unwrap();
    for q in [4u64, 5] {
        w.bit(false);
        w.bit(false);
        w.bit(false);
        w.constrained(q, 0, 63, "qfi").unwrap();
    }
    let t = codec::decode_modify_response_transfer(&w.finish()).unwrap();
    assert_eq!(t.qfis, vec![4, 5]);
}

#[test]
fn paging_round_trips() {
    let p = paging_multi();
    let bytes = codec::paging(&p).unwrap();
    let back = codec::parse_paging(&codec::decode_pdu(&bytes).unwrap()).unwrap();
    assert_eq!(back, p);
    assert!(codec::decode_pdu(&bytes)
        .unwrap()
        .ie(codec::IE_PAGING_DRX)
        .is_none());
}

#[test]
fn stream_selection_and_names() {
    // Release and modify carry the UE's NGAP ids, so they go on a UE-associated stream; Paging
    // names the UE only by its 5G-S-TMSI and is non-UE-associated signalling (TS 38.412 7).
    assert!(codec::is_ue_associated(&release_command_multi()));
    assert!(codec::is_ue_associated(
        &codec::pdu_session_resource_release_response(1, 1, &[1]).unwrap()
    ));
    assert!(codec::is_ue_associated(&modify_request_multi()));
    assert!(codec::is_ue_associated(&modify_response_multi()));
    assert!(!codec::is_ue_associated(
        &codec::paging(&paging_multi()).unwrap()
    ));

    assert_eq!(codec::procedure_name(codec::PROC_PAGING), Some("Paging"));
    assert_eq!(
        codec::procedure_name(codec::PROC_PDU_SESSION_RESOURCE_MODIFY),
        Some("PDUSessionResourceModify")
    );
    assert_eq!(
        codec::procedure_name(codec::PROC_PDU_SESSION_RESOURCE_RELEASE),
        Some("PDUSessionResourceRelease")
    );
    for (id, name) in [
        (79, "PDUSessionResourceToReleaseListRelCmd"),
        (70, "PDUSessionResourceReleasedListRelRes"),
        (64, "PDUSessionResourceModifyListModReq"),
        (65, "PDUSessionResourceModifyListModRes"),
        (54, "PDUSessionResourceFailedToModifyListModRes"),
        (135, "QosFlowAddOrModifyRequestList"),
        (115, "UEPagingIdentity"),
        (103, "TAIListForPaging"),
        (50, "PagingDRX"),
    ] {
        assert_eq!(codec::ie_name(id), Some(name), "IE {id}");
    }
}

// ----------------------------------------------------------------------------------------------
// Bounds and refusals
// ----------------------------------------------------------------------------------------------

/// A UE-associated PDU whose list IE `list_id` holds `n` outcome-shaped items (pDUSessionID and
/// a transfer); `modreq` adds the ModReq item's nAS-PDU presence bit (always absent).
fn pdu_with_list(
    code: u8,
    kind: PduKind,
    list_id: u16,
    n: usize,
    transfer: &[u8],
    modreq: bool,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.size(n, 1, 256, "list").unwrap();
    for i in 0..n {
        w.bit(false);
        if modreq {
            w.bit(false); // nAS-PDU absent
        }
        w.bit(false);
        w.constrained(i as u64, 0, 255, "psi").unwrap();
        w.octet_string(transfer, "transfer").unwrap();
    }
    let ies = vec![
        codec::amf_ue_ngap_id_ie(1, Criticality::Reject).unwrap(),
        codec::ran_ue_ngap_id_ie(1, Criticality::Reject).unwrap(),
        Ie::new(list_id, Criticality::Reject, w.finish()),
    ];
    codec::encode_pdu(&Pdu::new(kind, code, Criticality::Reject, ies)).unwrap()
}

#[test]
fn pdu_session_lists_beyond_the_bound_are_refused() {
    let max = codec::MAX_PDU_SESSIONS;
    let release = |n| {
        pdu_with_list(
            codec::PROC_PDU_SESSION_RESOURCE_RELEASE,
            PduKind::Initiating,
            codec::IE_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD,
            n,
            &[0x10],
            false,
        )
    };
    let parse = |b: Vec<u8>| {
        codec::parse_pdu_session_resource_release_command(&codec::decode_pdu(&b).unwrap())
    };
    assert_eq!(parse(release(max)).unwrap().sessions.len(), max);
    let err = parse(release(max + 1)).unwrap_err();
    assert!(err.detail.contains("exceeds"), "{err}");

    let released = |n| {
        pdu_with_list(
            codec::PROC_PDU_SESSION_RESOURCE_RELEASE,
            PduKind::Successful,
            codec::IE_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES,
            n,
            &[0x00],
            false,
        )
    };
    let parse_res = |b: Vec<u8>| {
        codec::parse_pdu_session_resource_release_response(&codec::decode_pdu(&b).unwrap())
    };
    assert_eq!(parse_res(released(max)).unwrap().released.len(), max);
    assert!(parse_res(released(max + 1)).is_err());

    let modreq = |n| {
        pdu_with_list(
            codec::PROC_PDU_SESSION_RESOURCE_MODIFY,
            PduKind::Initiating,
            codec::IE_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ,
            n,
            &unhex(MODIFY_REQUEST_TRANSFER),
            true,
        )
    };
    let parse_req = |b: Vec<u8>| {
        codec::parse_pdu_session_resource_modify_request(&codec::decode_pdu(&b).unwrap())
    };
    assert_eq!(parse_req(modreq(max)).unwrap().2.len(), max);
    assert!(parse_req(modreq(max + 1)).is_err());

    for list in [
        codec::IE_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES,
        codec::IE_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_RES,
    ] {
        let transfer = if list == codec::IE_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES {
            unhex("10 00 04")
        } else {
            unhex("00 d0")
        };
        let modres = |n| {
            pdu_with_list(
                codec::PROC_PDU_SESSION_RESOURCE_MODIFY,
                PduKind::Successful,
                list,
                n,
                &transfer,
                false,
            )
        };
        let parse_res = |b: Vec<u8>| {
            codec::parse_pdu_session_resource_modify_response(&codec::decode_pdu(&b).unwrap())
        };
        let ok = parse_res(modres(max)).unwrap();
        assert_eq!(ok.modified.len() + ok.failed.len(), max);
        assert!(parse_res(modres(max + 1)).is_err(), "list {list}");
    }

    // And on the way out.
    let many: Vec<(u8, Cause)> = (0..=max as u8).map(|i| (i, Cause::radio(0))).collect();
    assert!(codec::pdu_session_resource_release_command(1, 1, None, &many).is_err());
    assert!(codec::pdu_session_resource_release_command(1, 1, None, &[]).is_err());
    let ids: Vec<u8> = (0..=max as u8).collect();
    assert!(codec::pdu_session_resource_release_response(1, 1, &ids).is_err());
    assert!(codec::pdu_session_resource_release_response(1, 1, &[]).is_err());
    assert!(codec::pdu_session_resource_modify_response(1, 1, &[], &many).is_err());
    let items: Vec<ModifyItem> = (0..=max as u8)
        .map(|i| ModifyItem {
            pdu_session_id: i,
            nas: None,
            transfer: vec![0],
        })
        .collect();
    assert!(codec::pdu_session_resource_modify_request(1, 1, &items).is_err());
    assert!(codec::pdu_session_resource_modify_request(1, 1, &[]).is_err());
}

/// One QosFlowAddOrModifyRequestItem written field by field with the APER writer.
fn write_add_or_modify_item(w: &mut Writer, qfi: u64, with_params: bool) {
    w.bit(false); // ext
    w.bit(with_params);
    w.bit(false); // e-RAB-ID
    w.bit(false); // iE-Extensions
    w.bit(false); // QFI ext
    w.constrained(qfi, 0, 63, "qfi").unwrap();
    if !with_params {
        return;
    }
    for _ in 0..5 {
        w.bit(false); // QosFlowLevelQosParameters ext + four optionals
    }
    w.constrained(0, 0, 2, "QosCharacteristics").unwrap();
    for _ in 0..5 {
        w.bit(false); // NonDynamic5QIDescriptor ext + four optionals
    }
    w.bit(false); // fiveQI ext
    w.constrained(9, 0, 255, "fiveQI").unwrap();
    w.bit(false);
    w.bit(false);
    w.constrained(8, 1, 15, "arp").unwrap();
    w.enumerated(0, false, 2, true, "cap").unwrap();
    w.enumerated(0, false, 2, true, "vul").unwrap();
}

fn modify_transfer_with_flows(n: usize, with_params: bool) -> Vec<u8> {
    let mut list = Writer::new();
    list.size(n, 1, 64, "QosFlowAddOrModifyRequestList")
        .unwrap();
    for i in 0..n {
        write_add_or_modify_item(&mut list, i as u64, with_params);
    }
    let list = list.finish();
    let mut w = Writer::new();
    w.bit(false);
    w.size(1, 0, 65_535, "container").unwrap();
    w.constrained(
        codec::IE_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST as u64,
        0,
        65_535,
        "id",
    )
    .unwrap();
    w.constrained(0, 0, 2, "crit").unwrap();
    w.open_type(&list, "value").unwrap();
    w.finish()
}

#[test]
fn qos_flow_lists_beyond_the_bound_are_refused() {
    let max = codec::MAX_QOS_FLOWS;
    let ok = codec::decode_modify_request_transfer(&modify_transfer_with_flows(max, true)).unwrap();
    assert_eq!(ok.qos_flows.len(), max);
    assert_eq!(ok.qos_flows[3], flow(3, 9, 8));
    let err = codec::decode_modify_request_transfer(&modify_transfer_with_flows(max + 1, true))
        .unwrap_err();
    assert!(err.detail.contains("exceeds"), "{err}");
    // A flow modified without its QoS parameters cannot be represented as a QosFlow: refused,
    // never guessed.
    let err =
        codec::decode_modify_request_transfer(&modify_transfer_with_flows(1, false)).unwrap_err();
    assert!(err.detail.contains("qosFlowLevelQosParameters"), "{err}");

    // The response transfer's list.
    let response = |n: usize| {
        let mut w = Writer::new();
        for b in [false, false, false, true, false, false, false] {
            w.bit(b);
        }
        w.size(n, 1, 64, "list").unwrap();
        for i in 0..n {
            w.bit(false);
            w.bit(false);
            w.bit(false);
            w.constrained(i as u64, 0, 63, "qfi").unwrap();
        }
        w.finish()
    };
    assert_eq!(
        codec::decode_modify_response_transfer(&response(max))
            .unwrap()
            .qfis
            .len(),
        max
    );
    assert!(codec::decode_modify_response_transfer(&response(max + 1)).is_err());

    // On the way out.
    let too_many = ModifyRequestTransfer {
        ambr_dl_bps: None,
        ambr_ul_bps: None,
        qos_flows: (0..=max as u8).map(|q| flow(q, 9, 8)).collect(),
    };
    assert!(codec::encode_modify_request_transfer(&too_many).is_err());
    assert!(
        codec::encode_modify_response_transfer(&ModifyResponseTransfer {
            qfis: (0..=max as u8).collect()
        })
        .is_err()
    );
    // A one-sided AMBR.
    let lopsided = ModifyRequestTransfer {
        ambr_dl_bps: Some(1),
        ambr_ul_bps: None,
        qos_flows: vec![],
    };
    assert!(codec::encode_modify_request_transfer(&lopsided).is_err());
    let over = ModifyRequestTransfer {
        ambr_dl_bps: Some(codec::MAX_BIT_RATE + 1),
        ambr_ul_bps: Some(1),
        qos_flows: vec![],
    };
    assert!(codec::encode_modify_request_transfer(&over).is_err());
}

#[test]
fn paging_tai_lists_are_bounded() {
    // The constraint is SIZE(1..16) and MAX_PAGING_TAIS is 16: the maximum is accepted both
    // ways, and the fuzz corpus entry that declares it decodes.
    assert_eq!(codec::MAX_PAGING_TAIS, 16);
    let mut p = paging_multi();
    p.tais = (0..codec::MAX_PAGING_TAIS as u32)
        .map(|i| (plmn("001", "01"), i + 1))
        .collect();
    let bytes = codec::paging(&p).unwrap();
    assert_eq!(
        codec::parse_paging(&codec::decode_pdu(&bytes).unwrap())
            .unwrap()
            .tais
            .len(),
        16
    );
    let corpus = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/ngap_nas/paging_max_tais"
    ))
    .unwrap();
    let from_corpus = codec::parse_paging(&codec::decode_pdu(&corpus).unwrap()).unwrap();
    assert_eq!(from_corpus.tais.len(), 16);
    assert_eq!(from_corpus.tais[15], (plmn("001", "01"), 16));
    // Seventeen cannot be encoded, and none is too few.
    p.tais.push((plmn("001", "01"), 17));
    assert!(codec::paging(&p).is_err());
    p.tais.clear();
    assert!(codec::paging(&p).is_err());
    // Values outside their constraints are refused on the way out.
    let mut p = paging_multi();
    p.tais[0].1 = 0x100_0000;
    assert!(codec::paging(&p).is_err());
    let mut p = paging_multi();
    p.tais[0].0 = plmn("1", "01");
    assert!(codec::paging(&p).is_err());
    let mut p = paging_multi();
    p.amf_set_id = 0x400;
    assert!(codec::paging(&p).is_err());
    let mut p = paging_multi();
    p.paging_drx = Some("v512".into());
    assert!(codec::paging(&p).is_err());
}

#[test]
fn a_paging_identity_in_choice_extensions_is_refused() {
    // Index 1 of UEPagingIdentity is choice-Extensions, which NetGet does not decode.
    let mut pdu = codec::decode_pdu(&unhex(PAGING)).unwrap();
    let ie = pdu
        .ies
        .iter_mut()
        .find(|ie| ie.id == codec::IE_UE_PAGING_IDENTITY)
        .unwrap();
    ie.value[0] |= 0x80;
    assert!(codec::parse_paging(&pdu).is_err());
    // A missing mandatory TAI list is an abstract syntax error.
    let mut pdu = codec::decode_pdu(&unhex(PAGING)).unwrap();
    pdu.ies.retain(|ie| ie.id != codec::IE_TAI_LIST_FOR_PAGING);
    assert_eq!(
        codec::parse_paging(&pdu).unwrap_err().cause,
        Cause::protocol(codec::PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT)
    );
}

#[test]
fn truncated_inputs_are_refused_without_panicking() {
    let pdus = [
        release_command_multi(),
        codec::pdu_session_resource_release_response(1, 1, &[1, 2]).unwrap(),
        modify_request_multi(),
        modify_response_multi(),
        codec::paging(&paging_multi()).unwrap(),
    ];
    for bytes in &pdus {
        for cut in 0..bytes.len() {
            assert!(
                codec::decode_pdu(&bytes[..cut]).is_err(),
                "a PDU cut at {cut} of {} decoded",
                bytes.len()
            );
        }
        // Each IE value cut short, handed to every new parser.
        let pdu = codec::decode_pdu(bytes).unwrap();
        for i in 0..pdu.ies.len() {
            for cut in 0..pdu.ies[i].value.len() {
                let mut short = pdu.clone();
                short.ies[i].value.truncate(cut);
                let parsed = match pdu.procedure_code {
                    codec::PROC_PAGING => codec::parse_paging(&short).is_ok(),
                    codec::PROC_PDU_SESSION_RESOURCE_RELEASE if pdu.kind == PduKind::Initiating => {
                        codec::parse_pdu_session_resource_release_command(&short).is_ok()
                    }
                    codec::PROC_PDU_SESSION_RESOURCE_RELEASE => {
                        codec::parse_pdu_session_resource_release_response(&short).is_ok()
                    }
                    codec::PROC_PDU_SESSION_RESOURCE_MODIFY if pdu.kind == PduKind::Initiating => {
                        codec::parse_pdu_session_resource_modify_request(&short).is_ok()
                    }
                    _ => codec::parse_pdu_session_resource_modify_response(&short).is_ok(),
                };
                assert!(
                    !parsed,
                    "{} with IE {} cut at {cut} parsed",
                    pdu.label(),
                    pdu.ies[i].id
                );
            }
        }
    }
    // The transfers on their own.
    let transfers: [(&str, Vec<u8>); 4] = [
        (
            "release command",
            codec::encode_release_command_transfer(&Cause::radio(20)).unwrap(),
        ),
        ("modify request", unhex(MODIFY_REQUEST_TRANSFER)),
        (
            "modify response",
            codec::encode_modify_response_transfer(&ModifyResponseTransfer {
                qfis: vec![1, 2, 3],
            })
            .unwrap(),
        ),
        ("release response", vec![0x00]),
    ];
    for (what, t) in &transfers {
        for cut in 0..t.len() {
            let short = &t[..cut];
            let ok = match *what {
                "release command" => codec::decode_release_command_transfer(short).is_ok(),
                "modify request" => codec::decode_modify_request_transfer(short).is_ok(),
                "modify response" => codec::decode_modify_response_transfer(short).is_ok(),
                _ => codec::decode_release_response_transfer(short).is_ok(),
            };
            assert!(!ok, "the {what} transfer cut at {cut} decoded");
        }
    }
    // Arbitrary octets never panic any of them.
    for seed in 0u32..512 {
        let bytes: Vec<u8> = (0..(seed % 40))
            .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i * 97) >> 7) as u8)
            .collect();
        let _ = codec::decode_release_command_transfer(&bytes);
        let _ = codec::decode_release_response_transfer(&bytes);
        let _ = codec::decode_modify_request_transfer(&bytes);
        let _ = codec::decode_modify_response_transfer(&bytes);
        if let Ok(pdu) = codec::decode_pdu(&bytes) {
            let _ = codec::parse_paging(&pdu);
            let _ = codec::parse_pdu_session_resource_release_command(&pdu);
            let _ = codec::parse_pdu_session_resource_release_response(&pdu);
            let _ = codec::parse_pdu_session_resource_modify_request(&pdu);
            let _ = codec::parse_pdu_session_resource_modify_response(&pdu);
        }
    }
}

// ----------------------------------------------------------------------------------------------
// The independent dissector
// ----------------------------------------------------------------------------------------------

#[test]
fn tshark_dissects_the_new_procedures_cleanly() {
    let uli =
        json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}});
    let service = codec::initial_ue_message_with_tmsi(
        1,
        &unhex("7e 00 4c 10 00 07 f4 00 42 c0 ff ee 01"),
        &uli,
        "mo-Data",
        Some((1, 2, 0xc0ff_ee01)),
    )
    .unwrap();
    assert_ngap_clean(&[
        (
            true,
            unhex(&format!(
                "00 1c 00 18 00 00 03 {IDS_REJECT} 00 4f 00 05 00 00 01 01 10"
            )),
        ),
        (true, release_command_multi()),
        (
            false,
            codec::pdu_session_resource_release_response(3, 4, &[1, 2, 3]).unwrap(),
        ),
        (true, modify_request_multi()),
        (false, modify_response_multi()),
        (true, codec::paging(&paging_multi()).unwrap()),
        (true, unhex(PAGING)),
        (false, service),
    ]);
}

#[test]
fn tshark_reads_the_values_netget_meant() {
    let uli =
        json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}});
    let service = codec::initial_ue_message_with_tmsi(
        1,
        &unhex("7e 00 4c 10 00 07 f4 00 42 c0 ff ee 01"),
        &uli,
        "mo-Data",
        Some((0x3ff, 0x3f, 0xdead_beef)),
    )
    .unwrap();
    let pdus = vec![
        release_command_multi(),
        codec::pdu_session_resource_release_response(3, 4, &[1, 2, 3]).unwrap(),
        modify_request_multi(),
        modify_response_multi(),
        codec::paging(&paging_multi()).unwrap(),
        unhex(PAGING),
        service,
    ];
    let rows = tshark_fields(
        &pdus,
        &[
            "ngap.procedureCode",
            "ngap.id",
            "ngap.pDUSessionID",
            "ngap.nas",
            "ngap.radioNetwork",
            "ngap.NAS_PDU",
            "ngap.qosFlowIdentifier",
            "ngap.fiveQI",
            "ngap.priorityLevelARP",
            "ngap.pDUSessionAggregateMaximumBitRateDL",
            "ngap.pDUSessionAggregateMaximumBitRateUL",
            "ngap.aMFSetID",
            "ngap.aMFPointer",
            "ngap.fiveG_TMSI",
            "ngap.tAC",
            "ngap.pLMNIdentity",
            "ngap.PagingDRX",
            "ngap.AMF_UE_NGAP_ID",
            "ngap.RAN_UE_NGAP_ID",
            // A ModReq item's nAS-PDU is a SEQUENCE member, not an IE: its own field.
            "ngap.nAS_PDU",
        ],
    );
    let col = |row: usize, i: usize| rows[row][i].as_str();

    // Release Command: both sessions, each transfer's cause, the NAS-PDU octets and the ids.
    assert_eq!(col(0, 0), "28");
    assert_eq!(col(0, 1), "10,85,38,79");
    assert_eq!(col(0, 2), "1,2");
    assert_eq!(col(0, 3), "0", "nas/normal-release");
    assert_eq!(col(0, 4), "20", "radioNetwork/user-inactivity");
    assert_eq!(col(0, 5), hex::encode(unhex(RELEASE_NAS)));
    assert_eq!(col(0, 17), (0x12_3456_789au64).to_string());
    assert_eq!(col(0, 18), "65536");
    // Release Response.
    assert_eq!(col(1, 0), "28");
    assert_eq!(col(1, 1), "10,85,70");
    assert_eq!(col(1, 2), "1,2,3");
    // Modify Request: sessions 5 and 6, three flows, one AMBR.
    assert_eq!(col(2, 0), "26");
    assert_eq!(col(2, 1), "10,85,64,130,135,135");
    assert_eq!(col(2, 2), "5,6");
    assert_eq!(col(2, 5), "", "no message-level NAS-PDU IE");
    assert_eq!(col(2, 19), hex::encode(unhex(MODIFY_NAS)));
    assert_eq!(col(2, 6), "1,2,3");
    assert_eq!(col(2, 7), "9,8,7");
    assert_eq!(col(2, 8), "8,1,15");
    assert_eq!(col(2, 9), "2000000000");
    assert_eq!(col(2, 10), "1");
    // Modify Response: modified 5 (QFIs 1, 2) and 7, failed 6 with its cause.
    assert_eq!(col(3, 0), "26");
    assert_eq!(col(3, 1), "10,85,65,54");
    assert_eq!(col(3, 2), "5,7,6");
    assert_eq!(col(3, 4), "26", "radioNetwork/unknown-PDU-session-ID");
    assert_eq!(col(3, 6), "1,2");
    // Paging: the 5G-S-TMSI, both TAIs (a three-digit MNC among them), no DRX.
    assert_eq!(col(4, 0), "24");
    assert_eq!(col(4, 1), "115,103");
    assert_eq!(col(4, 11), "ffc0", "AMF set 1023, ten bits left-aligned");
    assert_eq!(col(4, 12), "fc", "AMF pointer 63, six bits left-aligned");
    assert_eq!(col(4, 13), 0xdead_beefu32.to_string());
    assert_eq!(col(4, 14), format!("1,{}", 0xab_cdef));
    assert_eq!(col(4, 15), "00f110,130014");
    assert_eq!(col(4, 16), "");
    // The hand-derived Paging, read by the dissector: set 1 -> 0040, pointer 2 -> 08, v128 = 2.
    assert_eq!(col(5, 11), "0040");
    assert_eq!(col(5, 12), "08");
    assert_eq!(col(5, 13), 0xc0ff_ee01u32.to_string());
    assert_eq!(col(5, 14), "1");
    assert_eq!(col(5, 16), "2");
    // Initial UE Message with its FiveG-S-TMSI.
    assert_eq!(col(6, 0), "15");
    assert_eq!(col(6, 1), "85,38,121,90,26");
    assert_eq!(col(6, 11), "ffc0");
    assert_eq!(col(6, 12), "fc");
    assert_eq!(col(6, 13), 0xdead_beefu32.to_string());
}
