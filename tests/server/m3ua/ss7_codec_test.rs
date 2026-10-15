//! The SS7 upper stack's codecs and dialogue engine, against third-party bytes.
//!
//! The requests are what Restcomm jSS7 8.0.112 put on the wire (`ss7_support::jss7`), and for the
//! MAP operations so are the expected answers: NetGet, given the same answer fields as jSS7's own
//! server, must produce **the same octets** — SCCP addresses, TCAP dialogue portion, components
//! and all. Where an expectation is not a jSS7 capture it is written from the specification with
//! the decode in a comment. tshark's m3ua / sccp / tcap / gsm_map / camel dissectors read every
//! message NetGet emits here.
//!
//! No sockets and no model: [`Engine`] is driven directly.

use super::ss7_support::{
    from_jss7, ip_sctp_m3ua, jss7, m3ua_data, tshark_verbose, unhex, with_dtid,
};
use netget::server::m3ua::ber::{self, Tag};
use netget::server::m3ua::codec::ProtocolData;
use netget::server::m3ua::gsm;
use netget::server::m3ua::sccp;
use netget::server::m3ua::ss7::{Engine, Family, Inbound, Outgoing, Ss7Event};
use netget::server::m3ua::tcap::{self, TcMessage};
use netget::utils::clock::Instant;
use serde_json::{json, Value};

fn event(inbound: Inbound) -> Ss7Event {
    match inbound {
        Inbound::Event(e) => e,
        other => panic!("expected an event for the model, got {other:?}"),
    }
}

fn handled(inbound: Inbound) -> (Vec<Outgoing>, String) {
    match inbound {
        Inbound::Handled { replies, note } => (replies, note),
        other => panic!("expected Rust to answer, got {other:?}"),
    }
}

fn begin(engine: &mut Engine, sccp_hex: &str) -> Ss7Event {
    event(engine.on_data(&from_jss7(sccp_hex, 1), Some(100), None, Instant::now()))
}

fn answer(engine: &mut Engine, intent: Value) -> Outgoing {
    engine
        .apply(&intent, None, 0, Instant::now())
        .unwrap_or_else(|e| panic!("{intent} was refused: {e}"))
        .1
}

fn tcap_of(out: &Outgoing) -> TcMessage {
    let ud = sccp::decode(&out.protocol_data.payload).unwrap();
    TcMessage::decode(&ud.data).unwrap()
}

// ---------------------------------------------------------------------------
// GSM encodings, from the specifications
// ---------------------------------------------------------------------------

#[test]
fn tbcd_and_address_strings_match_ts_29_002() {
    // TS 29.002 17.7.8: digits low nibble first, odd count filled with F. jSS7 wrote IMSI
    // 001010123456789 as 00 01 01 21 43 65 87 f9.
    assert_eq!(
        gsm::imsi_encode("001010123456789").unwrap(),
        unhex("00010121436587f9")
    );
    assert_eq!(
        gsm::tbcd_decode(&unhex("00010121436587f9")),
        "001010123456789"
    );
    // ISDN-AddressString: ext 1, nature international (001), plan ISDN (0001) = 0x91.
    let a = gsm::Address::international("31628838002");
    assert_eq!(a.encode(16).unwrap(), unhex("911326888300f2"));
    assert_eq!(gsm::Address::decode(&unhex("911326888300f2")).unwrap(), a);
    assert!(
        gsm::imsi_encode("12345").is_err(),
        "IMSI shorter than 6 digits"
    );
    assert!(gsm::Address::international("1234567890123456789")
        .encode(16)
        .is_err());
}

#[test]
fn gsm_7bit_packing_matches_ts_23_038() {
    // TS 23.038 6.1.2.1.1's worked example: "hellohello" packs to E8 32 9B FD 46 97 D9 EC 37.
    let septets = gsm::gsm7_septets("hellohello").unwrap();
    assert_eq!(gsm::pack_septets(&septets, 0), unhex("e8329bfd4697d9ec37"));
    // jSS7's USSD "*100#" is AA 18 0C 36 02.
    let (dcs, octets) = gsm::ussd_encode("*100#").unwrap();
    assert_eq!((dcs, octets.clone()), (0x0f, unhex("aa180c3602")));
    assert_eq!(gsm::ussd_decode(0x0f, &octets).as_deref(), Some("*100#"));
    // 6.1.2.3.1: seven characters leave seven spare bits, which carry CR rather than zeros
    // (zeros would read as a trailing '@').
    let (_, seven) = gsm::ussd_encode("ABCDEFG").unwrap();
    assert_eq!(seven.len(), 7);
    assert_eq!(seven[6] >> 1, 0x0d, "the spare bits hold CR");
    assert_eq!(gsm::ussd_decode(0x0f, &seven).as_deref(), Some("ABCDEFG"));
    // The extension table: '€' is ESC 0x65.
    assert_eq!(gsm::gsm7_septets("€").unwrap(), vec![0x1b, 0x65]);
    // Outside the alphabet goes UCS2 (DCS 0x48).
    let (dcs, ucs2) = gsm::ussd_encode("Ж").unwrap();
    assert_eq!((dcs, ucs2), (0x48, vec![0x04, 0x16]));
}

#[test]
fn sms_tpdus_jss7_built_decode_field_by_field() {
    // The SMS-SUBMIT inside jSS7's mo-forwardSM: TP-VPF relative (one octet, A7), TP-DA
    // 31622222222, GSM 7-bit "Hello from jSS7".
    let submit = gsm::sms_tpdu_decode(
        &unhex("11010b911326222222f20000a70fc8329bfd0699e5ef36483d9dde00"),
        true,
    )
    .unwrap();
    assert_eq!(submit["tpdu"], "sms_submit");
    assert_eq!(submit["destination"]["digits"], "31622222222");
    assert_eq!(submit["user_data"]["text"], "Hello from jSS7");
    // The SMS-DELIVER inside its mt-forwardSM.
    let deliver = gsm::sms_tpdu_decode(
        &unhex("040b911336333333f30000620151210000000fc8329bfd0699e5ef36483d9dde00"),
        false,
    )
    .unwrap();
    assert_eq!(deliver["originator"]["digits"], "31633333333");
    assert_eq!(deliver["user_data"]["text"], "Hello from jSS7");
    assert_eq!(
        deliver["service_centre_timestamp"],
        "2026-10-15T12:00:00+00:00"
    );
    // NetGet's SMS-SUBMIT round-trips through the same decoder and carries the text.
    let mine =
        gsm::sms_submit_encode(&json!({"destination": "31622222222", "text": "Hello from jSS7"}))
            .unwrap();
    assert_eq!(
        gsm::sms_tpdu_decode(&mine, true).unwrap()["user_data"]["text"],
        "Hello from jSS7"
    );
}

// ---------------------------------------------------------------------------
// BER bounds
// ---------------------------------------------------------------------------

#[test]
fn ber_refuses_a_depth_bomb_and_an_element_flood() {
    // 2000 nested SEQUENCEs with indefinite lengths: two octets a level.
    let mut bomb = Vec::new();
    for _ in 0..2000 {
        bomb.extend_from_slice(&[0x30, 0x80]);
    }
    for _ in 0..2000 {
        bomb.extend_from_slice(&[0x00, 0x00]);
    }
    let e = ber::decode(&bomb).unwrap_err();
    assert!(e.0.contains("nesting deeper"), "{e}");
    // Exactly the bound is refused, one less is accepted.
    let nest = |n: usize| {
        let mut v = vec![0x05, 0x00];
        for _ in 0..n {
            v = ber::tlv(Tag::SEQUENCE, &v);
        }
        v
    };
    assert!(ber::decode(&nest(ber::MAX_BER_DEPTH - 1)).is_ok());
    assert!(ber::decode(&nest(ber::MAX_BER_DEPTH)).is_err());
    // A flat SEQUENCE of NULLs past the element budget.
    let flood: Vec<u8> = std::iter::repeat_n([0x05u8, 0x00], ber::MAX_BER_ELEMENTS + 1)
        .flatten()
        .collect();
    let e = ber::decode(&ber::tlv(Tag::SEQUENCE, &flood)).unwrap_err();
    assert!(e.0.contains("elements"), "{e}");
    // A length that runs past the input, and one over four octets.
    assert!(ber::decode(&unhex("3005020101")).is_err());
    assert!(ber::decode(&unhex("0485000000000100")).is_err());
    // High tag numbers: CAP's [50] is 9F 32.
    assert_eq!(Tag::context(50, false).encode(), vec![0x9f, 0x32]);
    let t = ber::decode(&unhex("9f320100")).unwrap();
    assert!(t.tag.is_context(50));
}

#[test]
fn a_tcap_depth_bomb_from_the_wire_is_p_aborted_not_followed() {
    // A TC-BEGIN whose component portion nests far past the bound.
    let mut inner = vec![0x05, 0x00];
    for _ in 0..40 {
        inner = ber::tlv(Tag::SEQUENCE, &inner);
    }
    let comps = ber::tlv(
        Tag::application(12, true),
        &ber::tlv(Tag::context(1, true), &inner),
    );
    let begin = ber::seq(
        Tag::application(2, true),
        &[ber::tlv(Tag::application(8, false), &[0, 0, 0, 9]), comps],
    );
    let ud = sccp::decode(&unhex(jss7::SRI_SM_BEGIN)).unwrap();
    let pd = ProtocolData {
        payload: sccp::encode_udt(1, false, &ud.called, &ud.calling, &begin).unwrap(),
        ..from_jss7(jss7::SRI_SM_BEGIN, 1)
    };
    let mut engine = Engine::new();
    let (replies, note) = handled(engine.on_data(&pd, None, None, Instant::now()));
    assert!(note.contains("refused_malformed"), "{note}");
    let abort = tcap_of(&replies[0]);
    assert_eq!(abort.dtid.as_deref(), Some(&[0u8, 0, 0, 9][..]));
    assert_eq!(
        abort.p_abort_cause,
        Some(tcap::P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION)
    );
    assert_eq!(engine.open_dialogues(), 0);
}

// ---------------------------------------------------------------------------
// MAP: jSS7's requests decoded, NetGet's answers identical to jSS7's
// ---------------------------------------------------------------------------

#[test]
fn send_routing_info_for_sm_decodes_and_the_answer_is_jss7s_octets() {
    let mut engine = Engine::new();
    let ev = begin(&mut engine, jss7::SRI_SM_BEGIN);
    assert_eq!(ev.family, Family::Map);
    let d = &ev.data;
    assert_eq!(d["application_context"]["name"], "shortMsgGatewayContext");
    assert_eq!(d["application_context"]["version"], 3);
    let invoke = &d["components"][0];
    assert_eq!(invoke["operation"], "sendRoutingInfoForSM");
    assert_eq!(invoke["invoke_id"], 0);
    assert_eq!(invoke["argument"]["msisdn"]["digits"], "31628838002");
    assert_eq!(invoke["argument"]["msisdn"]["nature"], "international");
    assert_eq!(
        invoke["argument"]["service_centre_address"]["digits"],
        "31611111111"
    );
    assert_eq!(invoke["argument"]["sm_rp_pri"], true);
    assert_eq!(d["awaiting_answer_to"], json!([0]));
    assert_eq!(d["route"]["remote_address"]["gt"]["digits"], "31600000100");
    assert!(engine.awaiting_answer(ev.dialogue_id));

    let out = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": ev.dialogue_id,
               "result": {"imsi": "001010123456789", "network_node_number": "31600000001"}}),
    );
    // Same SCCP addresses (swapped), same TCAP: AARE accepted, ReturnResultLast with the
    // imsi and LocationInfoWithLMSI, byte for byte what jSS7's HLR sent.
    assert_eq!(hex::encode(&out.protocol_data.payload), jss7::SRI_SM_END);
    assert_eq!((out.protocol_data.opc, out.protocol_data.dpc), (2, 1));
    assert_eq!(out.routing_context, Some(100));
    assert!(!engine.awaiting_answer(ev.dialogue_id));
    assert_eq!(engine.open_dialogues(), 0, "TC-END closes the dialogue");
}

#[test]
fn any_time_interrogation_answer_is_jss7s_octets() {
    let mut engine = Engine::new();
    let ev = begin(&mut engine, jss7::ATI_BEGIN);
    let arg = &ev.data["components"][0]["argument"];
    assert_eq!(arg["subscriber"]["msisdn"]["digits"], "31628838002");
    assert_eq!(
        arg["requested_info"],
        json!(["location_information", "subscriber_state"])
    );
    assert_eq!(arg["gsm_scf_address"]["digits"], "31699999999");
    let out = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": ev.dialogue_id, "result": {
            "subscriber_state": "assumedIdle",
            "location_information": {"age_of_location_information": 5, "vlr_number": "31600000002",
                "cell_global_id": {"mcc": "001", "mnc": "01", "lac": 4660, "cell_id": 22136}}}}),
    );
    assert_eq!(hex::encode(&out.protocol_data.payload), jss7::ATI_END);
}

#[test]
fn ussd_decodes_its_map_open_and_the_answer_is_jss7s_octets() {
    let mut engine = Engine::new();
    let ev = begin(&mut engine, jss7::USSD_BEGIN);
    let d = &ev.data;
    assert_eq!(
        d["components"][0]["operation"],
        "processUnstructuredSS-Request"
    );
    assert_eq!(d["components"][0]["argument"]["ussd_text"], "*100#");
    assert_eq!(
        d["components"][0]["argument"]["ussd_data_coding_scheme"],
        15
    );
    assert_eq!(
        d["dialogue_portion"]["map_open"]["destination_reference"]["digits"],
        "31628838002"
    );
    assert_eq!(
        d["dialogue_portion"]["map_open"]["origination_reference"]["digits"],
        "31600000100"
    );
    let out = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": ev.dialogue_id,
               "operation": "processUnstructuredSS-Request",
               "result": {"ussd_text": "You sent *100#"}}),
    );
    assert_eq!(hex::encode(&out.protocol_data.payload), jss7::USSD_END);
}

#[test]
fn forward_short_message_both_directions_decode_and_answer_as_jss7() {
    let mut engine = Engine::new();
    let mo = begin(&mut engine, jss7::MO_FSM_BEGIN);
    let arg = &mo.data["components"][0]["argument"];
    assert_eq!(mo.data["components"][0]["operation"], "mo-forwardSM");
    assert_eq!(
        arg["sm_rp_da"]["service_centre_address"]["digits"],
        "31611111111"
    );
    assert_eq!(arg["sm_rp_oa"]["msisdn"]["digits"], "31628838002");
    assert_eq!(arg["sms"]["destination"]["digits"], "31622222222");
    assert_eq!(arg["sms"]["user_data"]["text"], "Hello from jSS7");
    let out = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": mo.dialogue_id, "result": {}}),
    );
    assert_eq!(hex::encode(&out.protocol_data.payload), jss7::MO_FSM_END);

    let mt = begin(&mut engine, jss7::MT_FSM_BEGIN);
    let arg = &mt.data["components"][0]["argument"];
    assert_eq!(arg["sm_rp_da"]["imsi"], "001010123456789");
    assert_eq!(arg["sms"]["tpdu"], "sms_deliver");
    assert_eq!(arg["sms"]["originator"]["digits"], "31633333333");
    let out = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": mt.dialogue_id, "result": {}}),
    );
    assert_eq!(hex::encode(&out.protocol_data.payload), jss7::MT_FSM_END);
}

#[test]
fn a_map_error_carries_the_code_and_closes_the_dialogue() {
    let mut engine = Engine::new();
    let ev = begin(&mut engine, jss7::SRI_SM_BEGIN);
    let out = answer(
        &mut engine,
        json!({"type": "send_map_error", "dialogue_id": ev.dialogue_id, "error": "unknownSubscriber"}),
    );
    let m = tcap_of(&out);
    assert_eq!(m.kind, tcap::TcKind::End);
    assert!(matches!(
        m.dialogue,
        Some(tcap::DialoguePdu::Response { result: 0, .. })
    ));
    // ReturnError: invokeID 0, local error code 1.
    let comp = hex::encode(m.components[0].encode());
    assert_eq!(comp, "a306020100020101");
}

// ---------------------------------------------------------------------------
// Fail closed and the transaction table
// ---------------------------------------------------------------------------

#[test]
fn an_unanswerable_map_dialogue_fails_closed_with_system_failure_not_success() {
    let mut engine = Engine::new();
    let ev = begin(&mut engine, jss7::SRI_SM_BEGIN);
    let out = engine.close_unanswered(ev.dialogue_id, true).unwrap();
    let m = tcap_of(&out);
    assert_eq!(m.kind, tcap::TcKind::End);
    // AARE accepted so the MAP user sees the error, then ReturnError systemFailure (34).
    assert!(matches!(
        m.dialogue,
        Some(tcap::DialoguePdu::Response { result: 0, .. })
    ));
    assert_eq!(hex::encode(m.components[0].encode()), "a306020100020122");
    assert_eq!(engine.open_dialogues(), 0);

    // Silence is a TC-U-ABORT: before the AARE went out, an AARE with result reject-permanent.
    let ev = begin(&mut engine, jss7::SRI_SM_BEGIN);
    let out = engine.close_unanswered(ev.dialogue_id, false).unwrap();
    let m = tcap_of(&out);
    assert_eq!(m.kind, tcap::TcKind::Abort);
    assert!(matches!(
        m.dialogue,
        Some(tcap::DialoguePdu::Response {
            result: 1,
            diagnostic: tcap::DIAG_USER_NO_REASON_GIVEN,
            ..
        })
    ));
    assert!(m.components.is_empty(), "no fabricated result");
}

#[test]
fn a_continue_for_an_unknown_transaction_is_p_aborted() {
    let mut engine = Engine::new();
    // An open dialogue that the Continue must NOT be matched to.
    let open = begin(&mut engine, jss7::IDP_BEGIN);
    assert_ne!(open.dialogue_id, 0x0bad_cafe);
    let (replies, note) = handled(engine.on_data(
        &from_jss7(&with_dtid(jss7::ERB_ANSWER, 0x0bad_cafe), 1),
        None,
        None,
        Instant::now(),
    ));
    assert!(note.contains("refused_transaction"), "{note}");
    // TC-ABORT dtid = their otid 00000001, P-AbortCause unrecognizedTransactionID (1).
    let ud = sccp::decode(&replies[0].protocol_data.payload).unwrap();
    assert_eq!(hex::encode(&ud.data), "67094904000000014a0101");
}

#[test]
fn the_dialogue_cap_and_the_component_cap_are_resource_limitation() {
    let mut engine = Engine::new();
    engine.max_dialogues = 2;
    begin(&mut engine, jss7::SRI_SM_BEGIN);
    begin(&mut engine, jss7::ATI_BEGIN);
    let (replies, note) =
        handled(engine.on_data(&from_jss7(jss7::USSD_BEGIN, 1), None, None, Instant::now()));
    assert!(note.contains("refused_dialogue_cap"), "{note}");
    assert_eq!(
        tcap_of(&replies[0]).p_abort_cause,
        Some(tcap::P_ABORT_RESOURCE_LIMITATION)
    );
    assert_eq!(engine.open_dialogues(), 2);

    // 17 components in one TC-BEGIN.
    let invoke = unhex("a106020101020138");
    let comps: Vec<u8> = std::iter::repeat_n(invoke, tcap::MAX_COMPONENTS + 1)
        .flatten()
        .collect();
    let msg = ber::seq(
        Tag::application(2, true),
        &[
            ber::tlv(Tag::application(8, false), &[1]),
            ber::tlv(Tag::application(12, true), &comps),
        ],
    );
    let (_, cause) = TcMessage::decode(&msg)
        .map(|_| ())
        .map_err(|(c, e)| (e, c))
        .unwrap_err();
    assert_eq!(cause, tcap::P_ABORT_RESOURCE_LIMITATION);
}

#[test]
fn an_unimplemented_operation_is_rejected_without_the_model() {
    // jSS7's SRI-SM Begin with the operation code changed to 56 (sendAuthenticationInfo).
    let vector = jss7::SRI_SM_BEGIN.replace("02012d3015", "0201383015");
    let mut engine = Engine::new();
    let (replies, note) =
        handled(engine.on_data(&from_jss7(&vector, 1), None, None, Instant::now()));
    assert!(note.contains("rejected_operation"), "{note}");
    let m = tcap_of(&replies[0]);
    assert_eq!(m.kind, tcap::TcKind::End);
    // Reject, invokeID 0, invoke problem unrecognizedOperation.
    assert_eq!(hex::encode(m.components[0].encode()), "a406020100810101");
}

#[test]
fn an_unknown_application_context_is_refused_with_an_aare_reject() {
    // jSS7's SRI-SM Begin naming application context {0 4 0 0 1 0 99 3}.
    let vector = jss7::SRI_SM_BEGIN.replacen("0607040000010014036c", "0607040000010063036c", 1);
    let mut engine = Engine::new();
    let (replies, note) =
        handled(engine.on_data(&from_jss7(&vector, 1), None, None, Instant::now()));
    assert!(note.contains("refused_application_context"), "{note}");
    let m = tcap_of(&replies[0]);
    assert_eq!(m.kind, tcap::TcKind::Abort);
    assert!(matches!(
        m.dialogue,
        Some(tcap::DialoguePdu::Response {
            result: 1,
            diagnostic: tcap::DIAG_USER_ACN_NOT_SUPPORTED,
            ..
        })
    ));
}

#[test]
fn a_segmented_xudt_is_refused_with_segmentation_not_supported() {
    let ud = sccp::decode(&unhex(jss7::SRI_SM_BEGIN)).unwrap();
    let called = ud.called.encode().unwrap();
    let calling = ud.calling.encode().unwrap();
    // XUDT, class 1 with return-on-error, hop counter 15, then a Segmentation parameter
    // (first segment, 2 remaining, local reference 0x000001).
    let mut x = vec![
        0x11,
        0x81,
        0x0f,
        4,
        (4 + called.len()) as u8,
        (4 + called.len() + calling.len()) as u8,
    ];
    let data = &ud.data[..20];
    // The optional-part pointer counts from its own octet (6) to the first optional parameter.
    x.push((4 + called.len() + calling.len() + data.len()) as u8);
    x.push(called.len() as u8);
    x.extend(&called);
    x.push(calling.len() as u8);
    x.extend(&calling);
    x.push(data.len() as u8);
    x.extend(data);
    x.extend([sccp::PARAM_SEGMENTATION, 4, 0x82, 0x00, 0x00, 0x01, 0x00]);
    let decoded = sccp::decode(&x).unwrap();
    assert_eq!(decoded.segmentation.unwrap().remaining, 2);
    let pd = ProtocolData {
        payload: x,
        ..from_jss7(jss7::SRI_SM_BEGIN, 1)
    };
    let mut engine = Engine::new();
    let (replies, note) = handled(engine.on_data(&pd, None, None, Instant::now()));
    assert!(note.contains("refused_segmented"), "{note}");
    let back = sccp::decode(&replies[0].protocol_data.payload).unwrap();
    assert_eq!(back.message_type, sccp::MSG_XUDTS);
    assert_eq!(
        back.return_cause,
        Some(sccp::CAUSE_SEGMENTATION_NOT_SUPPORTED)
    );
}

#[test]
fn sst_is_answered_ssa_in_rust() {
    // A UDT to SSN 1 carrying SST for SSN 6 at PC 2.
    let calling = sccp::SccpAddress {
        route_on_gt: false,
        point_code: Some(1),
        ssn: Some(1),
        global_title: None,
        national: false,
    };
    let called = sccp::SccpAddress {
        point_code: Some(2),
        ..calling.clone()
    };
    let sst = sccp::encode_udt(0, false, &called, &calling, &unhex("0306020000")).unwrap();
    let pd = ProtocolData {
        payload: sst,
        ..from_jss7(jss7::SRI_SM_BEGIN, 0)
    };
    let mut engine = Engine::new();
    let (replies, _) = handled(engine.on_data(&pd, None, None, Instant::now()));
    let ud = sccp::decode(&replies[0].protocol_data.payload).unwrap();
    assert_eq!(hex::encode(&ud.data), "0106020000");
    assert_eq!(ud.called.point_code, Some(1));
}

// ---------------------------------------------------------------------------
// CAP: jSS7's gsmSSF
// ---------------------------------------------------------------------------

#[test]
fn camel_initial_dp_then_armed_events_on_the_same_transaction() {
    let mut engine = Engine::new();
    let idp = begin(&mut engine, jss7::IDP_BEGIN);
    assert_eq!(idp.family, Family::Cap);
    let arg = &idp.data["components"][0]["argument"];
    assert_eq!(
        idp.data["application_context"]["name"],
        "capV2-gsmSSF-to-gsmSCF"
    );
    assert_eq!(arg["service_key"], 100);
    assert_eq!(arg["called_party_number"]["digits"], "31644444444");
    assert_eq!(arg["calling_party_number"]["digits"], "31655555555");
    assert_eq!(arg["event_type_bcsm"], "collectedInfo");
    assert_eq!(arg["imsi"], "001010123456789");
    assert_eq!(arg["msc_address"]["digits"], "31600000003");
    assert!(engine.awaiting_answer(idp.dialogue_id));

    // Arm oAnswer (notify) and oDisconnect (interrupted) and let the call continue.
    let out = answer(
        &mut engine,
        json!({"type": "send_cap_operations", "dialogue_id": idp.dialogue_id, "operations": [
            {"operation": "requestReportBCSMEvent", "bcsm_events": [
                {"event_type_bcsm": "oAnswer", "monitor_mode": "notifyAndContinue", "leg": 2},
                {"event_type_bcsm": "oDisconnect", "monitor_mode": "interrupted", "leg": 2}]},
            {"operation": "continue"}]}),
    );
    let m = tcap_of(&out);
    assert_eq!(
        m.kind,
        tcap::TcKind::Continue,
        "arming events keeps the dialogue open"
    );
    // The RRBCSM argument is octet for octet the one jSS7's gsmSCF sent for the same events.
    let jss7_scf = tcap_of(&Outgoing {
        protocol_data: from_jss7(jss7::IDP_CONTINUE, 1),
        routing_context: None,
        network_appearance: None,
        label: String::new(),
    });
    let param = |c: &tcap::Component| match c {
        tcap::Component::Invoke { parameter, .. } => {
            parameter.as_ref().map(|p| hex::encode(p.encode()))
        }
        _ => None,
    };
    assert_eq!(param(&m.components[0]), param(&jss7_scf.components[0]));

    // The gsmSSF's notification arrives on the SCF's transaction and needs no answer...
    let tid = idp.dialogue_id;
    let ev = event(engine.on_data(
        &from_jss7(&with_dtid(jss7::ERB_ANSWER, tid), 1),
        None,
        None,
        Instant::now(),
    ));
    assert_eq!(ev.dialogue_id, tid);
    assert_eq!(
        ev.data["components"][0]["argument"]["event_type_bcsm"],
        "oAnswer"
    );
    assert_eq!(
        ev.data["components"][0]["argument"]["message_type"],
        "notification"
    );
    assert!(!engine.awaiting_answer(tid));
    // ...the interrupted oDisconnect does.
    let ev = event(engine.on_data(
        &from_jss7(&with_dtid(jss7::ERB_DISCONNECT, tid), 1),
        None,
        None,
        Instant::now(),
    ));
    assert_eq!(
        ev.data["components"][0]["argument"]["event_type_bcsm"],
        "oDisconnect"
    );
    assert!(engine.awaiting_answer(tid));
    let out = answer(
        &mut engine,
        json!({"type": "send_cap_operations", "dialogue_id": tid,
               "operations": [{"operation": "releaseCall", "cause": "normal_call_clearing"}]}),
    );
    let m = tcap_of(&out);
    assert_eq!(m.kind, tcap::TcKind::End);
    assert_eq!(m.dtid.as_deref(), Some(&[0u8, 0, 0, 1][..]));
    match &m.components[0] {
        tcap::Component::Invoke {
            opcode, parameter, ..
        } => {
            assert_eq!(opcode.local(), Some(22));
            // Cause: ITU coding, location public-local (0x82), value 16 with ext (0x90).
            assert_eq!(
                hex::encode(parameter.as_ref().unwrap().encode()),
                "04028290"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(engine.open_dialogues(), 0);
}

// ---------------------------------------------------------------------------
// The oracle: tshark reads what NetGet sent
// ---------------------------------------------------------------------------

#[test]
fn tshark_dissects_netgets_map_and_cap_answers_cleanly() {
    let mut engine = Engine::new();
    let mut packets = Vec::new();
    let mut tsn = 1;
    let mut push = |out: &Outgoing, packets: &mut Vec<Vec<u8>>| {
        packets.push(ip_sctp_m3ua(
            2905,
            2906,
            tsn,
            1,
            &m3ua_data(&out.protocol_data, out.routing_context),
        ));
        tsn += 1;
    };
    let sri = begin(&mut engine, jss7::SRI_SM_BEGIN);
    let o = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": sri.dialogue_id,
        "result": {"imsi": "001010123456789", "network_node_number": "31600000001", "lmsi": "0a0b0c0d"}}),
    );
    push(&o, &mut packets);
    let ati = begin(&mut engine, jss7::ATI_BEGIN);
    let o = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": ati.dialogue_id,
        "result": {"subscriber_state": "netDetNotReachable", "not_reachable_reason": "imsiDetached",
                   "location_information": {"vlr_number": "31600000002",
                       "cell_global_id": {"mcc": "262", "mnc": "001", "lac": 1, "cell_id": 2}}}}),
    );
    push(&o, &mut packets);
    let ussd = begin(&mut engine, jss7::USSD_BEGIN);
    let o = answer(
        &mut engine,
        json!({"type": "send_map_result", "dialogue_id": ussd.dialogue_id,
        "result": {"ussd_text": "Balance: 42 EUR"}}),
    );
    push(&o, &mut packets);
    let mo = begin(&mut engine, jss7::MO_FSM_BEGIN);
    let o = answer(
        &mut engine,
        json!({"type": "send_map_error", "dialogue_id": mo.dialogue_id,
        "error": "sm-DeliveryFailure", "delivery_failure_cause": "sc-Congestion"}),
    );
    push(&o, &mut packets);
    let idp = begin(&mut engine, jss7::IDP_BEGIN);
    let o = answer(
        &mut engine,
        json!({"type": "send_cap_operations", "dialogue_id": idp.dialogue_id,
        "operations": [{"operation": "connect", "destination_routing_address": "31677777777"}]}),
    );
    push(&o, &mut packets);
    // And a dialogue NetGet opens itself, with MAP-OpenInfo.
    let route = engine.last_route.clone();
    let (_, o) = engine
        .apply(
            &json!({"type": "send_map_request", "operation": "processUnstructuredSS-Request",
                       "argument": {"ussd_text": "*101#", "msisdn": "31628838002"}}),
            route.as_ref(),
            0,
            Instant::now(),
        )
        .unwrap();
    push(&o, &mut packets);

    let (text, bad) = tshark_verbose(&packets);
    assert!(bad.is_empty(), "tshark flags NetGet's SS7: {bad:?}\n{text}");
    for needle in [
        "returnResultLast",
        "sendRoutingInfoForSM",
        "IMSI: 001010123456789",
        "31600000001",
        "anyTimeInterrogation",
        "netDetNotReachable: imsiDetached",
        "processUnstructuredSS-Request",
        "USSD String: Balance: 42 EUR",
        "returnError",
        "sm-DeliveryFailure",
        "sc-Congestion",
        "connect",
        "31677777777",
        "USSD String: *101#",
        "map-open",
    ] {
        assert!(
            text.contains(needle),
            "tshark's dissection lacks {needle:?}:\n{text}"
        );
    }
    // A hand-check of the protocol stack tshark recognised.
    assert!(text.contains("MTP 3 User Adaptation Layer"), "{text}");
    assert!(
        text.contains("Signalling Connection Control Part"),
        "{text}"
    );
    assert!(
        text.contains("Transaction Capabilities Application Part"),
        "{text}"
    );
    assert!(text.contains("Camel"), "{text}");
}

#[test]
fn a_dialogue_netget_opens_matches_its_peers_answer_by_transaction_id() {
    let mut engine = Engine::new();
    let route = {
        // Learn a route the way the client does: from configuration, here jSS7's addresses.
        let ud = sccp::decode(&unhex(jss7::SRI_SM_BEGIN)).unwrap();
        netget::server::m3ua::ss7::Route::reply_to(
            &from_jss7(jss7::SRI_SM_BEGIN, 1),
            &ud,
            None,
            None,
        )
    };
    let (id, out) = engine
        .apply(
            &json!({"type": "send_map_request", "operation": "sendRoutingInfoForSM",
                    "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}}),
            Some(&route),
            0,
            Instant::now(),
        )
        .unwrap();
    let m = tcap_of(&out);
    assert_eq!(m.kind, tcap::TcKind::Begin);
    assert_eq!(m.otid.as_deref(), Some(&id.to_be_bytes()[..]));
    // The peer's TC-END, addressed to that transaction: jSS7's own SRI-SM answer, with its dtid
    // rewritten to NetGet's transaction and the invoke id (0 in the capture) to NetGet's 1.
    let reply_hex = with_dtid(jss7::SRI_SM_END, id).replace("a21f020100301a", "a21f020101301a");
    let ev = event(engine.on_data(&from_jss7(&reply_hex, 1), None, None, Instant::now()));
    assert_eq!(ev.dialogue_id, id);
    let c = &ev.data["components"][0];
    assert_eq!(c["matched_own_invoke"], true, "{c}");
    assert_eq!(c["operation"], "sendRoutingInfoForSM");
    assert_eq!(c["result"]["imsi"], "001010123456789");
    assert_eq!(c["result"]["network_node_number"]["digits"], "31600000001");
    assert!(ev.ended);
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn the_dashboards_peer_command_refuses_an_ss7_intent_by_name() {
    use netget::llm::actions::protocol_trait::Server;
    use netget::server::m3ua::actions::M3uaProtocol;
    let intent = json!({"type": "send_map_result", "dialogue_id": 1, "result": {}});
    // The session's instance turns it into an intent for the engine...
    assert!(M3uaProtocol::new().execute_action(intent.clone()).is_ok());
    // ...the peer command task's cannot reach the dialogue and says so, rather than reporting
    // "executed" with nothing on the wire.
    let e = M3uaProtocol::for_peer_commands()
        .execute_action(intent)
        .unwrap_err()
        .to_string();
    assert!(e.contains("only the association's own"), "{e}");
}
