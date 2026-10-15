//! The H.225.0 / H.245 PER codec and the Q.931 envelope: checked against tshark's h225
//! dissector (an independent reading of the same ASN.1), against itself (decode ∘ encode), and
//! at every bound a peer controls — nesting depth, declared lengths, fragmentation, extension
//! indices, TPKT and IE lengths.

use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::h323::{h225, per, q931, schema};
use serde_json::{json, Value};

fn rrq() -> Value {
    json!({
        "requestSeqNum": 4242,
        "protocolIdentifier": h225::PROTOCOL_ID,
        "discoveryComplete": true,
        "callSignalAddress": [h225::transport("127.0.0.1:1720".parse().unwrap())],
        "rasAddress": [h225::transport("127.0.0.1:1719".parse().unwrap())],
        "terminalType": h225::endpoint_type("terminal"),
        "terminalAlias": [h225::alias("h323-ID:alice").unwrap(), h225::alias("1001").unwrap()],
        "endpointVendor": h225::vendor(),
        "timeToLive": 300,
        "keepAlive": false,
        "willSupplyUUIEs": false,
        "maintainConnection": false,
        "supportsAssignedGK": false,
    })
}

fn type_index(name: &str) -> u16 {
    schema::NAMES
        .iter()
        .position(|n| *n == name)
        .unwrap_or_else(|| panic!("{name} is not in the schema")) as u16
}

#[test]
fn rrq_round_trips_and_tshark_reads_every_field() {
    let bytes = h225::encode_ras("registrationRequest", rrq()).unwrap();
    let (kind, body) = h225::decode_ras(&bytes).unwrap();
    assert_eq!(kind, "registrationRequest");
    assert_eq!(body, rrq());

    PcapOracle::udp("h323_gatekeeper")
        .to_server(&bytes)
        .assert_clean();
    let rows = PcapOracle::udp("h323_gatekeeper")
        .to_server(&bytes)
        .fields(&[
            "h225.RasMessage",
            "h225.requestSeqNum",
            "h225.h323_ID",
            "h225.dialledDigits",
            "h225.timeToLive",
            "h225.ipV4",
            "h225.ipV4_port",
            "h225.keepAlive",
        ])
        .unwrap();
    let row = rows.last().unwrap();
    assert_eq!(
        row[0], "3",
        "registrationRequest is RasMessage alternative 3: {rows:?}"
    );
    assert_eq!(row[1], "4242");
    assert_eq!(row[2], "alice");
    assert_eq!(row[3], "1001");
    assert_eq!(row[4], "300");
    assert_eq!(row[5], "127.0.0.1,127.0.0.1");
    assert_eq!(row[6], "1720,1719");
    assert!(row[7] == "0" || row[7] == "False", "keepAlive: {}", row[7]);
}

/// The answers the gatekeeper writes, as tshark reads them: the reject reason survives the
/// round trip through an independent decoder, including an extension alternative
/// (`securityDenial` comes after the RegistrationRejectReason extension marker).
#[test]
fn rejects_carry_the_reason_tshark_reads() {
    let rrj = h225::encode_ras(
        "registrationReject",
        json!({
            "requestSeqNum": 7,
            "protocolIdentifier": h225::PROTOCOL_ID,
            "rejectReason": {"securityDenial": null},
            "gatekeeperIdentifier": "NetGet",
        }),
    )
    .unwrap();
    let arj = h225::encode_ras(
        "admissionReject",
        json!({"requestSeqNum": 8, "rejectReason": {"calledPartyNotRegistered": null}}),
    )
    .unwrap();
    PcapOracle::udp("h323_gatekeeper")
        .from_server(&rrj)
        .from_server(&arj)
        .assert_clean();
    let rows = PcapOracle::udp("h323_gatekeeper")
        .from_server(&rrj)
        .from_server(&arj)
        .fields(&[
            "h225.RasMessage",
            "h225.requestSeqNum",
            "h225.registrationRejectReason",
            "h225.rejectReason",
        ])
        .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0][0], "5");
    assert_eq!(rows[0][1], "7");
    // securityDenial is the extension alternative after RegistrationRejectReason's eight root
    // ones and transportQOSNotSupported, resourceUnavailable, invalidAlias: index 11.
    assert_eq!(rows[0][2], "11", "{rows:?}");
    assert_eq!(rows[1][0], "11");
    assert_eq!(
        rows[1][3], "0",
        "calledPartyNotRegistered is AdmissionRejectReason 0: {rows:?}"
    );
}

/// One level of H.245 `GenericParameter` nesting: parameterIdentifier `standard 1`, then a
/// parameterValue that is itself a one-element `genericParameter` list.
const LEVEL: [u8; 3] = [0x00, 0x17, 0x01];
/// The innermost GenericParameter: `standard 1`, value `logical`.
const LEAF: [u8; 2] = [0x00, 0x10];

fn nested(levels: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(levels * 3 + 2);
    for _ in 0..levels {
        v.extend_from_slice(&LEVEL);
    }
    v.extend_from_slice(&LEAF);
    v
}

/// H.245's GenericParameter (like H.225.0's GenericData) is recursive and costs three octets a
/// level on the wire. Without the depth bound, a hundred thousand levels — 300 KB of tunnelled
/// H.245 — overflow the stack and kill the whole process.
#[test]
fn a_depth_bomb_is_refused_before_the_stack_runs_out() {
    let ty = type_index("H245.GenericParameter");
    // Control: real nesting decodes.
    let shallow = per::decode(ty, &nested(4)).unwrap();
    assert_eq!(
        shallow["parameterValue"]["genericParameter"][0]["parameterIdentifier"]["standard"],
        1
    );
    for levels in [100_000, 20] {
        let err = per::decode(ty, &nested(levels)).unwrap_err();
        assert!(err.0.contains("nested deeper"), "{levels} levels: {err}");
    }
}

#[test]
fn declared_lengths_are_checked_against_what_is_there() {
    let ty = type_index("H245.GenericParameter");
    // parameterValue octetString (alternative 6), declaring 100 octets with three present.
    let short = [0x00, 0x16, 100, 1, 2, 3];
    let err = per::decode(ty, &short).unwrap_err();
    assert!(err.0.contains("declares 100 octets, 3 remain"), "{err}");
    // A fragmented length (X.691 11.9.3.8) is refused, not reassembled.
    let fragmented = [0x00, 0x16, 0xC1, 0, 0, 0];
    assert!(per::decode(ty, &fragmented)
        .unwrap_err()
        .0
        .contains("fragmented"));
    // An extension alternative whose normally-small index is above 63.
    let extension = [0x00, 0x1C, 0xFF, 0xFF];
    assert!(per::decode(ty, &extension)
        .unwrap_err()
        .0
        .contains("normally-small"));
    // Nothing at all.
    assert!(per::decode(ty, &[]).is_err());
}

#[test]
fn the_encoder_refuses_what_the_schema_does_not_allow() {
    // An unknown field is an error, not silently dropped.
    let mut bad = rrq();
    bad["timeToLiev"] = json!(5);
    assert!(h225::encode_ras("registrationRequest", bad)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));
    // Out of range: requestSeqNum is 1..65535.
    let mut bad = rrq();
    bad["requestSeqNum"] = json!(0);
    assert!(h225::encode_ras("registrationRequest", bad).is_err());
    // dialledDigits has a permitted alphabet.
    assert!(h225::alias("dialledDigits:12a").is_err());
    // A control character in a model-written alias is refused, not rewritten.
    assert!(h225::alias("h323-ID:ali\u{1b}[2Jce").is_err());
}

#[test]
fn tpkt_and_q931_bounds_are_enforced_before_reading() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // A TPKT declaring 65535 octets is refused from its header alone.
        let mut huge: &[u8] = &[3, 0, 0xFF, 0xFF, 0x08];
        let e = q931::read_tpkt(&mut huge).await.unwrap_err();
        assert!(e.to_string().contains("more than"), "{e}");
        // Not version 3.
        let mut wrong: &[u8] = &[4, 0, 0, 8, 1, 2, 3, 4];
        assert!(q931::read_tpkt(&mut wrong).await.is_err());
        // A clean end of stream is not an error.
        let mut empty: &[u8] = &[];
        assert!(q931::read_tpkt(&mut empty).await.unwrap().is_none());
    });
    // A User-user IE declaring more than the message holds.
    let truncated = [0x08, 0x02, 0x00, 0x01, 0x05, 0x7E, 0x00, 0x10, 0x05];
    assert!(q931::Q931::parse(&truncated).is_err());
    // More information elements than allowed.
    let mut many = vec![0x08, 0x02, 0x00, 0x01, 0x05];
    many.extend(std::iter::repeat_n(0xA1, q931::MAX_IES + 1));
    assert!(q931::Q931::parse(&many)
        .unwrap_err()
        .to_string()
        .contains("information elements"));
    // Round trip, with the call reference flag.
    let m = q931::Q931::new(q931::msg::CONNECT, 0x1234, true)
        .with_ie(q931::ie::CAUSE, q931::cause_ie(16));
    let back = q931::Q931::parse(&m.encode().unwrap()).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.cause(), Some(16));
}
