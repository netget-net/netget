//! The LoRaWAN and packet-forwarder codecs against published vectors: AES-CMAC from RFC 4493
//! and a data uplink from lora-packet's documentation (MIC and FRMPayload decryption), plus
//! the packet-forwarder bounds that are enforced before any JSON is parsed.
use netget::server::lorawan::{mac, region, semtech};
use serde_json::json;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn aes_cmac_rfc4493_vectors() {
    let key: mac::Key = h("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    let m = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    for (len, tag) in [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ] {
        assert_eq!(
            hex::encode(mac::aes_cmac(&key, &m[..len])),
            tag,
            "CMAC of {len} bytes"
        );
    }
}

/// lora-packet's README example: an unconfirmed uplink carrying "test".
#[test]
fn lora_packet_readme_uplink() {
    let phy = h("40F17DBE4900020001954378762B11FF0D");
    let nwk: mac::Key = h("44024241ed4ce9a68c6a8bc055233fd3").try_into().unwrap();
    let app: mac::Key = h("ec925802ae430ca77fd3dd73cb2cc588").try_into().unwrap();
    let f = mac::parse_data(&phy).unwrap();
    assert_eq!(f.mtype, mac::MTYPE_UNCONFIRMED_UP);
    assert_eq!(mac::dev_addr_hex(f.dev_addr), "49be7df1");
    assert_eq!(f.f_cnt, 2);
    assert_eq!(f.f_port, Some(1));
    assert!(mac::data_mic_ok(&phy, &nwk, mac::DIR_UP, f.dev_addr, 2));
    assert!(!mac::data_mic_ok(&phy, &nwk, mac::DIR_UP, f.dev_addr, 0x1_0002));
    assert_eq!(
        mac::crypt_frm(&app, mac::DIR_UP, f.dev_addr, 2, &f.frm_payload),
        b"test"
    );
    // And NetGet's encoder writes the identical frame.
    let again = mac::encode_data(
        &mac::OutFrame {
            mtype: mac::MTYPE_UNCONFIRMED_UP,
            dev_addr: f.dev_addr,
            adr: false,
            adr_ack_req: false,
            ack: false,
            f_pending: false,
            f_cnt: 2,
            f_opts: &[],
            f_port: Some(1),
            payload: b"test",
        },
        &nwk,
        &app,
    )
    .unwrap();
    assert_eq!(again, phy);
}

#[test]
fn join_round_trip_and_tamper() {
    let key: mac::Key = h("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    let jr = mac::JoinRequest {
        app_eui: [0x70, 0xb3, 0xd5, 0x7e, 0xd0, 0, 0, 1],
        dev_eui: [1, 2, 3, 4, 5, 6, 7, 8],
        dev_nonce: 0xbeef,
    };
    let phy = mac::encode_join_request(&jr, &key);
    assert_eq!(phy.len(), 23);
    // On air, EUIs are little-endian.
    assert_eq!(&phy[1..9], &[1, 0, 0, 0xd0, 0x7e, 0xd5, 0xb3, 0x70]);
    assert_eq!(mac::parse_join_request(&phy).unwrap(), jr);
    assert!(mac::join_request_mic_ok(&phy, &key));
    let mut bad = phy.clone();
    bad[17] ^= 1;
    assert!(!mac::join_request_mic_ok(&bad, &key));

    let ja = mac::JoinAccept {
        app_nonce: 0x123456,
        net_id: 0x000013,
        dev_addr: 0x2601_1bda,
        rx1_dr_offset: 1,
        rx2_data_rate: 3,
        rx_delay: 1,
        cf_list: None,
    };
    let enc = mac::encode_join_accept(&ja, &key);
    assert_eq!(enc.len(), 17);
    assert_eq!(mac::decode_join_accept(&enc, &key).unwrap(), ja);
    let mut tampered = enc.clone();
    tampered[5] ^= 0x80;
    assert!(mac::decode_join_accept(&tampered, &key).is_err());
    let other: mac::Key = [7; 16];
    assert!(mac::decode_join_accept(&enc, &other).is_err());
    let with_cf = mac::JoinAccept {
        cf_list: Some([9; 16]),
        ..ja.clone()
    };
    let enc = mac::encode_join_accept(&with_cf, &key);
    assert_eq!(enc.len(), 33);
    assert_eq!(mac::decode_join_accept(&enc, &key).unwrap(), with_cf);
    let (nwk, app) = mac::session_keys(&key, ja.app_nonce, ja.net_id, 0xbeef);
    assert_ne!(nwk, app);
}

#[test]
fn frame_counter_reconstruction() {
    use mac::FcntCheck::*;
    assert_eq!(mac::classify_fcnt(None, 7), Fresh(7));
    assert_eq!(mac::classify_fcnt(Some(7), 8), Fresh(8));
    assert_eq!(mac::classify_fcnt(Some(7), 7), Repeat(7));
    // Across the 16-bit wrap.
    assert_eq!(mac::classify_fcnt(Some(0xfffe), 1), Fresh(0x1_0001));
    // An old counter is the same low bits one wrap later: far beyond MAX_FCNT_GAP.
    assert_eq!(mac::classify_fcnt(Some(100), 5), TooFar(0x1_0005));
    assert_eq!(mac::classify_fcnt(Some(0), 16_385), TooFar(16_385));
    assert_eq!(mac::classify_fcnt(Some(0), 16_384), Fresh(16_384));
}

#[test]
fn mac_commands_decode() {
    let up = mac::decode_mac_commands(&[0x02, 0x06, 200, 0x3e, 0x03, 0x07], true);
    assert_eq!(up[0], json!({"command": "link_check_req"}));
    assert_eq!(
        up[1],
        json!({"command": "dev_status_ans", "battery": 200, "margin_db": -2})
    );
    assert_eq!(up[2]["command"], "link_adr_ans");
    assert_eq!(up[2]["channel_mask_ack"], true);
    let down = mac::decode_mac_commands(&[0x02, 20, 3, 0x06, 0xff], false);
    assert_eq!(
        down[0],
        json!({"command": "link_check_ans", "margin_db": 20, "gateway_count": 3})
    );
    assert_eq!(down[1], json!({"command": "dev_status_req"}));
    assert_eq!(down[2], json!({"command": "unknown", "cid": 255}));
    assert_eq!(
        mac::decode_mac_commands(&[0x06, 1], true),
        vec![json!({"command": "truncated", "cid": 6})]
    );
}

#[test]
fn eu868_table() {
    assert_eq!(region::data_rate_index("SF7BW125").unwrap(), 5);
    assert_eq!(region::data_rate_index("SF12BW125").unwrap(), 0);
    assert_eq!(region::data_rate_index("SF7BW250").unwrap(), 6);
    assert!(region::data_rate_index("SF7BW500").is_err());
    assert_eq!(region::max_phy_payload(0), 64);
    assert_eq!(region::max_frm_payload(0, 0), 51);
    assert_eq!(region::max_frm_payload(5, 3), 239);
    assert_eq!(region::rx1_data_rate(5, 2), 3);
    assert_eq!(region::rx1_data_rate(1, 5), 0);
    assert_eq!(region::link_margin_db(5, 9.5), 17);
    assert_eq!(region::link_margin_db(0, -25.0), 0);
}

fn push(body: &[u8]) -> Vec<u8> {
    let mut d = vec![2, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    d.extend(body);
    d
}

#[test]
fn packet_forwarder_bounds() {
    // A depth bomb is refused before serde sees it.
    let bomb = format!("{{\"rxpk\":[],\"x\":{}{}}}", "[".repeat(4000), "]".repeat(4000));
    let err = semtech::parse(&push(bomb.as_bytes())).unwrap_err();
    assert!(format!("{err:#}").contains("deeper"), "{err:#}");
    // A bracket inside a string is not nesting.
    let quoted = format!("{{\"rxpk\":[],\"x\":\"{}\"}}", "[".repeat(100));
    semtech::parse(&push(quoted.as_bytes())).unwrap();
    // Datagram size.
    let big = push(&vec![b' '; semtech::MAX_DATAGRAM]);
    assert!(semtech::parse(&big).is_err());
    // rxpk count.
    let one = json!({"freq": 868.1, "modu": "LORA", "datr": "SF7BW125", "size": 1, "data": "AA=="});
    let at = json!({"rxpk": vec![one.clone(); semtech::MAX_RXPK]});
    semtech::parse(&push(&serde_json::to_vec(&at).unwrap())).unwrap();
    let over = json!({"rxpk": vec![one; semtech::MAX_RXPK + 1]});
    assert!(semtech::parse(&push(&serde_json::to_vec(&over).unwrap())).is_err());
    // An oversized frame is refused by its base64 length.
    let long = json!({"rxpk": [{"freq": 868.1, "modu": "LORA", "datr": "SF7BW125", "size": 300,
        "data": "A".repeat(semtech::MAX_DATA_B64 + 4)}]});
    assert!(semtech::parse(&push(&serde_json::to_vec(&long).unwrap())).is_err());
    // Versions 1 and 2 only; short datagrams; unknown identifiers.
    assert!(semtech::parse(&[3, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    assert!(semtech::parse(&[2, 0, 0]).is_err());
    assert!(semtech::parse(&[2, 0, 0, 9]).is_err());
    // TX_ACK with and without a body.
    match semtech::parse(&[2, 0, 7, 5, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap() {
        semtech::Packet::TxAck { error, token, .. } => {
            assert_eq!((error, token), (None, 7))
        }
        p => panic!("{p:?}"),
    }
    let mut d = vec![2, 0, 7, 5, 1, 2, 3, 4, 5, 6, 7, 8];
    d.extend(br#"{"txpk_ack":{"error":"TOO_LATE"}}"#);
    match semtech::parse(&d).unwrap() {
        semtech::Packet::TxAck { error, .. } => assert_eq!(error.as_deref(), Some("TOO_LATE")),
        p => panic!("{p:?}"),
    }
}
