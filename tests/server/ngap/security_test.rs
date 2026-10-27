//! NAS security against published test vectors: Milenage (TS 35.208 test set 1), 128-NIA2 and
//! 128-NEA2 (TS 33.401 Annex C, the sets 5G reuses per TS 33.501 Annex D), SUCI concealment
//! Profiles A and B (TS 33.501 Annex C.4.3 and C.4.4), and the Internet checksum (RFC 1071).
//!
//! The 5G key derivations above Milenage (RES*, K_AUSF, K_SEAF, K_AMF, the NAS keys, K_gNB) have
//! no published vectors in TS 33.501; they are checked here for their structure (which bits are
//! kept, which inputs move the output) and against the real peers: UERANSIM's UE verifies the
//! AUTN, accepts the Security Mode Command's MAC and every protected message after it
//! (`real_client_test.rs`), and Open5GS's AMF verifies the gNB-side UE's RES* and hands it a K_gNB
//! the UE recomputes (`tests/client/ngap/real_server_test.rs`).
use super::support::unhex;
use netget::server::ngap::{security, suci, upf};

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("vector length")
}

#[test]
fn milenage_matches_ts_35_208_test_set_1() {
    let k = arr::<16>("465b5ce8 b199b49f aa5f0a2e e238a6bc");
    let rand = arr::<16>("23553cbe 9637a89d 218ae64d ae47bf35");
    let sqn = arr::<6>("ff9bb4d0 b607");
    let amf = arr::<2>("b9b9");
    let op = arr::<16>("cdc202d5 123e20f6 2b6d676a c72cb318");
    let m = security::Milenage::with_op(k, op);
    assert_eq!(
        m.opc().to_vec(),
        unhex("cd63cb71 954a9f4e 48a5994e 37a02baf")
    );
    let (mac_a, mac_s) = m.f1(&rand, &sqn, &amf);
    assert_eq!(mac_a.to_vec(), unhex("4a9ffac3 54dfafb3"), "f1");
    assert_eq!(mac_s.to_vec(), unhex("01cfaf9e c4e871e9"), "f1*");
    let o = m.f2345(&rand);
    assert_eq!(o.res.to_vec(), unhex("a54211d5 e3ba50bf"), "f2");
    assert_eq!(
        o.ck.to_vec(),
        unhex("b40ba9a3 c58b2a05 bbf0d987 b21bf8cb"),
        "f3"
    );
    assert_eq!(
        o.ik.to_vec(),
        unhex("f769bcd7 51044604 12767271 1c6d3441"),
        "f4"
    );
    assert_eq!(o.ak.to_vec(), unhex("aa689c64 8370"), "f5");
    assert_eq!(m.f5_star(&rand).to_vec(), unhex("451e8bec a43b"), "f5*");
    // The same subscriber given OPc directly computes the same.
    let m2 = security::Milenage::with_opc(k, m.opc());
    assert_eq!(m2.f1(&rand, &sqn, &amf).0, mac_a);
}

#[test]
fn nia2_matches_ts_33_401_eia2_test_set() {
    let ik = arr::<16>("d3c5d592 327fb11c 4035c668 0af8c6d1");
    let mac = security::nia2(&ik, 0x398a59b4, 0x1a, 1, &unhex("484583d5 afe082ae"));
    assert_eq!(mac.to_vec(), unhex("b93787e6"));
}

#[test]
fn nea2_matches_ts_33_401_eea2_test_set() {
    let ck = arr::<16>("2bd6459f 82c440e0 952c4910 4805ff48");
    let plain = unhex(
        "7ec61272 743bf161 4726446a 6c38ced1 66f6ca76 eb543004 4286346c ef130f92 \
         922b0345 0d3a9975 e5bd2ea0 eb55ad8e 1b199e3e c4316020 e9a1b285 e7627953 \
         59b7bdfd 39bef4b2 484583d5 afe082ae e638bf5f d5a60619 3901a08f 4ab41aab 9b134880",
    );
    let cipher = unhex(
        "59616053 53c64bdc a15b195e 288553a9 10632506 d6200aa7 90c4c806 c99904cf \
         2445cc50 bb1cf168 a4967373 4e081b57 e324ce52 59c0e78d 4cd97b87 0976503c \
         0943f2cb 5ae8f052 c7b7d392 239587b8 956086bc ab188360 42e2e6ce 42432a17 105c53d3",
    );
    let mut data = plain.clone();
    security::nea2(&ck, 0xc675a64b, 0x0c, 1, &mut data);
    assert_eq!(data, cipher);
    security::nea2(&ck, 0xc675a64b, 0x0c, 1, &mut data);
    assert_eq!(data, plain, "NEA2 is its own inverse");
}

#[test]
fn suci_profile_a_matches_ts_33_501_c_4_3() {
    let home_private =
        arr::<32>("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");
    let home_public = unhex("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");
    assert_eq!(
        home_private,
        suci::TS_33_501_C_4_3_HOME_NETWORK_PRIVATE_KEY,
        "the key the startup example is built from is the specification's"
    );
    let eph_private = arr::<32>("c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256");
    let expected = unhex(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d cb02352410 cddd9e730ef3fa87",
    );
    let out = suci::conceal(
        suci::PROFILE_A,
        &home_public,
        &eph_private,
        &unhex("00012080f6"),
    )
    .unwrap();
    assert_eq!(out, expected, "scheme output");
    assert_eq!(
        suci::deconceal(suci::PROFILE_A, &home_private, &expected).unwrap(),
        unhex("00012080f6")
    );
    let mut tampered = expected.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(suci::deconceal(suci::PROFILE_A, &home_private, &tampered).is_err());
    assert_eq!(
        suci::x963_kdf(
            &unhex("028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a"),
            &unhex("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d"),
            64
        )[..16]
            .to_vec(),
        unhex("2ba342cabd2b3b1e5e4e890da11b65f6"),
        "the encryption key out of the ANSI X9.63 KDF"
    );
}

#[test]
fn suci_profile_b_matches_ts_33_501_c_4_4() {
    let home_private =
        arr::<32>("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA");
    let home_public = unhex("0272DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1");
    let eph_private = arr::<32>("99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529");
    let expected = unhex(
        "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1 46A33FC271 6AC7DAE96AA30A4D",
    );
    let out = suci::conceal(
        suci::PROFILE_B,
        &home_public,
        &eph_private,
        &unhex("00012080f6"),
    )
    .unwrap();
    assert_eq!(out, expected);
    assert_eq!(
        suci::deconceal(suci::PROFILE_B, &home_private, &expected).unwrap(),
        unhex("00012080f6")
    );
}

/// The vector the home network makes is the one the UE accepts, RES* agrees with XRES*, and the
/// keys the two sides derive from it are the same; each derivation keeps the bits TS 33.501
/// Annex A says it keeps.
#[test]
fn five_g_aka_round_trip_and_derivation_shape() {
    let k = arr::<16>("465B5CE8B199B49FAA5F0A2EE238A6BC");
    let opc = arr::<16>("E8ED289DEBA952E4283B54E88E6183CA");
    let m = security::Milenage::with_opc(k, opc);
    let snn = security::serving_network_name("001", "01");
    assert_eq!(snn, "5G:mnc001.mcc001.3gppnetwork.org");
    let rand = [7u8; 16];
    let v = security::generate_vector(&m, rand, 0x20, [0x80, 0x00], &snn);
    let ue = security::ue_check_autn(&m, &rand, &v.autn, &snn, 0, 1 << 28);
    let security::AutnOutcome::Ok {
        res_star,
        k_ausf,
        sqn,
    } = ue
    else {
        panic!("the UE refused the network's own AUTN");
    };
    assert_eq!(sqn, 0x20);
    assert_eq!(res_star, v.xres_star);
    assert_eq!(k_ausf, v.k_ausf);
    assert_eq!(security::hres_star(&rand, &res_star), v.hxres_star);

    // RES* is the low 128 bits of KDF(CK||IK, 0x6B, SNN, RAND, RES).
    let o = m.f2345(&rand);
    let full = security::kdf(
        &[o.ck, o.ik].concat(),
        0x6B,
        &[snn.as_bytes(), &rand, &o.res],
    );
    assert_eq!(&full[16..], &v.xres_star[..]);

    // A different serving network name changes RES*: the binding to the serving network.
    let other = security::generate_vector(
        &m,
        rand,
        0x20,
        [0x80, 0x00],
        "5G:mnc002.mcc001.3gppnetwork.org",
    );
    assert_ne!(other.xres_star, v.xres_star);

    // A reused SQN is a synch failure whose AUTS resynchronises the network to the UE's SQN.
    let stale = security::generate_vector(&m, rand, 0x20, [0x80, 0x00], &snn);
    let security::AutnOutcome::SynchFailure { auts } =
        security::ue_check_autn(&m, &rand, &stale.autn, &snn, 0x40, 1 << 28)
    else {
        panic!("a stale SQN was accepted");
    };
    assert_eq!(security::resync_sqn(&m, &rand, &auts), Some(0x40));
    let mut bad = auts;
    bad[13] ^= 1;
    assert_eq!(
        security::resync_sqn(&m, &rand, &bad),
        None,
        "MAC-S is checked"
    );

    // A wrong key is a MAC failure; a cleared separation bit is refused as non-5G.
    let other_key = security::Milenage::with_opc([1; 16], opc);
    assert!(matches!(
        security::ue_check_autn(&other_key, &rand, &v.autn, &snn, 0, 1 << 28),
        security::AutnOutcome::MacFailure
    ));
    let non5g = security::generate_vector(&m, rand, 0x40, [0x00, 0x00], &snn);
    assert!(matches!(
        security::ue_check_autn(&m, &rand, &non5g.autn, &snn, 0, 1 << 28),
        security::AutnOutcome::SeparationBit
    ));

    // NAS keys: the low 128 bits, distinct per algorithm type and identity.
    let k_amf = security::k_amf(
        &security::k_seaf(&v.k_ausf, &snn),
        "001010000000001",
        &[0, 0],
    );
    let (enc0, int2) = security::nas_keys(&k_amf, 0, 2);
    let (enc2, _) = security::nas_keys(&k_amf, 2, 2);
    assert_eq!(&security::kdf(&k_amf, 0x69, &[&[2], &[2]])[16..], &int2[..]);
    assert_ne!(enc0, enc2);
    // K_gNB moves with the uplink NAS COUNT.
    assert_ne!(
        security::k_gnb(&k_amf, 0, security::ACCESS_3GPP),
        security::k_gnb(&k_amf, 1, security::ACCESS_3GPP)
    );
}

/// The protected-message framing and its COUNT rules, between an AMF context and a UE context
/// derived from the same K_AMF.
#[test]
fn nas_protection_counts_mac_and_replay() {
    let k_amf = [9u8; 32];
    for ea in [security::NEA0, security::NEA2] {
        let mut amf = security::NasContext::new(0, k_amf, security::NIA2, ea, security::DOWNLINK);
        let mut ue = security::NasContext::new(0, k_amf, security::NIA2, ea, security::UPLINK);
        let smc = [0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xf0, 0xf0];
        let wire = amf.protect(&smc, security::SHT_INTEGRITY_NEW_CONTEXT);
        assert_eq!(&wire[..2], &[0x7e, 0x03]);
        assert_eq!(wire[6], 0, "sequence number of COUNT 0");
        assert_eq!(&wire[7..], &smc, "header type 3 is never ciphered");
        let (plain, count, sht) = ue.unprotect(&wire).unwrap();
        assert_eq!((plain.as_slice(), count, sht), (&smc[..], 0, 3));

        let complete = [0x7e, 0x00, 0x5e];
        let up = ue.protect(&complete, security::SHT_INTEGRITY_CIPHERED_NEW_CONTEXT);
        if ea == security::NEA0 {
            assert_eq!(&up[7..], &complete, "NEA0 leaves the message readable");
        } else {
            assert_ne!(&up[7..], &complete, "NEA2 ciphers it");
        }
        assert_eq!(amf.unprotect(&up).unwrap().0, complete);
        // The same octets again carry an already-accepted COUNT.
        assert!(matches!(
            amf.unprotect(&up),
            Err(security::UnprotectError::Replay { count: 0 })
        ));
        // One flipped MAC bit, or a flipped body bit, fails integrity.
        let next = ue.protect(&[0x7e, 0x00, 0x43], security::SHT_INTEGRITY_CIPHERED);
        let mut forged = next.clone();
        forged[2] ^= 0x80;
        assert!(matches!(
            amf.unprotect(&forged),
            Err(security::UnprotectError::Mac { count: 1 })
        ));
        let mut forged = next.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(amf.unprotect(&forged).is_err());
        // The genuine message still verifies: a failure does not advance the COUNT.
        assert_eq!(amf.unprotect(&next).unwrap().1, 1);
        assert_eq!(amf.last_uplink_count(), 1);
    }
    // The 8-bit sequence number wraps into the overflow counter.
    assert_eq!(security::estimate_count(Some(0xFF), 0x00), 0x100);
    assert_eq!(security::estimate_count(Some(0x1FE), 0xFF), 0x1FF);
    assert_eq!(security::estimate_count(None, 5), 5);
}

#[test]
fn icmp_echo_reply_swaps_addresses_and_recomputes_checksums() {
    // An echo request 10.45.0.2 -> 10.45.0.1, id 0x1234, seq 1, payload "netget".
    let mut req = vec![
        0x45, 0, 0, 34, 0, 1, 0x40, 0, 64, 1, 0, 0, 10, 45, 0, 2, 10, 45, 0, 1, 8, 0, 0, 0, 0x12,
        0x34, 0, 1,
    ];
    req.extend_from_slice(b"netget");
    let ip = upf::checksum(&req[..20]);
    req[10..12].copy_from_slice(&ip.to_be_bytes());
    let icmp = upf::checksum(&req[20..]);
    req[22..24].copy_from_slice(&icmp.to_be_bytes());
    let reply = upf::echo_reply(&req).expect("an echo request");
    assert_eq!(&reply[12..16], &[10, 45, 0, 1]);
    assert_eq!(&reply[16..20], &[10, 45, 0, 2]);
    assert_eq!(reply[20], 0, "echo reply");
    assert_eq!(upf::checksum(&reply[..20]), 0, "IPv4 header checksum");
    assert_eq!(upf::checksum(&reply[20..]), 0, "ICMP checksum");
    assert_eq!(
        &reply[24..],
        &req[24..],
        "identifier, sequence and data come back"
    );
    let mut corrupt = req.clone();
    corrupt[30] ^= 1;
    assert!(
        upf::echo_reply(&corrupt).is_none(),
        "a bad ICMP checksum is not answered"
    );
}
