//! The pieces of Stratum V2's secure channel and codec that can be checked against published
//! values without a peer: the specification's base58check test vector, the authority key pair
//! SRI's own example configuration ships (so a secret NetGet decodes yields the public key SRI
//! pins), a handshake between NetGet's two roles, and each way the initiator must refuse a
//! responder. The interoperability evidence is in `real_client_test.rs` and the client's
//! `real_server_test.rs`; this file pins the parts those cannot isolate.
use netget::server::stratum_v2::{noise, wire};

/// sv2-spec §4.7.1.
const SPEC_RAW_KEY: [u8; 32] = [
    118, 99, 112, 0, 151, 156, 28, 17, 175, 12, 48, 11, 205, 140, 127, 228, 134, 16, 252, 233, 185,
    193, 30, 61, 174, 227, 90, 224, 176, 138, 116, 85,
];
const SPEC_ENCODED: &str = "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh";
/// The pair in SRI's pool config examples (sv2-apps `pool-apps/pool/config-examples`).
const SRI_SECRET: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const SRI_PUBLIC: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

#[test]
fn authority_keys_encode_as_the_spec_and_sri_write_them() {
    assert_eq!(noise::encode_authority_key(&SPEC_RAW_KEY), SPEC_ENCODED);
    assert_eq!(
        noise::decode_authority_key(SPEC_ENCODED).unwrap(),
        SPEC_RAW_KEY
    );
    let authority = noise::decode_secret_key(SRI_SECRET).unwrap();
    assert_eq!(
        noise::encode_authority_key(&authority.public_xonly()),
        SRI_PUBLIC
    );
    assert_eq!(
        noise::encode_secret_key(&authority.secret_bytes()),
        SRI_SECRET
    );
    // A flipped character breaks the checksum; the secret is not a public key.
    let mut broken = SPEC_ENCODED.to_string();
    broken.replace_range(10..11, "z");
    assert!(noise::decode_authority_key(&broken).is_err());
    assert!(noise::decode_authority_key(SRI_SECRET).is_err());
    assert!(noise::decode_authority_key("0OIl").is_err());
}

fn responder_answer(
    authority: &noise::Authority,
    validity: u32,
    now: u32,
) -> (
    noise::Initiator,
    [u8; noise::RESPONDER_MESSAGE_LEN],
    noise::Session,
) {
    let (initiator, first) = noise::Initiator::start().unwrap();
    assert_eq!(first.len(), 64);
    let static_key = noise::EllKey::generate();
    let (reply, session) = noise::respond(&first, &static_key, authority, validity, now).unwrap();
    assert_eq!(
        reply.len(),
        234,
        "sv2-spec §4.5.2: the second message is 234 bytes"
    );
    (initiator, reply, session)
}

#[test]
fn both_roles_agree_on_the_session_keys() {
    let authority = noise::Authority::generate();
    let now = wire::now_secs();
    let (initiator, reply, mut responder) = responder_answer(&authority, 3600, now);
    let (mut client, cert) = initiator
        .finish(&reply, &authority.public_xonly(), now)
        .unwrap();
    assert_eq!(cert.version, 0);
    assert_eq!(cert.valid_from, now);
    assert_eq!(cert.not_valid_after, now + 3600);

    // A frame each way, through the transport framing.
    let frame = wire::Message::SetupConnectionSuccess {
        used_version: 2,
        flags: 0,
    }
    .encode();
    let sealed = wire::seal(&mut responder.send, &frame).unwrap();
    assert_eq!(sealed.len(), wire::ENCRYPTED_HEADER_LEN + 6 + 16);
    let header = client.recv.decrypt(&[], &sealed[..22]).unwrap();
    assert_eq!(header, frame.header());
    let payload = client.recv.decrypt(&[], &sealed[22..]).unwrap();
    assert_eq!(payload, frame.payload);
    let back = client.send.encrypt(&[], b"device to pool").unwrap();
    assert_eq!(
        responder.recv.decrypt(&[], &back).unwrap(),
        b"device to pool"
    );
}

#[test]
fn the_initiator_refuses_every_bad_responder() {
    let authority = noise::Authority::generate();
    let now = wire::now_secs();

    // Signed by a different authority than the one pinned.
    let (initiator, reply, _) = responder_answer(&authority, 3600, now);
    let other = noise::Authority::generate();
    let err = initiator
        .finish(&reply, &other.public_xonly(), now)
        .err()
        .expect("a certificate from another authority must be refused");
    assert!(format!("{err:#}").contains("not signed"), "{err:#}");

    // Expired, and not yet valid (beyond the ten-second leeway).
    let (initiator, reply, _) = responder_answer(&authority, 60, now - 1000);
    let err = initiator
        .finish(&reply, &authority.public_xonly(), now)
        .err()
        .expect("expired");
    assert!(format!("{err:#}").contains("valid from"), "{err:#}");
    let (initiator, reply, _) = responder_answer(&authority, 60, now + 1000);
    assert!(initiator
        .finish(&reply, &authority.public_xonly(), now)
        .is_err());

    // Any flipped bit in the encrypted static key or certificate fails its MAC.
    for at in [64, 100, 143, 150, 233] {
        let (initiator, mut reply, _) = responder_answer(&authority, 3600, now);
        reply[at] ^= 1;
        let err = initiator
            .finish(&reply, &authority.public_xonly(), now)
            .err()
            .unwrap_or_else(|| panic!("byte {at} flipped and still accepted"));
        assert!(
            format!("{err:#}").contains("did not authenticate"),
            "byte {at}: {err:#}"
        );
    }
    // A different ephemeral key makes every later MAC fail too.
    let (initiator, mut reply, _) = responder_answer(&authority, 3600, now);
    reply[0] ^= 1;
    assert!(initiator
        .finish(&reply, &authority.public_xonly(), now)
        .is_err());
}

#[test]
fn a_cipher_refuses_a_replayed_or_tampered_message() {
    let mut a = noise::CipherState::with_key([7; 32]);
    let mut b = noise::CipherState::with_key([7; 32]);
    let first = a.encrypt(&[], b"one").unwrap();
    let second = a.encrypt(&[], b"two").unwrap();
    assert_eq!(b.decrypt(&[], &first).unwrap(), b"one");
    // Replaying the first under the next nonce fails, and does not advance the nonce.
    assert!(b.decrypt(&[], &first).is_err());
    assert_eq!(b.nonce_value(), 1);
    let mut tampered = second.clone();
    tampered[0] ^= 0x80;
    assert!(b.decrypt(&[], &tampered).is_err());
    assert_eq!(b.decrypt(&[], &second).unwrap(), b"two");
}

#[test]
fn ciphertext_length_follows_the_spec_formula() {
    assert_eq!(wire::ciphertext_len(0), 0);
    assert_eq!(wire::ciphertext_len(1), 17);
    assert_eq!(wire::ciphertext_len(65519), 65535);
    assert_eq!(wire::ciphertext_len(65520), 65535 + 17);
    assert_eq!(wire::ciphertext_len(2 * 65519 + 5), 2 * 65535 + 21);
}

#[test]
fn messages_round_trip_and_malformed_ones_are_refused() {
    use wire::Message;
    let all = vec![
        Message::SetupConnection {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 5,
            endpoint_host: b"127.0.0.1".to_vec(),
            endpoint_port: 3333,
            vendor: b"v".to_vec(),
            hardware_version: b"h".to_vec(),
            firmware: b"f".to_vec(),
            device_id: vec![],
        },
        Message::OpenExtendedMiningChannel {
            request_id: 9,
            user_identity: b"u".to_vec(),
            nominal_hash_rate: 1.5e9,
            max_target: [0xff; 32],
            min_extranonce_size: 8,
        },
        Message::NewMiningJob {
            channel_id: 1,
            job_id: 2,
            min_ntime: None,
            version: 0x2000_0000,
            merkle_root: [3; 32],
        },
        Message::NewExtendedMiningJob {
            channel_id: 1,
            job_id: 2,
            min_ntime: Some(7),
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: vec![[1; 32], [2; 32]],
            coinbase_tx_prefix: vec![1, 2, 3],
            coinbase_tx_suffix: vec![4, 5],
        },
        Message::SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 2,
            job_id: 3,
            nonce: 4,
            ntime: 5,
            version: 6,
            extranonce: vec![0; 8],
        },
        Message::SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 2,
            new_submits_accepted_count: 3,
            new_shares_sum: 4,
        },
        Message::SetGroupChannel {
            group_channel_id: 1,
            channel_ids: vec![2, 3],
        },
    ];
    for m in all {
        let frame = m.encode();
        assert_eq!(
            frame.extension_type & wire::CHANNEL_MSG_BIT != 0,
            wire::channel_bit(frame.msg_type)
        );
        assert_eq!(Message::decode(&frame).unwrap(), m);
        // One byte more, or one fewer, is malformed.
        let mut long = frame.clone();
        long.payload.push(0);
        assert!(
            Message::decode(&long).is_err(),
            "{m:?} with a trailing byte"
        );
        let mut short = frame.clone();
        short.payload.pop();
        assert!(Message::decode(&short).is_err(), "{m:?} cut short");
    }
    // F32 that is NaN, infinite or negative is a protocol error.
    for bad in [f32::NAN, f32::INFINITY, -1.0, -0.0] {
        let frame = Message::OpenStandardMiningChannel {
            request_id: 1,
            user_identity: vec![],
            nominal_hash_rate: bad,
            max_target: [0xff; 32],
        }
        .encode();
        assert!(Message::decode(&frame).is_err(), "{bad}");
    }
    // OPTION with two elements, B0_32 longer than 32.
    let mut frame = Message::NewMiningJob {
        channel_id: 1,
        job_id: 2,
        min_ntime: Some(1),
        version: 0,
        merkle_root: [0; 32],
    }
    .encode();
    frame.payload[8] = 2;
    assert!(Message::decode(&frame).is_err());
    let mut frame = Message::SetExtranoncePrefix {
        channel_id: 1,
        extranonce_prefix: vec![0; 32],
    }
    .encode();
    frame.payload[4] = 33;
    frame.payload.push(0);
    assert!(Message::decode(&frame).is_err());
    // Unknown types and non-core extensions are not decoded as core messages.
    let unknown = wire::Frame {
        extension_type: 0,
        msg_type: 0x7f,
        payload: vec![],
    };
    assert!(Message::decode(&unknown).is_err());
    let extension = wire::Frame {
        extension_type: 0x4001,
        msg_type: 0x00,
        payload: vec![],
    };
    assert!(Message::decode(&extension).is_err());
}

#[test]
fn targets_and_difficulty_agree() {
    // Difficulty 1 is 0x00000000ffff0000…: little-endian, bytes 26 and 27 are ff.
    let one = wire::target_for(1.0);
    let mut expected = [0u8; 32];
    expected[26] = 0xff;
    expected[27] = 0xff;
    assert_eq!(one, expected);
    assert!((wire::target_difficulty(&one) - 1.0).abs() < 1e-9);
    for d in [0.0001, 0.5, 3.0, 1e6, 1e12] {
        let back = wire::target_difficulty(&wire::target_for(d));
        assert!((back / d - 1.0).abs() < 1e-9, "{d} → {back}");
    }
    assert!(wire::meets(&wire::target_for(2.0), &one));
    assert!(!wire::meets(&one, &wire::target_for(2.0)));
    assert_eq!(wire::target_for(1e-80), [0xff; 32]);
}
