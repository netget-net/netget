//! NetGet's Stratum V2 pool driven frame by frame with NetGet's own codec, for what no real
//! device sends: handshakes and frames that do not authenticate, frames over the bound, unknown
//! and malformed messages, every share Rust refuses before the model is asked, the model's own
//! refusals, an extended channel's share, and a model that fails. The independent evidence is
//! `real_client_test.rs`; this file is the refusals.
use super::support::{self, Raw};
use netget::server::stratum_v2::{wire, MAX_INBOUND_PAYLOAD};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wire::Message;

const DIFFICULTY: f64 = 0.00001;

/// The connection ends: EOF or a reset, within the deadline, with nothing more said.
async fn hung_up(raw: &mut Raw) -> bool {
    raw.recv().await.is_none()
}

#[tokio::test]
async fn rust_refuses_before_the_model() {
    let (state, id, port) = support::start(
        support::policy(DIFFICULTY),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;

    // A handshake whose first message is noise gets an answer (any 64 bytes decode as a key),
    // and then the first frame cannot authenticate.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&[0x5a; 64]).await.unwrap();
    let mut reply = [0u8; 234];
    s.read_exact(&mut reply).await.unwrap();
    s.write_all(&[0x11; 22]).await.unwrap();
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut rest))
        .await
        .expect("the pool kept a connection whose frame did not authenticate")
        .unwrap_or(0);
    assert_eq!(n, 0, "the pool answered an unauthenticated frame");

    // A frame whose payload was tampered with.
    let mut raw = Raw::connect(port).await;
    let mut bytes =
        wire::seal(&mut raw.send, &support::setup_message("tamper", 0).encode()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    raw.raw(&bytes).await;
    assert!(hung_up(&mut raw).await, "tampered payload accepted");

    // A header declaring one byte more than the bound: refused before any payload is sent.
    let mut raw = Raw::connect(port).await;
    let declared = (MAX_INBOUND_PAYLOAD + 1) as u32;
    let mut header = vec![0u8, 0, 0];
    header.extend_from_slice(&declared.to_le_bytes()[..3]);
    let sealed = raw.send.encrypt(&[], &header).unwrap();
    raw.raw(&sealed).await;
    assert!(
        hung_up(&mut raw).await,
        "an over-bound header was waited on"
    );

    // Exactly the bound is read (as an unknown extension, ignored) and the session goes on.
    let mut raw = Raw::connect(port).await;
    raw.frame(&wire::Frame {
        extension_type: 0x4001,
        msg_type: 0,
        payload: vec![0xab; MAX_INBOUND_PAYLOAD],
    })
    .await;
    assert!(matches!(
        raw.setup("netget", 0).await,
        Message::SetupConnectionSuccess {
            used_version: 2,
            flags: 0
        }
    ));

    // Before SetupConnection, nothing else is accepted.
    let mut raw = Raw::connect(port).await;
    raw.send(&Message::OpenStandardMiningChannel {
        request_id: 1,
        user_identity: b"netget".to_vec(),
        nominal_hash_rate: 1.0,
        max_target: [0xff; 32],
    })
    .await;
    assert!(hung_up(&mut raw).await);

    // An unknown core message, a malformed SetupConnection, and a NaN hash rate.
    let mut raw = Raw::connect(port).await;
    raw.frame(&wire::Frame {
        extension_type: 0,
        msg_type: 0x7f,
        payload: vec![],
    })
    .await;
    assert!(hung_up(&mut raw).await);
    let mut raw = Raw::connect(port).await;
    let mut frame = support::setup_message("netget", 0).encode();
    frame.payload.push(0);
    raw.frame(&frame).await;
    assert!(hung_up(&mut raw).await);
    let mut raw = Raw::connect(port).await;
    assert!(matches!(
        raw.setup("netget", 0).await,
        Message::SetupConnectionSuccess { .. }
    ));
    raw.send(&Message::OpenStandardMiningChannel {
        request_id: 1,
        user_identity: b"netget".to_vec(),
        nominal_hash_rate: f32::NAN,
        max_target: [0xff; 32],
    })
    .await;
    assert!(hung_up(&mut raw).await);
    let calls_after_good_setups = support::model_calls(&state, id).await;
    assert_eq!(
        calls_after_good_setups, 2,
        "only the two complete setups reached the model"
    );

    // Unsupported features, version and protocol are refused by Rust, with the flags named.
    for (setup, flags, code) in [
        (
            support::setup_message("netget", wire::REQUIRES_WORK_SELECTION),
            wire::REQUIRES_WORK_SELECTION,
            "unsupported-feature-flags",
        ),
        (
            support::setup_message("netget", 1 << 9),
            1 << 9,
            "unsupported-feature-flags",
        ),
    ] {
        let mut raw = Raw::connect(port).await;
        raw.send(&setup).await;
        match raw.recv().await {
            Some(Message::SetupConnectionError {
                flags: f,
                error_code,
            }) => {
                assert_eq!(f, flags);
                assert_eq!(error_code, code.as_bytes());
            }
            other => panic!("{other:?}"),
        }
        assert!(hung_up(&mut raw).await);
    }
    let mut bad_version = support::setup_message("netget", 0);
    if let Message::SetupConnection {
        min_version,
        max_version,
        ..
    } = &mut bad_version
    {
        *min_version = 3;
        *max_version = 4;
    }
    let mut bad_protocol = support::setup_message("netget", 0);
    if let Message::SetupConnection { protocol, .. } = &mut bad_protocol {
        *protocol = 2;
    }
    for (setup, code) in [
        (bad_version, "protocol-version-mismatch"),
        (bad_protocol, "unsupported-protocol"),
    ] {
        let mut raw = Raw::connect(port).await;
        raw.send(&setup).await;
        assert!(
            matches!(raw.recv().await, Some(Message::SetupConnectionError { error_code, .. }) if error_code == code.as_bytes())
        );
    }
    assert_eq!(
        support::model_calls(&state, id).await,
        calls_after_good_setups
    );
}

#[tokio::test]
async fn the_model_decides_and_rust_verifies_every_share() {
    let (state, id, port) = support::start(
        support::policy(DIFFICULTY),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;

    // The model refuses a device, then a user.
    let mut raw = Raw::connect(port).await;
    assert!(matches!(raw.setup("blocked", 0).await,
        Message::SetupConnectionError { flags: 0, error_code } if error_code == b"device-blocked"));
    let mut raw = Raw::connect(port).await;
    assert!(matches!(
        raw.setup("netget", 0).await,
        Message::SetupConnectionSuccess { .. }
    ));
    let setup = support::events(&state, id, "stratum_v2_setup_connection").await;
    assert_eq!(setup.len(), 2, "{setup:?}");
    let admitted = setup
        .iter()
        .find(|e| e["vendor"] == "netget")
        .expect("the admitted device");
    assert_eq!(admitted["device_id"], "raw-1", "{setup:?}");
    assert_eq!(admitted["hardware_version"], "raw", "{setup:?}");
    raw.send(&Message::OpenStandardMiningChannel {
        request_id: 3,
        user_identity: b"intruder".to_vec(),
        nominal_hash_rate: 1000.0,
        max_target: [0xff; 32],
    })
    .await;
    assert!(matches!(raw.recv().await,
        Some(Message::OpenMiningChannelError { request_id: 3, error_code }) if error_code == b"unknown-user"));

    // An accepted channel at the model's difficulty, on the model's prev hash.
    let (success, job, prev) = raw.open_standard("netget.raw").await;
    let Message::OpenStandardMiningChannelSuccess {
        request_id: 7,
        channel_id,
        target,
        extranonce_prefix,
        ..
    } = success
    else {
        panic!("{success:?}");
    };
    assert_eq!(target, wire::target_for(DIFFICULTY));
    assert_eq!(extranonce_prefix.len(), 4);
    let Message::NewMiningJob {
        job_id,
        min_ntime: None,
        version,
        merkle_root,
        ..
    } = job
    else {
        panic!("the first job must be a future job: {job:?}");
    };
    let Message::SetNewPrevHash {
        job_id: activated,
        prev_hash,
        min_ntime: ntime,
        nbits,
        ..
    } = prev
    else {
        panic!("{prev:?}");
    };
    assert_eq!(activated, job_id);
    assert_eq!(
        wire::display_hex(&prev_hash),
        "00000000000000000000000000000000000000000000000000000000deadbeef"
    );
    let open = support::events(&state, id, "stratum_v2_open_channel").await;
    assert_eq!(open.len(), 2);
    let opened = open
        .iter()
        .find(|e| e["user_identity"] == "netget.raw")
        .expect("the opened channel");
    assert_eq!(opened["channel_kind"], "standard");
    assert!(opened["default_difficulty"].as_f64().unwrap() > 0.0);

    let submit =
        |seq: u32, job: u32, nonce: u32, ntime: u32, version: u32| Message::SubmitSharesStandard {
            channel_id,
            sequence_number: seq,
            job_id: job,
            nonce,
            ntime,
            version,
        };
    let (good, good_hash) = support::find_nonce(
        version,
        &prev_hash,
        &merkle_root,
        ntime,
        nbits,
        &target,
        true,
    );
    let (bad, _) = support::find_nonce(
        version,
        &prev_hash,
        &merkle_root,
        ntime,
        nbits,
        &target,
        false,
    );
    let refusals = [
        (
            Message::SubmitSharesStandard {
                channel_id: 99,
                sequence_number: 11,
                job_id,
                nonce: good,
                ntime,
                version,
            },
            "invalid-channel-id",
        ),
        (
            submit(12, job_id + 1000, good, ntime, version),
            "invalid-job-id",
        ),
        (
            submit(13, job_id, good, ntime - 1, version),
            "invalid-timestamp",
        ),
        (
            submit(14, job_id, good, wire::now_secs() + 7300, version),
            "invalid-timestamp",
        ),
        (
            submit(15, job_id, good, ntime, version | 0x8000_0000),
            "invalid-version",
        ),
        (
            submit(16, job_id, bad, ntime, version),
            "difficulty-too-low",
        ),
    ];
    for (share, code) in refusals {
        raw.send(&share).await;
        match raw.recv().await {
            Some(Message::SubmitSharesError { error_code, .. }) => {
                assert_eq!(String::from_utf8_lossy(&error_code), code, "{share:?}")
            }
            other => panic!("{share:?} → {other:?}"),
        }
    }
    assert!(
        support::events(&state, id, "stratum_v2_share")
            .await
            .is_empty(),
        "a refused share reached the model"
    );

    // A good share: the model credits odd sequence numbers, refuses even ones.
    raw.send(&submit(1, job_id, good, ntime, version)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SubmitSharesSuccess {
            last_sequence_number: 1,
            new_submits_accepted_count: 1,
            ..
        })
    ));
    let shares = support::events(&state, id, "stratum_v2_share").await;
    assert_eq!(shares[0]["hash"], wire::display_hex(&good_hash));
    assert!(shares[0]["share_difficulty"].as_f64().unwrap() >= DIFFICULTY);
    assert_eq!(shares[0]["user_identity"], "netget.raw");
    raw.send(&submit(2, job_id, good, ntime, version)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"duplicate-share"));
    // Version rolling inside the BIP 320 bits is a different header and is verified as such.
    let rolled = version | 0x0000_6000;
    let (n2, _) = support::find_nonce(
        rolled,
        &prev_hash,
        &merkle_root,
        ntime,
        nbits,
        &target,
        true,
    );
    raw.send(&submit(2, job_id, n2, ntime, rolled)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"policy-rejected"));
    assert_eq!(
        support::events(&state, id, "stratum_v2_share").await.len(),
        2
    );

    // UpdateChannel asking for a smaller max_target is honoured with SetTarget.
    let tighter = wire::target_for(DIFFICULTY * 4.0);
    raw.send(&Message::UpdateChannel {
        channel_id,
        nominal_hash_rate: 10.0,
        max_target: tighter,
    })
    .await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetTarget { maximum_target, .. }) if maximum_target == tighter));

    // An extended channel: Rust rebuilds the coinbase from the device's extranonce.
    raw.send(&Message::OpenExtendedMiningChannel {
        request_id: 8,
        user_identity: b"netget.ext".to_vec(),
        nominal_hash_rate: 1000.0,
        max_target: [0xff; 32],
        min_extranonce_size: 4,
    })
    .await;
    let Some(Message::OpenExtendedMiningChannelSuccess {
        channel_id: ext,
        extranonce_size: 8,
        extranonce_prefix,
        target,
        ..
    }) = raw.recv().await
    else {
        panic!("no extended channel");
    };
    let Some(Message::NewExtendedMiningJob {
        job_id,
        min_ntime: None,
        version,
        coinbase_tx_prefix,
        coinbase_tx_suffix,
        merkle_path,
        ..
    }) = raw.recv().await
    else {
        panic!("no extended job");
    };
    let Some(Message::SetNewPrevHash {
        prev_hash,
        min_ntime: ntime,
        nbits,
        ..
    }) = raw.recv().await
    else {
        panic!("no prev hash");
    };
    assert!(merkle_path.is_empty());
    let extranonce = vec![9u8; 8];
    let coinbase = [
        &coinbase_tx_prefix[..],
        &extranonce_prefix,
        &extranonce,
        &coinbase_tx_suffix,
    ]
    .concat();
    let root = wire::merkle_root(&coinbase, &[]);
    let (nonce, _) = support::find_nonce(version, &prev_hash, &root, ntime, nbits, &target, true);
    let ext_share = |seq: u32, extranonce: Vec<u8>| Message::SubmitSharesExtended {
        channel_id: ext,
        sequence_number: seq,
        job_id,
        nonce,
        ntime,
        version,
        extranonce,
    };
    raw.send(&ext_share(20, vec![9u8; 4])).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"invalid-extranonce-size"));
    // The standard channel does not know the extended channel's job.
    raw.send(&submit(21, job_id, nonce, ntime, version)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"invalid-job-id"));
    raw.send(&Message::SubmitSharesStandard {
        channel_id: ext,
        sequence_number: 22,
        job_id,
        nonce,
        ntime,
        version,
    })
    .await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"invalid-channel-type"));
    raw.send(&ext_share(3, extranonce.clone())).await;
    assert!(
        matches!(raw.recv().await, Some(Message::SubmitSharesSuccess { channel_id: c, .. }) if c == ext)
    );
    let shares = support::events(&state, id, "stratum_v2_share").await;
    assert_eq!(
        shares[0]["channel_kind"], "extended",
        "the newest share is the extended one"
    );
    // Another extranonce is another coinbase and so another header, which Rust measures afresh:
    // the same nonce is no duplicate, and almost certainly misses the target.
    raw.send(&ext_share(5, vec![1u8; 8])).await;
    match raw.recv().await {
        Some(Message::SubmitSharesSuccess { .. }) => {}
        Some(Message::SubmitSharesError { error_code, .. }) => {
            assert_eq!(error_code, b"difficulty-too-low")
        }
        other => panic!("{other:?}"),
    }

    // A channel closed by the device refuses its shares.
    raw.send(&Message::CloseChannel {
        channel_id: ext,
        reason_code: b"done".to_vec(),
    })
    .await;
    raw.send(&ext_share(7, extranonce)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"invalid-channel-id"));
}

#[tokio::test]
async fn the_model_moving_work_makes_old_shares_stale() {
    let mut handlers = support::policy(DIFFICULTY).unwrap();
    // The first credited share moves the channel to a new prev hash.
    handlers[0]["handler"]["code"] = json!(handlers[0]["handler"]["code"].as_str().unwrap().replace(
        "a=[{'type':'stratum_v2_accept'}] if e['sequence_number']%2==1",
        "a=[{'type':'stratum_v2_accept'},{'type':'stratum_v2_new_job','message':'next','prev_hash':'00000000000000000000000000000000000000000000000000000000cafecafe'},{'type':'stratum_v2_set_target','difficulty':0.00002}] if e['sequence_number']%2==1"
    ));
    let (_state, _id, port) = support::start(
        Some(handlers),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.setup("netget", 0).await;
    let (success, job, prev) = raw.open_standard("netget.stale").await;
    let (
        Message::OpenStandardMiningChannelSuccess {
            channel_id, target, ..
        },
        Message::NewMiningJob {
            job_id,
            version,
            merkle_root,
            ..
        },
        Message::SetNewPrevHash {
            prev_hash,
            min_ntime: ntime,
            nbits,
            ..
        },
    ) = (success, job, prev)
    else {
        panic!("no channel");
    };
    let (nonce, _) = support::find_nonce(
        version,
        &prev_hash,
        &merkle_root,
        ntime,
        nbits,
        &target,
        true,
    );
    let share = |seq| Message::SubmitSharesStandard {
        channel_id,
        sequence_number: seq,
        job_id,
        nonce,
        ntime,
        version,
    };
    raw.send(&share(1)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SubmitSharesSuccess { .. })
    ));
    let Some(Message::NewMiningJob {
        job_id: next,
        min_ntime: None,
        ..
    }) = raw.recv().await
    else {
        panic!("no new job")
    };
    assert!(matches!(raw.recv().await,
        Some(Message::SetNewPrevHash { job_id, prev_hash, .. }) if job_id == next && wire::display_hex(&prev_hash).ends_with("cafecafe")));
    assert!(matches!(raw.recv().await,
        Some(Message::SetTarget { maximum_target, .. }) if maximum_target == wire::target_for(0.00002)));
    raw.send(&share(3)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SubmitSharesError { error_code, .. }) if error_code == b"stale-share"));
}

#[tokio::test]
async fn a_failed_model_admits_nobody_and_credits_nothing() {
    // No handler and no reachable model: the connection is refused with a category.
    let (state, id, port) =
        support::start(None, json!({"authority_secret_key": support::SECRET})).await;
    let mut raw = Raw::connect(port).await;
    match raw.setup("netget", 0).await {
        Message::SetupConnectionError {
            flags: 0,
            error_code,
        } => {
            assert_eq!(error_code, b"service-unavailable")
        }
        other => panic!("a failed model admitted a device: {other:?}"),
    }
    assert!(hung_up(&mut raw).await);
    assert_eq!(
        support::events(&state, id, "stratum_v2_setup_connection")
            .await
            .len(),
        1
    );

    // A model that admits and opens, then fails on the share: the share is refused.
    let mut handlers = support::policy(DIFFICULTY).unwrap();
    handlers[0]["handler"]["code"] = json!(handlers[0]["handler"]["code"]
        .as_str()
        .unwrap()
        .replace("else:\n  a=", "else:\n  sys.exit(3)\n  a="));
    let (_state, _id, port) = support::start(
        Some(handlers),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.setup("netget", 0).await;
    let (success, job, prev) = raw.open_standard("netget.fail").await;
    let (
        Message::OpenStandardMiningChannelSuccess {
            channel_id, target, ..
        },
        Message::NewMiningJob {
            job_id,
            version,
            merkle_root,
            ..
        },
        Message::SetNewPrevHash {
            prev_hash,
            min_ntime: ntime,
            nbits,
            ..
        },
    ) = (success, job, prev)
    else {
        panic!("no channel");
    };
    let (nonce, _) = support::find_nonce(
        version,
        &prev_hash,
        &merkle_root,
        ntime,
        nbits,
        &target,
        true,
    );
    raw.send(&Message::SubmitSharesStandard {
        channel_id,
        sequence_number: 1,
        job_id,
        nonce,
        ntime,
        version,
    })
    .await;
    match raw.recv().await {
        Some(Message::SubmitSharesError { error_code, .. }) => {
            assert_eq!(error_code, b"service-unavailable")
        }
        other => panic!("a failed model credited a share: {other:?}"),
    }
}
