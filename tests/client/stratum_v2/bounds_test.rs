//! NetGet's Stratum V2 mining device against a canned pool written in this file with NetGet's
//! own codec, for what SRI's pool never does: refuse SetupConnection, send a frame over the
//! client's bound, and answer every share with an error so a handler that always mines would
//! loop forever without the follow-up bound. Not interoperability evidence — that is
//! `real_server_test.rs` — but each bound here was checked by removing it.
use netget::cli::management::ClientForm;
use netget::client::stratum_v2::{MAX_FOLLOWUP_DEPTH, MAX_INBOUND_PAYLOAD};
use netget::server::stratum_v2::{noise, wire};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use wire::Message;

#[derive(Clone, Copy)]
enum Behaviour {
    RefuseSetup,
    LargeFrame,
    RefuseEveryShare,
}

/// A pool on a free port; returns its port, its authority key and a count of shares received.
async fn canned_pool(behaviour: Behaviour) -> (u16, String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = noise::Authority::generate();
    let key = noise::encode_authority_key(&authority.public_xonly());
    let shares = Arc::new(AtomicUsize::new(0));
    let counter = shares.clone();
    tokio::spawn(async move {
        let static_key = noise::EllKey::generate();
        while let Ok((mut stream, _)) = listener.accept().await {
            let session = wire::accept_handshake(
                &mut stream,
                &static_key,
                &authority,
                3600,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
            let (r, w) = tokio::io::split(stream);
            let (mut reader, mut writer) = wire::transport(r, w, session, 1 << 20);
            let counter = counter.clone();
            tokio::spawn(async move {
                while let Ok(Some(frame)) = reader.next(Duration::from_secs(60)).await {
                    let reply = match Message::decode(&frame).unwrap() {
                        Message::SetupConnection { .. } => match behaviour {
                            Behaviour::RefuseSetup => vec![Message::SetupConnectionError {
                                flags: 0,
                                error_code: b"pool-full".to_vec(),
                            }],
                            _ => vec![Message::SetupConnectionSuccess {
                                used_version: 2,
                                flags: 0,
                            }],
                        },
                        Message::OpenStandardMiningChannel { request_id, .. } => {
                            let job = match behaviour {
                                // Two full coinbase halves: ~128 KiB, under the client's bound.
                                Behaviour::LargeFrame => Message::NewExtendedMiningJob {
                                    channel_id: 1,
                                    job_id: 1,
                                    min_ntime: None,
                                    version: 0x2000_0000,
                                    version_rolling_allowed: true,
                                    merkle_path: vec![],
                                    coinbase_tx_prefix: vec![0; 65535],
                                    coinbase_tx_suffix: vec![0; 65535],
                                },
                                _ => Message::NewMiningJob {
                                    channel_id: 1,
                                    job_id: 1,
                                    min_ntime: None,
                                    version: 0x2000_0000,
                                    merkle_root: [7; 32],
                                },
                            };
                            vec![
                                Message::OpenStandardMiningChannelSuccess {
                                    request_id,
                                    channel_id: 1,
                                    target: [0xff; 32],
                                    extranonce_prefix: vec![0; 4],
                                    group_channel_id: 0,
                                },
                                job,
                                Message::SetNewPrevHash {
                                    channel_id: 1,
                                    job_id: 1,
                                    prev_hash: [0; 32],
                                    min_ntime: wire::now_secs(),
                                    nbits: 0x207f_ffff,
                                },
                            ]
                        }
                        Message::SubmitSharesStandard {
                            channel_id,
                            sequence_number,
                            ..
                        } => {
                            counter.fetch_add(1, Ordering::SeqCst);
                            vec![Message::SubmitSharesError {
                                channel_id,
                                sequence_number,
                                error_code: b"no-thanks".to_vec(),
                            }]
                        }
                        _ => vec![],
                    };
                    for m in reply {
                        if writer.send(&m).await.is_err() {
                            return;
                        }
                    }
                }
                writer.shutdown().await;
            });
        }
    });
    (port, key, shares)
}

async fn connect(
    port: u16,
    key: &str,
    handler: serde_json::Value,
) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "stratum_v2".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Mine".into()),
        startup_params: Some(json!({"authority_public_key": key})),
        event_handlers: Some(match handler {
            serde_json::Value::Array(all) => all,
            one => vec![one],
        }),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

#[tokio::test]
async fn a_refused_setup_and_a_foreign_certificate_fail_the_connect() {
    let (port, key, _) = canned_pool(Behaviour::RefuseSetup).await;
    let quiet = json!({"event_pattern":"*","handler":{"type":"static","actions":[]}});
    let err = connect(port, &key, quiet.clone())
        .await
        .err()
        .expect("refused setup connected");
    assert!(format!("{err:#}").contains("pool-full"), "{err:#}");
    let other = noise::encode_authority_key(&noise::Authority::generate().public_xonly());
    let err = connect(port, &other, quiet.clone())
        .await
        .err()
        .expect("foreign certificate connected");
    assert!(format!("{err:#}").contains("not signed"), "{err:#}");
    let err = connect(port, "not-a-key", quiet)
        .await
        .err()
        .expect("a malformed key connected");
    assert!(
        format!("{err:#}").contains("authority_public_key"),
        "{err:#}"
    );
}

#[tokio::test]
async fn a_handler_that_always_mines_stops_at_the_follow_up_bound() {
    let (port, key, shares) = canned_pool(Behaviour::RefuseEveryShare).await;
    let mine = json!({"type":"static","actions":[{"type":"stratum_v2_mine","max_hashes":1,"submit_best":true}]});
    let always = json!([
        {"event_pattern":"stratum_v2_job","handler": mine},
        {"event_pattern":"stratum_v2_share_result","handler": mine},
        {"event_pattern":"*","handler":{"type":"static","actions":[]}},
    ]);
    let (_state, _id) = connect(port, &key, always).await.expect("connect");
    // Job (depth 0) → mine at depth 1 → refused → mine at depth 2 … → depth 8 is the last.
    let settled = tokio::time::timeout(Duration::from_secs(30), async {
        let mut last = usize::MAX;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let now = shares.load(Ordering::SeqCst);
            if now == last && now > 0 {
                return now;
            }
            last = now;
        }
    })
    .await
    .expect("the share loop never settled");
    assert_eq!(
        settled, MAX_FOLLOWUP_DEPTH,
        "shares submitted before the chain stopped"
    );
}

#[tokio::test]
async fn a_frame_over_the_bound_ends_the_session() {
    // Two full coinbase halves are ~128 KiB: under the bound, so this one is read.
    let (port, key, _) = canned_pool(Behaviour::LargeFrame).await;
    let quiet = json!({"event_pattern":"*","handler":{"type":"static","actions":[]}});
    let (state, id) = connect(port, &key, quiet.clone()).await.expect("connect");
    let job = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == "stratum_v2_job");
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the ~128 KiB job under the bound was not read");
    assert_eq!(job["request"]["merkle_path_len"], 0, "{job}");
    assert!(
        matches!(
            state.get_client(id).await.map(|c| c.status),
            Some(ClientStatus::Connected)
        ),
        "a frame under the bound ended the session"
    );

    // A pool that declares one byte past the bound in a frame header.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = noise::Authority::generate();
    let key = noise::encode_authority_key(&authority.public_xonly());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut session = wire::accept_handshake(
            &mut stream,
            &noise::EllKey::generate(),
            &authority,
            3600,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 22];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        let ok = wire::seal(
            &mut session.send,
            &Message::SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            }
            .encode(),
        )
        .unwrap();
        stream.write_all(&ok).await.unwrap();
        let declared = (MAX_INBOUND_PAYLOAD + 1) as u32;
        let mut header = vec![0u8, 0x80, wire::msg::NEW_MINING_JOB];
        header.extend_from_slice(&declared.to_le_bytes()[..3]);
        let sealed = session.send.encrypt(&[], &header).unwrap();
        stream.write_all(&sealed).await.unwrap();
        // Hold the connection open: the client must end it, not the pool.
        let mut rest = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest).await;
    });
    let (state, id) = connect(port, &key, quiet).await.expect("connect");
    let status = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match state.get_client(id).await.map(|c| c.status) {
                Some(ClientStatus::Connected) | Some(ClientStatus::Connecting) => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                other => return other,
            }
        }
    })
    .await
    .expect("the client kept a session whose pool declared an over-bound frame");
    match status {
        Some(ClientStatus::Error(e)) => assert!(e.contains("accepts"), "{e}"),
        other => panic!("{other:?}"),
    }
}
