//! The M-Bus gateway from a raw master socket: readouts, the FCB rule, multi-telegram
//! readouts, selection and collisions, writes, the fail-closed paths and the bounds — and a
//! mocked model through the binary.
//!
//! A python policy (`support::POLICY`) plays the model, except in the last test.
use super::support::{self, decode, expect_log, Gateway, HEAT, WATER};
use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::server::mbus::frame::{self, c, ci, Frame};
use netget::server::mbus::records;
use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const SILENCE: Duration = Duration::from_millis(1500);

async fn policy_gateway() -> Gateway {
    support::start(support::policy(), support::params()).await
}

fn write_frame(a: u8, fcb: bool, records: &[serde_json::Value]) -> Frame {
    let mut data = Vec::new();
    for r in records {
        data.extend(records::encode_record(r).unwrap());
    }
    Frame::long(
        c::SND_UD | if fcb { c::FCB } else { 0 },
        a,
        ci::DATA_SEND,
        data,
    )
}

#[tokio::test]
async fn a_readout_carries_the_models_records_encoded_and_the_meters_identity() {
    let g = policy_gateway().await;
    let mut m = g.master().await;
    let answer = m.req_ud2(1, true).await;
    assert_eq!(answer.len(), 1, "{answer:?}");
    assert_eq!(answer[0].a(), Some(1));
    let (h, d) = decode(&answer[0]);
    assert_eq!(h.address.to_hex(), HEAT);
    assert_eq!(h.status, 0);
    let r = &d.records;
    assert_eq!(r.len(), 5, "{r:?}");
    assert_eq!(
        (r[0]["quantity"].clone(), r[0]["value"].clone()),
        (json!("energy"), json!(12345000))
    );
    assert_eq!(r[1]["value"], json!(456.789));
    assert_eq!(r[1]["encoding"], "bcd6");
    assert_eq!(r[2]["value"], json!(65.4));
    assert_eq!(r[3]["storage"], json!(1));
    assert_eq!(r[3]["tariff"], json!(1));
    assert_eq!(r[4]["value"], "2026-09-30");
    // The water meter: a real in litres, a negative BCD, and the power-low flag.
    let (h, d) = decode(&m.req_ud2(2, true).await[0]);
    assert_eq!(h.address.to_hex(), WATER);
    assert_eq!(h.status, records::status::POWER_LOW);
    assert_eq!(d.records[0]["value"], json!(1.2345));
    assert_eq!(d.records[1]["value"], json!(-0.042));
    // The model saw which meter was asked, and how.
    let events = g.events("mbus_request_data").await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["meter"]["secondary_address"], HEAT);
    assert_eq!(events[0]["meter"]["manufacturer"], "KAM");
    assert_eq!(events[0]["addressed_by"], "primary");
    // An address with no meter is silent.
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2,
            a: 3,
        },
        SILENCE,
    )
    .await;
    expect_log(&g, "decision=model_answer").await;
}

#[tokio::test]
async fn a_repeated_fcb_resends_the_last_telegram_and_never_asks_the_model() {
    let g = policy_gateway().await;
    let mut m = g.master().await;
    let first = m.req_ud2(1, true).await;
    let again = m.req_ud2(1, true).await;
    assert_eq!(first, again, "a repeated FCB must get the same telegram");
    assert_eq!(g.events("mbus_request_data").await.len(), 1);
    // Toggled: a fresh readout, with the next access number.
    let fresh = m.req_ud2(1, false).await;
    assert_eq!(
        decode(&fresh[0]).0.access_number,
        decode(&first[0]).0.access_number + 1
    );
    assert_eq!(g.events("mbus_request_data").await.len(), 2);
    // A new connection is a new master session: its first FCB is never a "repeat".
    let mut other = g.master().await;
    other.req_ud2(1, false).await;
    assert_eq!(g.events("mbus_request_data").await.len(), 3);
    // Without FCV the FCB means nothing and every request is fresh.
    m.ask(&Frame::Short {
        c: 0x4B | c::FCB,
        a: 1,
    })
    .await;
    m.ask(&Frame::Short {
        c: 0x4B | c::FCB,
        a: 1,
    })
    .await;
    assert_eq!(g.events("mbus_request_data").await.len(), 5);
    expect_log(&g, "repeats FCB 1").await;
}

#[tokio::test]
async fn a_readout_too_big_for_one_telegram_is_fetched_by_toggling_the_fcb() {
    let g = support::start(support::script(support::BIG_POLICY), support::params()).await;
    let mut m = g.master().await;
    let mut fcb = true;
    let mut storages = Vec::new();
    let mut telegrams = 0;
    loop {
        let answer = m.req_ud2(1, fcb).await;
        assert_eq!(answer.len(), 1);
        if telegrams == 1 {
            // Mid-readout, the same FCB again repeats the second telegram.
            let repeat = m.req_ud2(1, fcb).await;
            assert_eq!(repeat, answer);
        }
        let (_, d) = decode(&answer[0]);
        telegrams += 1;
        storages.extend(d.records.iter().map(|r| r["storage"].as_u64().unwrap()));
        if !d.more_records_follow {
            break;
        }
        fcb = !fcb;
        assert!(telegrams < 20, "the readout never ended");
    }
    assert!(telegrams > 1, "120 records fit one telegram?");
    assert_eq!(storages, (0..120).collect::<Vec<u64>>());
    assert_eq!(
        g.events("mbus_request_data").await.len(),
        1,
        "the model was asked again mid-readout"
    );
    // SND_NKE abandons the readout: the next request is a fresh one.
    assert_eq!(m.snd_nke(1).await, vec![Frame::Ack]);
    m.req_ud2(1, true).await;
    assert_eq!(g.events("mbus_request_data").await.len(), 2);
}

#[tokio::test]
async fn selection_addresses_one_meter_and_a_mask_matching_two_collides() {
    let g = policy_gateway().await;
    let mut m = g.master().await;
    assert_eq!(m.select(HEAT).await, vec![Frame::Ack]);
    let (h, _) = decode(&m.req_ud2(frame::addr::NETWORK_LAYER, true).await[0]);
    assert_eq!(h.address.to_hex(), HEAT);
    assert_eq!(
        g.events("mbus_request_data").await[0]["addressed_by"],
        "secondary"
    );
    // Selecting the water meter deselects the heat meter.
    assert_eq!(m.select(WATER).await, vec![Frame::Ack]);
    let (h, _) = decode(&m.req_ud2(frame::addr::NETWORK_LAYER, false).await[0]);
    assert_eq!(h.address.to_hex(), WATER);
    // Both match: both answer, back to back.
    assert_eq!(
        m.select("1234567FFFFFFFFF").await,
        vec![Frame::Ack, Frame::Ack]
    );
    let both = m.req_ud2(frame::addr::NETWORK_LAYER, true).await;
    assert_eq!(both.len(), 2, "{both:?}");
    // Wildcards in the manufacturer, version and medium nibbles.
    assert_eq!(m.select("FFFFFFFF9315FFFF").await, vec![Frame::Ack]);
    assert_eq!(m.select("FFFFFFFFFFFFFF04").await, vec![Frame::Ack]);
    // Nobody matches: silence, and nobody is selected any more.
    m.expect_silence(&support::select_frame("99999999FFFFFFFF"), SILENCE)
        .await;
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2,
            a: frame::addr::NETWORK_LAYER,
        },
        SILENCE,
    )
    .await;
    // SND_NKE at 253 ends a selection.
    assert_eq!(m.select(HEAT).await, vec![Frame::Ack]);
    assert_eq!(
        m.snd_nke(frame::addr::NETWORK_LAYER).await,
        vec![Frame::Ack]
    );
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2 | c::FCB,
            a: frame::addr::NETWORK_LAYER,
        },
        SILENCE,
    )
    .await;
    // A selection not addressed to 253, and mode 2, select nothing.
    let mut wrong = support::select_frame(HEAT);
    if let Frame::Long { a, .. } = &mut wrong {
        *a = 1;
    }
    m.expect_silence(&wrong, SILENCE).await;
}

#[tokio::test]
async fn meters_sharing_an_address_answer_together_and_broadcasts_behave() {
    let params = json!({"meters": [
        {"primary_address": 5, "id": "11111111", "manufacturer": "KAM", "medium": "heat"},
        {"primary_address": 5, "id": "22222222", "manufacturer": "KAM", "medium": "heat"}
    ]});
    let g = support::start(support::policy(), params).await;
    let mut m = g.master().await;
    assert_eq!(m.snd_nke(5).await, vec![Frame::Ack, Frame::Ack]);
    let both = m.req_ud2(5, true).await;
    assert_eq!(both.len(), 2);
    let ids: Vec<String> = both.iter().map(|f| decode(f).0.address.to_hex()).collect();
    assert!(
        ids[0].starts_with("11111111") && ids[1].starts_with("22222222"),
        "{ids:?}"
    );
    // 254: everyone answers; 255: everyone listens, nobody answers.
    assert_eq!(m.snd_nke(254).await.len(), 2);
    m.expect_silence(
        &Frame::Short {
            c: c::SND_NKE,
            a: 255,
        },
        SILENCE,
    )
    .await;
    // REQ_UD1: no alarms, so E5.
    assert_eq!(
        m.ask(&Frame::Short {
            c: c::REQ_UD1,
            a: 5
        })
        .await,
        vec![Frame::Ack, Frame::Ack]
    );
}

#[tokio::test]
async fn writes_are_the_models_to_accept_and_a_bus_address_write_moves_the_meter() {
    let g = policy_gateway().await;
    let mut m = g.master().await;
    // The heat meter accepts a write; the same telegram again with the same FCB (the master
    // missed the E5) is acknowledged again without being applied, or shown, twice.
    let reset_energy = write_frame(
        1,
        true,
        &[json!({"quantity": "energy", "unit": "Wh", "value": 0})],
    );
    assert_eq!(m.ask(&reset_energy).await, vec![Frame::Ack]);
    assert_eq!(m.ask(&reset_energy).await, vec![Frame::Ack]);
    assert_eq!(g.events("mbus_write_data").await.len(), 1);
    expect_log(&g, "repeats FCB 1; acknowledging again").await;
    // A new primary address, FCB toggled: a new transaction the model decides.
    let ack = m
        .ask(&write_frame(
            1,
            false,
            &[json!({"quantity": "bus_address", "value": 7, "encoding": "int8"})],
        ))
        .await;
    assert_eq!(ack, vec![Frame::Ack]);
    let w = g.events("mbus_write_data").await;
    assert_eq!(w.len(), 2);
    assert_eq!(w[1]["records"][0]["quantity"], "bus_address");
    assert_eq!(w[1]["records"][0]["value"], json!(7));
    expect_log(&g, "moved from primary address 1 to 7").await;
    assert_eq!(
        decode(&m.req_ud2(7, true).await[0]).0.address.to_hex(),
        HEAT
    );
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2,
            a: 1,
        },
        SILENCE,
    )
    .await;
    // The water meter refuses writes: silence, which is how M-Bus says no.
    m.expect_silence(
        &write_frame(
            2,
            true,
            &[json!({"quantity": "volume", "unit": "m3", "value": 0})],
        ),
        SILENCE,
    )
    .await;
    expect_log(&g, "decision=model_reject").await;
    // Application reset, with a subcode.
    let reset = m
        .ask(&Frame::long(
            c::SND_UD,
            7,
            ci::APPLICATION_RESET,
            vec![0x10],
        ))
        .await;
    assert_eq!(reset, vec![Frame::Ack]);
    let r = g.events("mbus_application_reset").await;
    assert_eq!(r[0]["subcode"], json!(16));
    // Data the gateway cannot decode is not answered at all.
    m.expect_silence(
        &Frame::long(c::SND_UD, 7, ci::DATA_SEND, vec![0x04, 0x13, 0x01]),
        SILENCE,
    )
    .await;
    // Baud-rate changes are acknowledged by the link layer.
    assert_eq!(
        m.ask(&Frame::long(c::SND_UD, 7, 0xBD, vec![])).await,
        vec![Frame::Ack]
    );
}

#[tokio::test]
async fn with_no_model_a_readout_reports_an_error_status_and_no_readings() {
    let g = support::start(None, support::params()).await;
    let mut m = g.master().await;
    let answer = m.req_ud2(1, true).await;
    assert_eq!(answer.len(), 1);
    let (h, d) = decode(&answer[0]);
    assert_eq!(
        h.address.to_hex(),
        HEAT,
        "the identity is the configuration's"
    );
    assert_eq!(
        h.status & records::status::APPLICATION_MASK,
        records::status::APPLICATION_ERROR
    );
    assert!(
        d.records.is_empty(),
        "a reading was invented: {:?}",
        d.records
    );
    expect_log(&g, "decision=fail_closed_llm_error").await;
    // A write nobody approved is not acknowledged.
    m.expect_silence(
        &write_frame(
            1,
            true,
            &[json!({"quantity": "energy", "unit": "Wh", "value": 0})],
        ),
        SILENCE,
    )
    .await;
    expect_log(&g, "not acknowledged decision=fail_closed_llm_error").await;
    // Link-layer traffic does not need the model.
    assert_eq!(m.snd_nke(1).await, vec![Frame::Ack]);
}

#[tokio::test]
async fn an_answer_that_cannot_be_encoded_is_an_error_status_and_silence_is_silence() {
    let bad = support::static_rule(json!([{
        "type": "mbus_respond_data",
        "records": [{"quantity": "energy", "unit": "furlongs", "value": 1}]
    }]));
    let g = support::start(bad, support::params()).await;
    let mut m = g.master().await;
    let (h, d) = decode(&m.req_ud2(1, true).await[0]);
    assert_eq!(h.status, records::status::APPLICATION_ERROR);
    assert!(d.records.is_empty());
    expect_log(&g, "decision=fail_closed_bad_action").await;

    let quiet = support::start(support::static_rule(json!([])), support::params()).await;
    let mut m = quiet.master().await;
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2,
            a: 1,
        },
        SILENCE,
    )
    .await;
    expect_log(&quiet, "decision=model_silent").await;

    let refuse = support::start(
        support::static_rule(json!([{"type": "mbus_no_response", "reason": "maintenance"}])),
        support::params(),
    )
    .await;
    let mut m = refuse.master().await;
    m.expect_silence(
        &Frame::Short {
            c: c::REQ_UD2,
            a: 1,
        },
        SILENCE,
    )
    .await;
    expect_log(
        &refuse,
        "decision=model_reject: the meter stays silent (maintenance)",
    )
    .await;
}

#[tokio::test]
async fn garbled_telegrams_are_never_answered_and_the_gateway_resynchronises() {
    let g = policy_gateway().await;
    let mut m = g.master().await;
    let mut bad = Frame::Short {
        c: c::SND_NKE,
        a: 1,
    }
    .encode()
    .unwrap();
    bad[3] ^= 0x55;
    m.write(&bad).await;
    assert!(m
        .collect(SILENCE, Duration::from_millis(100))
        .await
        .is_empty());
    // Line noise, then a good telegram in the same segment.
    let mut noisy = vec![0x00, 0xFF, 0x68, 0x05, 0x07, 0x68, 0x42];
    noisy.extend(
        Frame::Short {
            c: c::SND_NKE,
            a: 1,
        }
        .encode()
        .unwrap(),
    );
    m.write(&noisy).await;
    let got = m
        .collect(Duration::from_secs(10), Duration::from_millis(300))
        .await;
    assert_eq!(got, vec![frame::ACK]);
    expect_log(&g, "decision=protocol_error").await;
    // A long frame announcing more than arrives is waited for, not guessed at.
    let full = Frame::Short {
        c: c::REQ_UD2,
        a: 1,
    }
    .encode()
    .unwrap();
    m.write(&full[..2]).await;
    assert!(m
        .collect(Duration::from_millis(500), Duration::from_millis(100))
        .await
        .is_empty());
    m.write(&full[2..]).await;
    let got = m
        .collect(Duration::from_secs(20), Duration::from_millis(300))
        .await;
    assert!(!got.is_empty(), "the split telegram was never answered");
}

#[tokio::test]
async fn more_than_a_telegram_of_bytes_that_are_not_m_bus_closes_the_connection() {
    let g = policy_gateway().await;
    // Exactly one telegram's worth of junk is tolerated (line noise); the gateway still answers.
    let mut m = g.master().await;
    m.write(&vec![0x41; frame::MAX_FRAME_LEN]).await;
    assert_eq!(m.snd_nke(1).await, vec![Frame::Ack]);
    // One byte more is a peer that does not speak M-Bus: hung up, and never shown the model.
    let mut m = g.master().await;
    m.write(&vec![0x41; frame::MAX_FRAME_LEN + 1]).await;
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(10), m.stream.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "the connection stayed open: {closed:?}"
    );
    expect_log(&g, "bytes without a valid telegram").await;
    assert!(g.events("mbus_request_data").await.is_empty());
}

#[tokio::test]
async fn an_idle_master_is_disconnected() {
    let g = support::start(
        support::policy(),
        json!({"meters": support::meters(), "idle_timeout_secs": 1}),
    )
    .await;
    let mut m = g.master().await;
    assert_eq!(m.snd_nke(1).await, vec![Frame::Ack]);
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(10), m.stream.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "the idle connection stayed open: {closed:?}"
    );
    expect_log(&g, "decision=protocol_timeout").await;
}

#[tokio::test]
async fn startup_parameters_are_validated() {
    let state =
        netget::state::app_state::AppState::new_with_options(false, "http://127.0.0.1:1".into());
    for bad in [
        json!({"meters": []}),
        json!({"meters": [{"primary_address": 251, "id": "1"}]}),
        json!({"meters": [{"primary_address": 1, "id": "123456789"}]}),
        json!({"meters": [{"primary_address": 1, "id": "1", "manufacturer": "kam"}]}),
        json!({"meters": [{"primary_address": 1, "id": "1", "medium": "lava"}]}),
        json!({"idle_timeout_secs": 0}),
    ] {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let created = netget::cli::management::ServerForm {
            protocol: "mbus".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            instruction: Some(String::new()),
            startup_params: Some(bad.clone()),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let refused = match created {
            Err(_) => true,
            Ok(id) => {
                // Startup failures land as an error status rather than an Err.
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    let s = state
                        .get_server(id)
                        .await
                        .map(|s| format!("{:?}", s.status));
                    if s.as_deref().is_some_and(|s| s.contains("Error")) {
                        break true;
                    }
                    if tokio::time::Instant::now() > deadline {
                        break false;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        assert!(refused, "{bad} was accepted");
    }
}

/// The model's own path: a mocked LLM starts the gateway and answers a readout for the binary.
#[tokio::test]
async fn the_model_drives_the_gateway_through_the_binary() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via mbus").with_mock(|mock| {
        mock.on_instruction_containing("via mbus")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "mbus",
                "startup_params": {"meters": [
                    {"primary_address": 3, "id": "55555555", "manufacturer": "KAM", "medium": "heat"}
                ]},
                "instruction": "Report 42 kWh"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mbus_request_data")
            .respond_with_actions_from_event(|e| {
                assert_eq!(e["meter"]["id"], "55555555");
                json!([{
                    "type": "mbus_respond_data",
                    "records": [{"quantity": "energy", "unit": "kWh", "value": 42}]
                }])
            })
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let mut m = support::RawMaster::connect(([127, 0, 0, 1], server.port).into()).await;
    let answer = m.req_ud2(3, true).await;
    let (h, d) = decode(&answer[0]);
    assert_eq!(frame::id_hex(&h.address.id), "55555555");
    assert_eq!(d.records[0]["value"], json!(42000));
    assert_eq!(d.records[0]["unit"], "Wh");
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
