//! The co-processor over raw TCP: ASH framing, CRC, frame and acknowledgement numbers,
//! retransmission and the failed state, the frame-length bound, EZSP version negotiation and
//! the answers to unknown and truncated commands, the one-host cap, the APS payload bound,
//! and the device side — ZDO and attribute reads answered from the description at no model
//! cost, a cluster command answered by the model, and every way the model can fail to answer
//! ending in ZCL FAILURE.
use super::support::*;
use netget::server::zigbee::{ash, ezsp};
use serde_json::json;
use std::time::Duration;

/// Start with a formed network and the lamps described, negotiate, register an endpoint and
/// bring the network up.
async fn up(params: serde_json::Value) -> (Started, Host) {
    let s = start(POLICY, params).await;
    let mut h = Host::connect(s.addr).await;
    assert_eq!(h.startup().await, ezsp::DEFAULT_VERSION);
    h.add_endpoint().await;
    let (_, p) = h.command(ezsp::id::NETWORK_INIT, &[0, 0]).await;
    assert_eq!(status(&p), 0, "networkInit on a formed network");
    let st = h
        .callback(ezsp::id::STACK_STATUS_HANDLER, 5.0)
        .await
        .expect("stackStatusHandler");
    assert_eq!(status(&st), 0x15, "NETWORK_UP");
    (s, h)
}

fn formed_with_devices() -> serde_json::Value {
    json!({"network": formed(15), "network_key": NETWORK_KEY, "devices": devices()})
}

#[tokio::test(flavor = "multi_thread")]
async fn version_negotiation_and_commands_it_does_not_know() {
    let s = start(POLICY, json!({})).await;
    let mut h = Host::connect(s.addr).await;
    assert_eq!(
        h.reset().await,
        ash::reset::SOFTWARE,
        "RSTACK reports a software reset"
    );

    // An extended command before any version: ERROR_VERSION_NOT_SET, in four bytes.
    let (id, p) = h.command(ezsp::id::NETWORK_STATE, &[]).await;
    assert_eq!(id, ezsp::id::INVALID_COMMAND);
    assert_eq!(p, vec![0x30, 0, 0, 0]);

    // bellows asks for v4 in the legacy format; herdsman for 19. Both get 17 back in the
    // format they asked in, and switch.
    for asked in [4u8, 19] {
        h.seq = h.seq.wrapping_add(1);
        h.send_ezsp(&[h.seq, 0x00, 0x00, asked]).await;
        let r = h.response(5.0).await.expect("legacy version");
        assert_eq!(&r[..4], &[h.seq, 0x80, 0x00, 17], "asked for {asked}");
        assert_eq!(r[4], ezsp::STACK_TYPE_MESH);
    }
    // Still not negotiated: the NCP waits for its own version.
    let (id, _) = h.command(ezsp::id::GET_EUI64, &[]).await;
    assert_eq!(id, ezsp::id::INVALID_COMMAND);
    let (id, p) = h.command(ezsp::id::VERSION, &[17]).await;
    assert_eq!((id, p[0], p[1]), (ezsp::id::VERSION, 17, 2));

    // A frame id no EmberZNet release defines: invalidCommand(ERROR_INVALID_FRAME_ID).
    let (id, p) = h.command(0x0999, &[1, 2, 3]).await;
    assert_eq!((id, p), (ezsp::id::INVALID_COMMAND, vec![0x31, 0, 0, 0]));
    // A known command with its parameters cut short: ERROR_INVALID_VALUE.
    let (id, p) = h.command(ezsp::id::GET_CONFIGURATION_VALUE, &[]).await;
    assert_eq!((id, p), (ezsp::id::INVALID_COMMAND, vec![0x36, 0, 0, 0]));
    // A real one answers normally afterwards.
    let (id, p) = h.command(ezsp::id::GET_EUI64, &[]).await;
    assert_eq!(id, ezsp::id::GET_EUI64);
    assert_eq!(
        u64::from_le_bytes(p[..8].try_into().unwrap()),
        0x000D_6F00_0A1B_2C3D
    );
    // No network: networkInit says NOT_JOINED and networkState NO_NETWORK.
    let (_, p) = h.command(ezsp::id::NETWORK_INIT, &[0, 0]).await;
    assert_eq!(status(&p), 0x17);
    let (_, p) = h.command(ezsp::id::NETWORK_STATE, &[]).await;
    assert_eq!(p, vec![0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_with_a_bad_crc_is_nakked_and_not_executed() {
    let s = start(POLICY, json!({})).await;
    let mut h = Host::connect(s.addr).await;
    h.startup().await;
    let frm_before = h.frm;
    // A good getEui64 frame with its CRC's last byte flipped.
    let f = h.ext(ezsp::id::GET_EUI64, &[]);
    let mut wire = ash::data_frame(h.frm, false, h.ack, &f);
    // Unstuff-safe: flip a bit of the byte before the flag, re-escaping if needed.
    let n = wire.len();
    let last = wire[n - 2] ^ 0x01;
    if [0x7E, 0x7D, 0x11, 0x13, 0x18, 0x1A].contains(&last) || wire[n - 3] == ash::ESCAPE {
        wire[n - 2] ^= 0x02;
    } else {
        wire[n - 2] = last;
    }
    h.write(&wire).await;
    match h.next(3.0).await {
        Some(Got::Frame(ash::Frame::Nak { ack_num, .. })) => {
            assert_eq!(ack_num, frm_before, "NAK names the frame still expected")
        }
        other => panic!("expected a NAK for the bad CRC, got {other:?}"),
    }
    assert!(
        h.response(1.0).await.is_none(),
        "a bad-CRC frame must not be executed"
    );
    // The same command, intact, is accepted under the same frame number.
    let (id, _) = h.command(ezsp::id::GET_EUI64, &[]).await;
    assert_eq!(id, ezsp::id::GET_EUI64);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_numbers_ack_numbers_and_retransmission() {
    let s = start(POLICY, json!({})).await;
    let mut h = Host::connect(s.addr).await;
    h.startup().await;
    // Out of sequence: frame 5 when the NCP expects h.frm.
    let f = h.ext(ezsp::id::GET_EUI64, &[]);
    h.write(&ash::data_frame((h.frm + 5) & 7, false, h.ack, &f))
        .await;
    match h.next(3.0).await {
        Some(Got::Frame(ash::Frame::Nak { ack_num, .. })) => assert_eq!(ack_num, h.frm),
        other => panic!("expected a NAK for an out-of-sequence frame, got {other:?}"),
    }
    assert!(h.response(1.0).await.is_none());

    // A retransmission of a frame already accepted is acknowledged again, not re-executed.
    let f = h.ext(ezsp::id::NOP, &[]);
    let accepted = h.frm;
    h.send_ezsp(&f).await;
    assert!(h.response(3.0).await.is_some(), "nop answered");
    h.write(&ash::data_frame(accepted, true, h.ack, &f)).await;
    match h.next(3.0).await {
        Some(Got::Frame(ash::Frame::Ack { ack_num, .. })) => assert_eq!(ack_num, h.frm),
        other => panic!("expected an ACK for the retransmission, got {other:?}"),
    }
    assert!(
        h.response(1.0).await.is_none(),
        "a duplicate must not run twice"
    );

    // Stop acknowledging: the NCP retransmits its response with reTx set and the same
    // frame number, then gives up with an ERROR frame after four timeouts.
    h.auto_ack = false;
    let f = h.ext(ezsp::id::GET_EUI64, &[]);
    h.send_ezsp(&f).await;
    let mut first = None;
    let mut retransmits = 0;
    let started = tokio::time::Instant::now();
    let error = loop {
        match h.next(15.0).await {
            Some(Got::Frame(ash::Frame::Data {
                frm_num,
                re_tx,
                ezsp,
                ..
            })) => match first {
                None => {
                    assert!(!re_tx);
                    first = Some((frm_num, ezsp));
                }
                Some((n, ref e)) => {
                    assert!(re_tx, "a retransmission carries reTx");
                    assert_eq!((frm_num, &ezsp), (n, e), "the same frame again");
                    retransmits += 1;
                }
            },
            Some(Got::Frame(ash::Frame::Ack { .. })) => {}
            Some(Got::Error(code)) => break code,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(error, ash::reset::EXCEEDED_MAXIMUM_ACK_TIMEOUT_COUNT);
    assert_eq!(retransmits, ash::ACK_TIMEOUTS - 1);
    assert!(
        started.elapsed() >= Duration::from_millis(1600),
        "the timer starts at 1.6 s"
    );
    // In the failed state only RST is heard.
    h.auto_ack = true;
    let f = h.ext(ezsp::id::NOP, &[]);
    h.send_ezsp(&f).await;
    assert!(h.response(1.0).await.is_none(), "failed state ignores DATA");
    assert_eq!(h.reset().await, ash::reset::SOFTWARE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_frame_length_bound_and_the_one_host_cap() {
    let s = start(POLICY, json!({})).await;
    // Before any RST, a frame longer than any ASH frame is not a host: closed.
    let mut stranger = Host::connect(s.addr).await;
    stranger.write(&vec![b'A'; ash::MAX_FRAME + 1]).await;
    assert!(
        stranger.closed_within(5).await,
        "an over-long first frame closes the connection"
    );

    let mut h = Host::connect(s.addr).await;
    h.startup().await;
    // A second host while the first is connected: refused.
    let mut second = Host::connect(s.addr).await;
    assert!(second.closed_within(5).await, "the NCP has one UART");

    // After RST, an over-long frame is NAKed and discarded; the link carries on.
    h.write(&vec![0x42; ash::MAX_FRAME + 1]).await;
    h.write(&[ash::FLAG]).await;
    match h.next(3.0).await {
        Some(Got::Frame(ash::Frame::Nak { .. })) => {}
        other => panic!("expected a NAK for an over-long frame, got {other:?}"),
    }
    // A frame of exactly the maximum (220-byte EZSP frame) is accepted.
    let mut big = h.ext(ezsp::id::NOP, &[]);
    big.resize(ash::MAX_DATA, 0);
    h.send_ezsp(&big).await;
    let r = h.response(3.0).await.expect("a maximal frame is executed");
    assert_eq!(u16::from_le_bytes([r[3], r[4]]), ezsp::id::NOP);
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_are_interviewed_from_their_description_at_no_model_cost() {
    let (s, mut h) = up(formed_with_devices()).await;
    let joined = h.permit_and_join(3).await;
    assert!(joined.iter().any(|(n, _)| *n == LAMP_NWK));
    let announce = h.incoming(5.0).await.expect("Device_annce");
    assert_eq!(announce.0, 0x0013);
    // Drain the other announcements.
    while h.incoming(0.5).await.is_some() {}
    let permit_calls = model_calls(&s.state, s.id, "zigbee_permit_joining").await;
    assert_eq!(permit_calls.len(), 1, "one model call for the permit");
    let shown = permit_calls[0].to_string();
    assert!(
        !shown.contains(NETWORK_KEY),
        "the network key never reaches the model"
    );

    // Node Descriptor, Active Endpoints, Simple Descriptor.
    assert_eq!(
        h.unicast(LAMP_NWK, 0, 0x0002, 0, 1, &[7, 0x21, 0x4a]).await,
        0
    );
    let sent = h
        .callback(ezsp::id::MESSAGE_SENT_HANDLER, 5.0)
        .await
        .expect("messageSent");
    assert_eq!(status(&sent), 0, "APS ack");
    let (c, _, sender, p) = h.incoming(5.0).await.expect("Node_Desc_rsp");
    assert_eq!((c, sender, p[0], p[1]), (0x8002, LAMP_NWK, 7, 0));
    assert_eq!(p[4] & 0x07, 1, "a router");
    assert_eq!(
        h.unicast(LAMP_NWK, 0, 0x0005, 0, 2, &[8, 0x21, 0x4a]).await,
        0
    );
    let (c, _, _, p) = h.incoming(5.0).await.expect("Active_EP_rsp");
    assert_eq!((c, &p[..]), (0x8005, &[8, 0, 0x21, 0x4a, 1, 1][..]));
    assert_eq!(
        h.unicast(LAMP_NWK, 0, 0x0004, 0, 3, &[9, 0x21, 0x4a, 1])
            .await,
        0
    );
    let (c, _, _, p) = h.incoming(5.0).await.expect("Simple_Desc_rsp");
    assert_eq!(c, 0x8004);
    assert_eq!(
        &p[5..10],
        &[1, 0x04, 0x01, 0x00, 0x01],
        "endpoint 1, HA, on/off light"
    );
    // Basic attributes: model and manufacturer, and one that is not described.
    assert_eq!(
        h.unicast(
            LAMP_NWK,
            0x0104,
            0x0000,
            1,
            4,
            &zcl_read(10, &[5, 4, 0x4000])
        )
        .await,
        0
    );
    let (c, ep, _, p) = h.incoming(5.0).await.expect("Read Attributes Response");
    assert_eq!((c, ep, p[1], p[2]), (0x0000, 1, 10, 0x01));
    let body = String::from_utf8_lossy(&p);
    assert!(body.contains("Lamp-1") && body.contains("NetGet"));
    assert_eq!(
        &p[p.len() - 3..],
        &[0x00, 0x40, 0x86],
        "UNSUPPORTED_ATTRIBUTE"
    );
    // A cluster the endpoint does not serve.
    assert_eq!(
        h.unicast(LAMP_NWK, 0x0104, 0x0300, 1, 5, &zcl_read(11, &[0]))
            .await,
        0
    );
    let (_, _, _, p) = h.incoming(5.0).await.expect("Default Response");
    assert_eq!(&p[2..], &[0x0B, 0x00, 0xC3], "UNSUPPORTED_CLUSTER");
    // ZDO the device does not implement.
    assert_eq!(
        h.unicast(LAMP_NWK, 0, 0x0038, 0, 6, &[12, 0, 0, 0, 0])
            .await,
        0
    );
    let (c, _, _, p) = h.incoming(5.0).await.expect("NOT_SUPPORTED");
    assert_eq!((c, p[1]), (0x8038, 0x84));
    assert!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .is_empty(),
        "nothing the description covers reaches the model"
    );
    // The coordinator answers ZDO about itself from the endpoints the host registered.
    assert_eq!(h.unicast(0x0000, 0, 0x0005, 0, 7, &[13, 0, 0]).await, 0);
    let (c, _, sender, p) = h.incoming(5.0).await.expect("coordinator Active_EP_rsp");
    assert_eq!((c, sender, &p[..]), (0x8005, 0, &[13, 0, 0, 0, 1, 1][..]));
    // A device that is not there: DELIVERY_FAILED.
    assert_eq!(
        h.unicast(0x7777, 0, 0x0002, 0, 8, &[14, 0x77, 0x77]).await,
        0
    );
    let sent = h
        .callback(ezsp::id::MESSAGE_SENT_HANDLER, 5.0)
        .await
        .unwrap();
    let sent = loop {
        if u16::from_le_bytes([sent[7], sent[8]]) == 0x0002 && status(&sent) != 0 {
            break sent;
        }
        let next = h
            .callback(ezsp::id::MESSAGE_SENT_HANDLER, 5.0)
            .await
            .expect("messageSent");
        if status(&next) != 0 {
            break next;
        }
    };
    assert_eq!(status(&sent), 0x0C02, "ZIGBEE_DELIVERY_FAILED");
    // A message longer than an APS frame carries: refused at the NCP.
    assert_eq!(
        h.unicast(LAMP_NWK, 0x0104, 6, 1, 9, &[0u8; 83]).await,
        0x38,
        "MESSAGE_TOO_LONG"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cluster_command_is_the_models_and_its_answer_is_applied() {
    let (s, mut h) = up(formed_with_devices()).await;
    h.permit_and_join(3).await;
    while h.incoming(0.5).await.is_some() {}
    // On: the model sets on_off and reports it; the Default Response says SUCCESS.
    assert_eq!(
        h.unicast(LAMP_NWK, 0x0104, 0x0006, 1, 20, &zcl_on(42))
            .await,
        0
    );
    let mut default = None;
    let mut report = None;
    for _ in 0..2 {
        let (c, ep, sender, p) = h.incoming(10.0).await.expect("the device's answer");
        assert_eq!((c, ep, sender), (6, 1, LAMP_NWK));
        match p[2] {
            0x0B => default = Some(p),
            0x0A => report = Some(p),
            other => panic!("unexpected ZCL command 0x{other:02x}"),
        }
    }
    let default = default.expect("Default Response");
    assert_eq!(
        (default[1], default[3], default[4]),
        (42, 0x01, 0x00),
        "On succeeded"
    );
    let report = report.expect("Report Attributes");
    assert_eq!(&report[3..], &[0x00, 0x00, 0x10, 0x01], "on_off = true");
    let calls = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(calls.len(), 1, "one model call for the On command");
    assert_eq!(calls[0]["command"], "on");
    assert_eq!(calls[0]["cluster"], "on_off");
    // The stored value answers the next read at no model cost.
    assert_eq!(
        h.unicast(LAMP_NWK, 0x0104, 0x0006, 1, 21, &zcl_read(43, &[0]))
            .await,
        0
    );
    let (_, _, _, p) = h.incoming(5.0).await.expect("read");
    assert_eq!(&p[3..], &[0x00, 0x00, 0x00, 0x10, 0x01]);
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .len(),
        1
    );

    // A button press injected through send_to_peer reaches the host as a client command.
    let conn = s
        .state
        .get_server(s.id)
        .await
        .unwrap()
        .connections
        .keys()
        .next()
        .copied()
        .expect("the host's connection");
    let outcome = s
        .state
        .send_to_peer(
            s.id,
            conn.as_u32(),
            json!({"type": "zigbee_report_attributes", "device": "kitchen-lamp", "endpoint": 1,
                   "attributes": [{"cluster": "level_control", "attribute": 0, "value": 77}]}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(format!("{outcome:?}").contains("Executed"), "{outcome:?}");
    let (c, _, _, p) = h.incoming(5.0).await.expect("injected report");
    assert_eq!((c, p[2]), (0x0008, 0x0A));
    assert_eq!(&p[3..], &[0x00, 0x00, 0x20, 77]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_zcl_request_fails_closed() {
    let mut s = start(POLICY, formed_with_devices()).await;
    let mut h = Host::connect(s.addr).await;
    h.startup().await;
    h.add_endpoint().await;
    let (_, p) = h.command(ezsp::id::NETWORK_INIT, &[0, 0]).await;
    assert_eq!(status(&p), 0);
    h.permit_and_join(3).await;
    while h.incoming(0.5).await.is_some() {}
    // The model says nothing (silent-lamp) and answers invalidly (invalid-lamp): both devices
    // answer FAILURE after the APS acknowledgement.
    for (nwk, tsn, decision) in [
        (SILENT_NWK, 50u8, "decision=model_silent"),
        (INVALID_NWK, 51, "decision=fail_closed_invalid_reply"),
    ] {
        assert_eq!(
            h.unicast(nwk, 0x0104, 0x0006, 1, tsn as u16, &zcl_on(tsn))
                .await,
            0
        );
        let (c, _, sender, p) = h.incoming(10.0).await.expect("the device's failure");
        assert_eq!((c, sender), (6, nwk));
        assert_eq!(
            &p[1..],
            &[tsn, 0x0B, 0x01, 0x01],
            "Default Response FAILURE"
        );
        let line = wait_for_log(&mut s.logs, decision, 10).await;
        assert!(line.contains("cluster=on_off"), "{line}");
    }
    // Both were asked: two model calls, neither answered usefully.
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .len(),
        1,
        "the silent one shows no actions"
    );
    // The invalid answer changed nothing: on_off is still false.
    assert_eq!(
        h.unicast(INVALID_NWK, 0x0104, 0x0006, 1, 60, &zcl_read(60, &[0]))
            .await,
        0
    );
    let (_, _, _, p) = h.incoming(5.0).await.expect("read");
    assert_eq!(&p[3..], &[0x00, 0x00, 0x00, 0x10, 0x00]);
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_parameters_are_bounded() {
    let state =
        netget::state::app_state::AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let many: Vec<_> = (0..33)
        .map(|i| {
            json!({"name": format!("d{i}"), "ieee": format!("00:12:4b:00:00:00:01:{i:02x}"),
                        "endpoints": [{"id": 1, "in_clusters": [6]}]})
        })
        .collect();
    for (params, why) in [
        (json!({"devices": many}), "devices holds at most 32"),
        (json!({"ezsp_version": 7}), "ezsp_version is 8 to 17"),
        (json!({"ezsp_version": 18}), "ezsp_version is 8 to 17"),
        (json!({"network_key": NETWORK_KEY}), "give network too"),
        (
            json!({"network": {"channel": 27, "pan_id": 1, "extended_pan_id": "0011223344556677"}}),
            "network.channel is 11..26",
        ),
    ] {
        let id = netget::cli::management::ServerForm {
            protocol: "zigbee".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            startup_params: Some(params),
            ..Default::default()
        }
        .create(&state, tx.clone())
        .await;
        let failed = match id {
            Err(e) => e.to_string(),
            Ok(id) => {
                let mut msg = String::new();
                for _ in 0..200 {
                    if let Some(srv) = state.get_server(id).await {
                        if let netget::state::server::ServerStatus::Error(e) = &srv.status {
                            msg = e.clone();
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                msg
            }
        };
        assert!(failed.contains(why), "expected {why:?}, got {failed:?}");
    }
}
