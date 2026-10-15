//! NetGet's H.323 client, gatekeeper and endpoint against each other, with python policies
//! standing in for the model, and tshark reading every message both ways from a live capture.
//!
//! This is NetGet agreeing with itself, so it is not interoperability evidence — that is
//! `real_peer_test.rs` and `tests/client/h323/real_server_test.rs`. What it pins is the model's
//! side of every path (admit, refuse, ring, forward, a model that is down or silent), the
//! decoded results the client reports, and that every byte on the wire is what tshark's
//! independent H.225.0 / Q.931 / H.245 dissectors call clean.
use super::support::{self, body, ras, LiveCapture};
use crate::helpers::E2EResult;
use serde_json::json;

const DOWN: &str = "http://127.0.0.1:1";

fn gatekeeper_policy(rrq: &str, arq: &str) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='h323_gatekeeper_request': a=[{{'type':'h323_confirm_gatekeeper'}}]
elif t=='h323_registration_request': a={rrq}
elif t=='h323_admission_request': a={arq}
print(json.dumps({{'actions':a}}))"#
    ))
}

fn endpoint_policy(setup: &str) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='h323_setup': a={setup}
print(json.dumps({{'actions':a}}))"#
    ))
}

fn client_policy(destination: &str) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='h323_client_ready' and (e.get('registration') or {{}}).get('result')!='rejected': a=[{{'type':'h323_place_call','destination':'{destination}'}}]
elif t=='h323_call_connected': a=[{{'type':'h323_hangup'}}]
print(json.dumps({{'actions':a}}))"#
    ))
}

#[tokio::test]
async fn a_registered_client_is_admitted_and_its_call_connects_with_fast_start() -> E2EResult<()> {
    let endpoint = support::start_server(
        "H323",
        0,
        endpoint_policy("[{'type':'h323_call_proceeding'},{'type':'h323_alerting'},{'type':'h323_connect','codec':'g711u'}]"),
        json!({}),
        DOWN,
    )
    .await;
    let arq = format!(
        "[{{'type':'h323_confirm_admission','destination':'127.0.0.1:{}'}}]",
        endpoint.port
    );
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy(
            "[{'type':'h323_confirm_registration','time_to_live':120}]",
            &arq,
        ),
        json!({"gatekeeper_id": "TestGK"}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[gk.port], &[endpoint.port]).await;
    let client = support::start_client(
        &gk.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "gatekeeper", "aliases": ["h323-ID:alice", "1001"], "time_to_live": 120}),
        DOWN,
    )
    .await?;

    let released = client.wait_for_events("h323_call_released", 1).await;
    let ready = client.events("h323_client_ready").await;
    let connected = client.events("h323_call_connected").await;
    let frames = capture.finish().await;
    let logs = format!(
        "client:\n{}\ngk:\n{}\nendpoint:\n{}",
        client.log_text(),
        gk.log_text(),
        endpoint.log_text()
    );
    assert_eq!(ready.len(), 1, "{logs}");
    assert_eq!(ready[0]["gatekeeper"]["result"], "confirmed", "{logs}");
    assert_eq!(ready[0]["gatekeeper"]["gatekeeper_id"], "TestGK");
    assert_eq!(ready[0]["registration"]["result"], "confirmed");
    assert_eq!(ready[0]["registration"]["time_to_live"], 120);
    assert_eq!(
        ready[0]["registration"]["aliases"],
        json!(["h323-ID:alice", "dialledDigits:1001"])
    );
    assert_eq!(connected.len(), 1, "{logs}");
    let call = &connected[0]["call"];
    assert_eq!(call["media"]["negotiated_by"], "fastStart", "{logs}");
    assert_eq!(call["media"]["codec"], "g711u");
    assert!(call["media"]["remote_rtp"].as_str().is_some(), "{call}");
    assert_eq!(
        connected[0]["admission"]["destination_address"],
        endpoint.addr().to_string()
    );
    assert_eq!(
        connected[0]["progress"],
        json!(["CallProceeding", "Alerting"])
    );
    assert_eq!(released.len(), 1, "{logs}");
    assert_eq!(released[0]["released_by"], "local");
    assert_eq!(released[0]["disengage"], "DCF");
    assert_eq!(released[0]["reached"], "connected");

    // What each server's model was shown.
    let rrq = gk.events("h323_registration_request").await;
    assert_eq!(
        rrq[0]["aliases"],
        json!(["h323-ID:alice", "dialledDigits:1001"])
    );
    let arq_ev = gk.events("h323_admission_request").await;
    assert_eq!(
        arq_ev[0]["destination_aliases"],
        json!(["dialledDigits:1002"])
    );
    assert_eq!(
        arq_ev[0]["caller_aliases"],
        json!(["h323-ID:alice", "dialledDigits:1001"])
    );
    let setup = endpoint.events("h323_setup").await;
    assert_eq!(setup[0]["calling_number"], "1001");
    assert_eq!(setup[0]["called_number"], "1002");
    assert_eq!(
        setup[0]["destination_aliases"],
        json!(["dialledDigits:1002"])
    );
    assert_eq!(setup[0]["h245_tunnelling"], true);
    assert_eq!(
        setup[0]["fast_start"].as_array().map(|a| a.len()),
        Some(4),
        "{}",
        setup[0]
    );

    // And what tshark read off the wire.
    support::assert_clean(&frames);
    let from_gk = support::ras_from(&frames, gk.port);
    for want in [ras::GCF, ras::RCF, ras::ACF, ras::DCF] {
        assert!(from_gk.contains(&want), "gatekeeper sent {from_gk:?}");
    }
    let to_gk: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == gk.port)
        .filter_map(|f| f.ras)
        .collect();
    assert_eq!(
        to_gk,
        vec![ras::GRQ, ras::RRQ, ras::ARQ, ras::DRQ],
        "{frames:#?}"
    );
    let from_ep = support::bodies_from(&frames, endpoint.port);
    assert_eq!(
        &from_ep[..3],
        &[body::CALL_PROCEEDING, body::ALERTING, body::CONNECT],
        "{frames:#?}"
    );
    let to_ep: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == endpoint.port)
        .filter_map(|f| f.body)
        .collect();
    assert_eq!(to_ep.first(), Some(&body::SETUP));
    assert_eq!(to_ep.last(), Some(&body::RELEASE_COMPLETE));
    // The endpoint opened tunnelled H.245 in its Connect: TerminalCapabilitySet (request 2) and
    // MasterSlaveDetermination (request 1); the client answered both (response 3 and 1).
    let ep_h245 = support::h245_from(&frames, endpoint.port);
    assert!(ep_h245.contains(&("request".into(), 2)), "{ep_h245:?}");
    assert!(ep_h245.contains(&("request".into(), 1)), "{ep_h245:?}");
    let client_h245: Vec<(String, u32)> = frames
        .iter()
        .filter(|f| f.dst_port == endpoint.port)
        .flat_map(|f| f.h245.clone())
        .collect();
    assert!(
        client_h245.contains(&("response".into(), 3)),
        "{client_h245:?}"
    );
    Ok(())
}

#[tokio::test]
async fn refusals_reach_the_client_decoded() -> E2EResult<()> {
    // A gatekeeper that refuses registration.
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy(
            "[{'type':'h323_reject_registration','reason':'securityDenial'}]",
            "[]",
        ),
        json!({}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[gk.port], &[]).await;
    let client = support::start_client(
        &gk.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "gatekeeper", "aliases": ["1001"]}),
        DOWN,
    )
    .await?;
    let ready = client.wait_for_events("h323_client_ready", 1).await;
    let frames = capture.finish().await;
    assert_eq!(
        ready[0]["registration"]["result"],
        "rejected",
        "{}",
        client.log_text()
    );
    assert_eq!(ready[0]["registration"]["reason"], "securityDenial");
    assert!(
        support::ras_from(&frames, gk.port).contains(&ras::RRJ),
        "{frames:#?}"
    );
    support::assert_clean(&frames);
    assert!(
        gk.log_text().contains("decision=model_reject"),
        "{}",
        gk.log_text()
    );

    // A gatekeeper that admits nobody.
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy(
            "[{'type':'h323_confirm_registration'}]",
            "[{'type':'h323_reject_admission','reason':'calledPartyNotRegistered'}]",
        ),
        json!({}),
        DOWN,
    )
    .await;
    let client = support::start_client(
        &gk.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "gatekeeper", "aliases": ["1001"]}),
        DOWN,
    )
    .await?;
    let failed = client.wait_for_events("h323_call_failed", 1).await;
    assert_eq!(failed.len(), 1, "{}", client.log_text());
    assert_eq!(failed[0]["stage"], "admission");
    assert_eq!(failed[0]["reason"], "ARJ calledPartyNotRegistered");

    // An endpoint that is busy, called directly.
    let endpoint = support::start_server(
        "H323",
        0,
        endpoint_policy("[{'type':'h323_alerting'},{'type':'h323_release_complete','cause':17,'reason':'inConf'}]"),
        json!({}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[], &[endpoint.port]).await;
    let client = support::start_client(
        &endpoint.addr().to_string(),
        client_policy("h323-ID:bob"),
        json!({"mode": "endpoint"}),
        DOWN,
    )
    .await?;
    let released = client.wait_for_events("h323_call_released", 1).await;
    let frames = capture.finish().await;
    assert_eq!(
        released[0]["released_by"],
        "remote",
        "{}",
        client.log_text()
    );
    assert_eq!(released[0]["cause"], 17);
    assert_eq!(released[0]["reason"], "inConf");
    assert_eq!(released[0]["reached"], "alerting");
    support::assert_clean(&frames);
    let rc = frames
        .iter()
        .find(|f| f.src_port == endpoint.port && f.body == Some(body::RELEASE_COMPLETE))
        .expect("Release Complete");
    assert_eq!(rc.cause, Some(17), "tshark reads the Q.850 cause");
    assert!(endpoint.log_text().contains("decision=model_reject"));

    // An endpoint that deflects the call.
    let endpoint = support::start_server(
        "H323",
        0,
        endpoint_policy("[{'type':'h323_forward_call','destination':'h323-ID:voicemail'}]"),
        json!({}),
        DOWN,
    )
    .await;
    let client = support::start_client(
        &endpoint.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "endpoint"}),
        DOWN,
    )
    .await?;
    let forwarded = client.wait_for_events("h323_call_forwarded", 1).await;
    assert_eq!(forwarded.len(), 1, "{}", client.log_text());
    assert_eq!(
        forwarded[0]["forward_aliases"],
        json!(["h323-ID:voicemail"])
    );
    Ok(())
}

#[tokio::test]
async fn a_model_that_is_down_or_silent_never_admits() -> E2EResult<()> {
    // No handlers and no model: every decision fails closed.
    let gk = support::start_server("H323-Gatekeeper", 0, None, json!({}), DOWN).await;
    let client = support::start_client(
        &gk.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "gatekeeper", "discover": false}),
        DOWN,
    )
    .await?;
    let ready = client.wait_for_events("h323_client_ready", 1).await;
    // The client's own model is down too, so its event is recorded but not answered.
    assert_eq!(
        ready[0]["registration"]["result"],
        "rejected",
        "{}",
        gk.log_text()
    );
    assert_eq!(ready[0]["registration"]["reason"], "undefinedReason");
    assert!(
        gk.log_text().contains("decision=fail_closed_llm_error"),
        "{}",
        gk.log_text()
    );

    // A model that answers with nothing.
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy("[]", "[]"),
        json!({}),
        DOWN,
    )
    .await;
    let client = support::start_client(
        &gk.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "gatekeeper"}),
        DOWN,
    )
    .await?;
    let ready = client.wait_for_events("h323_client_ready", 1).await;
    assert_eq!(ready[0]["gatekeeper"]["result"], "confirmed");
    assert_eq!(ready[0]["registration"]["result"], "rejected");
    assert!(
        gk.log_text().contains("decision=model_silent"),
        "{}",
        gk.log_text()
    );

    // An endpoint whose model is down releases the call: Q.850 41, temporary failure.
    let endpoint = support::start_server("H323", 0, None, json!({}), DOWN).await;
    let client = support::start_client(
        &endpoint.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "endpoint"}),
        DOWN,
    )
    .await?;
    let released = client.wait_for_events("h323_call_released", 1).await;
    assert_eq!(released[0]["cause"], 41, "{}", endpoint.log_text());
    assert_eq!(released[0]["reached"], "offered");
    assert!(endpoint
        .log_text()
        .contains("decision=fail_closed_llm_error"));

    // An endpoint whose model answers with nothing: cause 31, never connected.
    let endpoint = support::start_server("H323", 0, endpoint_policy("[]"), json!({}), DOWN).await;
    let client = support::start_client(
        &endpoint.addr().to_string(),
        client_policy("1002"),
        json!({"mode": "endpoint"}),
        DOWN,
    )
    .await?;
    let released = client.wait_for_events("h323_call_released", 1).await;
    assert_eq!(released[0]["cause"], 31, "{}", endpoint.log_text());
    assert!(endpoint.log_text().contains("decision=model_silent"));
    Ok(())
}

/// One RAS request from a raw socket, and the answer (or `None` after two seconds).
async fn ras_once(
    sock: &tokio::net::UdpSocket,
    gk: std::net::SocketAddr,
    kind: &str,
    body: serde_json::Value,
) -> Option<(String, serde_json::Value)> {
    use netget::server::h323::h225;
    let bytes = h225::encode_ras(kind, body).unwrap();
    sock.send_to(&bytes, gk).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(h225::decode_ras(&buf[..n]).unwrap())
}

/// The gatekeeper's own bookkeeping, which never reaches the model: retransmissions, keep-alive
/// registration, admission for an endpoint that is not registered, disengage, unregistration.
/// Every answer carries the sequence number of the request it answers.
#[tokio::test]
async fn ras_bookkeeping_is_answered_without_the_model() -> E2EResult<()> {
    use netget::server::h323::h225;
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy(
            "[{'type':'h323_confirm_registration','time_to_live':60}]",
            "[]",
        ),
        json!({}),
        DOWN,
    )
    .await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let me = sock.local_addr()?;
    let rrq = |seq: u64, keep_alive: bool, endpoint: Option<&str>| {
        let mut b = json!({
            "requestSeqNum": seq,
            "protocolIdentifier": h225::PROTOCOL_ID,
            "discoveryComplete": false,
            "callSignalAddress": [h225::transport("127.0.0.1:1720".parse().unwrap())],
            "rasAddress": [h225::transport(me)],
            "terminalType": h225::endpoint_type("terminal"),
            "terminalAlias": [h225::alias("h323-ID:raw").unwrap()],
            "endpointVendor": h225::vendor(),
            "keepAlive": keep_alive,
            "willSupplyUUIEs": false,
            "maintainConnection": false,
            "supportsAssignedGK": false,
        });
        if let Some(e) = endpoint {
            b["endpointIdentifier"] = json!(e);
        }
        b
    };
    let (kind, rcf) = ras_once(
        &sock,
        gk.addr(),
        "registrationRequest",
        rrq(100, false, None),
    )
    .await
    .expect("RCF");
    assert_eq!(kind, "registrationConfirm", "{rcf}");
    assert_eq!(rcf["requestSeqNum"], 100);
    assert_eq!(rcf["timeToLive"], 60);
    let endpoint_id = rcf["endpointIdentifier"].as_str().unwrap().to_string();
    // The same request again (a retransmission): the same answer, and no second model turn.
    let (_, again) = ras_once(
        &sock,
        gk.addr(),
        "registrationRequest",
        rrq(100, false, None),
    )
    .await
    .expect("RCF again");
    assert_eq!(again, rcf);
    // A keep-alive for the registration: refreshed without the model.
    let (kind, ka) = ras_once(
        &sock,
        gk.addr(),
        "registrationRequest",
        rrq(101, true, Some(&endpoint_id)),
    )
    .await
    .expect("keep-alive");
    assert_eq!(kind, "registrationConfirm");
    assert_eq!(ka["requestSeqNum"], 101);
    assert_eq!(ka["endpointIdentifier"], endpoint_id.as_str());
    // A keep-alive for an endpoint nobody registered.
    let (kind, rrj) = ras_once(
        &sock,
        gk.addr(),
        "registrationRequest",
        rrq(102, true, Some("nobody")),
    )
    .await
    .expect("RRJ");
    assert_eq!(kind, "registrationReject");
    assert_eq!(
        rrj["rejectReason"],
        json!({"fullRegistrationRequired": null})
    );
    assert_eq!(gk.events("h323_registration_request").await.len(), 1);
    // Admission for an endpoint that is not registered.
    let arq = json!({
        "requestSeqNum": 103,
        "callType": {"pointToPoint": null},
        "endpointIdentifier": "nobody",
        "destinationInfo": [h225::alias("1002").unwrap()],
        "srcInfo": [h225::alias("h323-ID:raw").unwrap()],
        "bandWidth": 1280,
        "callReferenceValue": 9,
        "conferenceID": "00".repeat(16),
        "activeMC": false,
        "answerCall": false,
    });
    let (kind, arj) = ras_once(&sock, gk.addr(), "admissionRequest", arq)
        .await
        .expect("ARJ");
    assert_eq!(kind, "admissionReject");
    assert_eq!(arj["requestSeqNum"], 103);
    assert_eq!(arj["rejectReason"], json!({"callerNotRegistered": null}));
    assert!(gk.events("h323_admission_request").await.is_empty());
    // Disengage and unregister.
    let drq = json!({
        "requestSeqNum": 104,
        "endpointIdentifier": endpoint_id,
        "conferenceID": "00".repeat(16),
        "callReferenceValue": 9,
        "disengageReason": {"normalDrop": null},
    });
    let (kind, _) = ras_once(&sock, gk.addr(), "disengageRequest", drq)
        .await
        .expect("DCF");
    assert_eq!(kind, "disengageConfirm");
    let urq = json!({
        "requestSeqNum": 105,
        "callSignalAddress": [h225::transport("127.0.0.1:1720".parse().unwrap())],
        "endpointIdentifier": endpoint_id,
    });
    let (kind, _) = ras_once(&sock, gk.addr(), "unregistrationRequest", urq.clone())
        .await
        .expect("UCF");
    assert_eq!(kind, "unregistrationConfirm");
    let mut urq2 = urq;
    urq2["requestSeqNum"] = json!(106);
    let (kind, urj) = ras_once(&sock, gk.addr(), "unregistrationRequest", urq2)
        .await
        .expect("URJ");
    assert_eq!(kind, "unregistrationReject");
    assert_eq!(urj["rejectReason"], json!({"notCurrentlyRegistered": null}));
    // Garbage is not answered at all.
    sock.send_to(b"\xff\xff\xff\xff not RAS", gk.addr()).await?;
    let mut buf = [0u8; 64];
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sock.recv_from(&mut buf)
    )
    .await
    .is_err());
    assert!(
        gk.wait_for_log("decision=protocol_error").await,
        "{}",
        gk.log_text()
    );
    Ok(())
}
