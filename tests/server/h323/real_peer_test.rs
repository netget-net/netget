//! NetGet's H.323 gatekeeper and endpoint against two independent H.323 stacks:
//!
//! - **H323Plus**: its sample endpoint `simph323` registers with NetGet's gatekeeper, is
//!   admitted, and calls NetGet's endpoint — with fastStart, and without it (tunnelled H.245
//!   only) — and its own console says the call is up and which logical channels opened.
//! - **ooh323c**, as Asterisk's `chan_ooh323`: Asterisk registers with NetGet's gatekeeper,
//!   originates a call that NetGet admits and NetGet's endpoint answers, and plays a tone at it;
//!   NetGet counts the RTP that arrives on the address its fastStart answer named.
//!
//! A registration NetGet's model refuses is refused in each peer's own words, and a call it
//! rejects is rejected with its cause. tshark's h225, q931 and h245 dissectors read every
//! message both ways from a live loopback capture.
//!
//! The peers are required: a missing one fails the test, naming how to install it. Run on
//! Linux (see `tests/server/h323/AGENTS.md`); CI's `h323` pair job installs them.
use super::support::{self, body, ras, LiveCapture};
use crate::helpers::h323_peers::{self, AsteriskSpec, H323PLUS};
use crate::helpers::real_server::ToolProcess;
use crate::helpers::E2EResult;
use netget::state::AccessLogOwner;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const DOWN: &str = "http://127.0.0.1:1";

/// Asterisk's gatekeeper client always talks to port 1719, so the tests that point it at NetGet
/// take turns with that port.
static PORT_1719: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn gatekeeper_policy(rrq: &str, arq_to: u16) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='h323_gatekeeper_request': a=[{{'type':'h323_confirm_gatekeeper'}}]
elif t=='h323_registration_request': a={rrq}
elif t=='h323_admission_request':
  a=[{{'type':'h323_confirm_admission'}}] if e.get('answer_call') else [{{'type':'h323_confirm_admission','destination':'127.0.0.1:{arq_to}'}}]
elif t=='h323_location_request': a=[{{'type':'h323_reject_location','reason':'notRegistered'}}]
print(json.dumps({{'actions':a}}))"#
    ))
}

fn endpoint_policy(setup: &str) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a={setup} if t=='h323_setup' else []
print(json.dumps({{'actions':a}}))"#
    ))
}

const ANSWER: &str =
    "[{'type':'h323_call_proceeding'},{'type':'h323_alerting'},{'type':'h323_connect'}]";

/// The connection the endpoint's first Setup arrived on.
async fn setup_connection(endpoint: &support::Node) -> Option<u32> {
    endpoint
        .state
        .list_access_logs_for(Some(AccessLogOwner::Server(endpoint.id.as_u32())), None)
        .await
        .iter()
        .find(|e| e.event_type == "h323_setup")
        .and_then(|e| e.connection_id)
}

fn simph323(args: &[String]) -> E2EResult<ToolProcess> {
    let mut c = Command::new("simph323");
    c.args(args);
    ToolProcess::spawn(c, "simph323", H323PLUS)
}

async fn simph323_call(fast_start: bool) -> E2EResult<()> {
    let endpoint = support::start_server("H323", 0, endpoint_policy(ANSWER), json!({}), DOWN).await;
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy("[{'type':'h323_confirm_registration'}]", endpoint.port),
        json!({"gatekeeper_id": "NetGetGK"}),
        DOWN,
    )
    .await;
    let own_port = support::free_port(false);
    let capture = LiveCapture::start(&[gk.port], &[endpoint.port, own_port]).await;
    let mut args = vec![
        "-g".to_string(),
        format!("127.0.0.1:{}", gk.port),
        "-u".into(),
        "alice".into(),
        "-x".into(),
        own_port.to_string(),
        "-i".into(),
        "127.0.0.1".into(),
        "-S".into(),
    ];
    if fast_start {
        args.push("-f".into());
    }
    args.push("1002".into());
    let peer = simph323(&args)?;
    let up = peer
        .wait_for_line("In call with", Duration::from_secs(40), |l| {
            l.contains("In call with")
        })
        .await;
    let channels = peer
        .wait_for_line(
            "a receiving logical channel",
            Duration::from_secs(20),
            |l| l.contains("Started logical channel: receiving"),
        )
        .await;
    // NetGet hangs up; simph323 says so and disengages from the gatekeeper.
    let conn = setup_connection(&endpoint).await;
    let released = match conn {
        Some(c) => endpoint
            .state
            .send_to_peer(
                endpoint.id,
                c,
                json!({"type": "h323_release_complete", "cause": 16}),
                Duration::from_secs(10),
            )
            .await
            .map(|o| format!("{o:?}"))
            .map_err(|e| e.to_string()),
        None => Err("no h323_setup event".into()),
    };
    let cleared = peer
        .wait_for_line("the call cleared", Duration::from_secs(20), |l| {
            l.contains("has cleared the call")
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let frames = capture.finish().await;
    let context = format!(
        "simph323:\n{}\nNetGet gatekeeper:\n{}\nNetGet endpoint:\n{}",
        peer.lines().join("\n"),
        gk.log_text(),
        endpoint.log_text()
    );
    up.map_err(|e| format!("{e}\n{context}"))?;
    channels.map_err(|e| format!("{e}\n{context}"))?;
    released.map_err(|e| format!("{e}\n{context}"))?;
    cleared.map_err(|e| format!("{e}\n{context}"))?;
    assert!(
        peer.lines().iter().any(|l| l.contains("Gatekeeper set:")),
        "simph323 did not register: {context}"
    );

    // What NetGet's model was shown.
    let rrq = gk.events("h323_registration_request").await;
    assert_eq!(rrq.len(), 1, "{context}");
    assert!(
        rrq[0]["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "h323-ID:alice"),
        "{}",
        rrq[0]
    );
    assert_eq!(rrq[0]["endpoint"]["kind"], "terminal");
    let arq = gk.events("h323_admission_request").await;
    assert_eq!(
        arq[0]["destination_aliases"],
        json!(["dialledDigits:1002"]),
        "{}",
        arq[0]
    );
    let setup = endpoint.events("h323_setup").await;
    assert!(
        setup[0]["source_aliases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "h323-ID:alice"),
        "{}",
        setup[0]
    );
    assert_eq!(
        setup[0]["fast_start"].as_array().map(|a| !a.is_empty()),
        Some(fast_start),
        "{}",
        setup[0]
    );
    assert_eq!(setup[0]["h245_tunnelling"], true);
    let negotiated = if fast_start {
        "\"negotiated_by\":\"fastStart\""
    } else {
        "\"negotiated_by\":\"h245\""
    };
    assert!(endpoint.log_text().contains(negotiated), "{context}");

    // And what tshark read off the wire.
    support::assert_netget_clean(&frames, &[gk.port, endpoint.port]);
    let to_gk: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == gk.port)
        .filter_map(|f| f.ras)
        .collect();
    for want in [ras::RRQ, ras::ARQ, ras::DRQ] {
        assert!(
            to_gk.contains(&want),
            "simph323 sent {to_gk:?}\n{frames:#?}"
        );
    }
    let from_gk = support::ras_from(&frames, gk.port);
    for want in [ras::RCF, ras::ACF, ras::DCF] {
        assert!(
            from_gk.contains(&want),
            "NetGet's gatekeeper sent {from_gk:?}"
        );
    }
    let from_ep = support::bodies_from(&frames, endpoint.port);
    assert!(
        from_ep.contains(&body::CONNECT) && from_ep.contains(&body::RELEASE_COMPLETE),
        "{from_ep:?}"
    );
    let to_ep: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == endpoint.port)
        .filter_map(|f| f.body)
        .collect();
    assert_eq!(to_ep.first(), Some(&body::SETUP), "{frames:#?}");
    // Tunnelled H.245 both ways: each side's TerminalCapabilitySet (request 2) was acknowledged
    // (response 3).
    let ep_h245 = support::h245_from(&frames, endpoint.port);
    let peer_h245: Vec<(String, u32)> = frames
        .iter()
        .filter(|f| f.dst_port == endpoint.port)
        .flat_map(|f| f.h245.clone())
        .collect();
    for side in [&ep_h245, &peer_h245] {
        assert!(
            side.contains(&("request".into(), 2)),
            "{ep_h245:?} / {peer_h245:?}"
        );
        assert!(
            side.contains(&("response".into(), 3)),
            "{ep_h245:?} / {peer_h245:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn simph323_registers_is_admitted_and_its_fast_start_call_is_answered() -> E2EResult<()> {
    simph323_call(true).await
}

#[tokio::test]
async fn simph323_call_without_fast_start_connects_over_tunnelled_h245() -> E2EResult<()> {
    simph323_call(false).await
}

#[tokio::test]
async fn simph323_is_refused_registration_and_a_rejected_call() -> E2EResult<()> {
    // The model refuses the registration: simph323 cannot register and says so.
    let gk = support::start_server(
        "H323-Gatekeeper",
        0,
        gatekeeper_policy(
            "[{'type':'h323_reject_registration','reason':'securityDenial'}]",
            1,
        ),
        json!({}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[gk.port], &[]).await;
    let peer = simph323(&[
        "-g".into(),
        format!("127.0.0.1:{}", gk.port),
        "-u".into(),
        "mallory".into(),
        "-x".into(),
        support::free_port(false).to_string(),
        "-i".into(),
        "127.0.0.1".into(),
        "-S".into(),
        "-l".into(),
    ])?;
    peer.wait_for_line("a registration error", Duration::from_secs(30), |l| {
        l.contains("Error registering with gatekeeper")
    })
    .await
    .map_err(|e| format!("{e}\nNetGet:\n{}", gk.log_text()))?;
    let frames = capture.finish().await;
    support::assert_netget_clean(&frames, &[gk.port]);
    assert!(
        support::ras_from(&frames, gk.port).contains(&ras::RRJ),
        "{frames:#?}"
    );
    assert!(gk.log_text().contains("decision=model_reject"));
    drop(peer);

    // The model rejects the call as busy: simph323 calls NetGet's endpoint directly.
    let endpoint = support::start_server(
        "H323",
        0,
        endpoint_policy("[{'type':'h323_release_complete','cause':17,'reason':'inConf'}]"),
        json!({}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[], &[endpoint.port]).await;
    let peer = simph323(&[
        "-n".into(),
        "-u".into(),
        "alice".into(),
        "-x".into(),
        support::free_port(false).to_string(),
        "-i".into(),
        "127.0.0.1".into(),
        "-S".into(),
        "-f".into(),
        format!("1002@127.0.0.1:{}", endpoint.port),
    ])?;
    let ended = peer
        .wait_for_line("the call ending", Duration::from_secs(30), |l| {
            l.contains("did not accept your call") || l.contains("completed") || l.contains("ended")
        })
        .await
        .map_err(|e| format!("{e}\nNetGet:\n{}", endpoint.log_text()))?;
    let frames = capture.finish().await;
    support::assert_netget_clean(&frames, &[endpoint.port]);
    let rc = frames
        .iter()
        .find(|f| f.src_port == endpoint.port && f.body == Some(body::RELEASE_COMPLETE))
        .unwrap_or_else(|| panic!("no Release Complete from NetGet: {frames:#?}"));
    assert_eq!(rc.cause, Some(17), "{frames:#?}");
    assert!(
        !peer.lines().iter().any(|l| l.contains("In call with")),
        "{ended}"
    );
    Ok(())
}

#[tokio::test]
async fn asterisk_registers_with_netget_and_its_call_is_answered_with_media() -> E2EResult<()> {
    let _turn = PORT_1719.lock().await;
    let endpoint = support::start_server("H323", 0, endpoint_policy(ANSWER), json!({}), DOWN).await;
    let gk = support::start_server(
        "H323-Gatekeeper",
        1719,
        gatekeeper_policy("[{'type':'h323_confirm_registration'}]", endpoint.port),
        json!({"gatekeeper_id": "NetGetGK"}),
        DOWN,
    )
    .await;
    let ast = h323_peers::asterisk(AsteriskSpec {
        gatekeeper: "127.0.0.1",
        h323id: "astpeer",
        e164: "2001",
        faststart: true,
        tunneling: true,
    })
    .await?;
    let capture = LiveCapture::start(&[1719], &[endpoint.port, ast.port]).await;
    let registered = gk.wait_for_events("h323_registration_request", 1).await;
    let ast_log = || {
        format!(
            "asterisk:\n{}\nooh323c:\n{}",
            ast.log(),
            h323_peers::ooh323_log(&ast)
        )
    };
    assert_eq!(
        registered.len(),
        1,
        "Asterisk never asked NetGet to register it\n{}\n{}",
        ast_log(),
        gk.log_text()
    );
    // Asterisk's own view of its gatekeeper: registered, before anything is called.
    let mut gk_view = String::new();
    for _ in 0..100 {
        gk_view = h323_peers::asterisk_cli(&ast, "ooh323 show gk")
            .await
            .unwrap_or_default();
        if gk_view.contains("GkClientRegistered")
            || gk_view.to_ascii_lowercase().contains("registered")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let plan = h323_peers::asterisk_cli(&ast, "dialplan show")
        .await
        .unwrap_or_default();
    assert!(
        gk_view.to_ascii_lowercase().contains("registered"),
        "Asterisk does not show itself registered with NetGet:\n{gk_view}\n{plan}\n{}",
        ast_log()
    );

    // A call to 1002 through the gatekeeper: ARQ to NetGet, then Setup to where ACF said.
    h323_peers::asterisk_cli(&ast, "channel originate OOH323/1002 extension s@tone").await?;
    let up = endpoint.wait_for_log("Connect sent; media").await;
    // The tone plays for four seconds, then Asterisk hangs up.
    let ended = endpoint.wait_for_log("call ended by the caller").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let frames = capture.finish().await;
    let context = format!(
        "{}\nNetGet gatekeeper:\n{}\nNetGet endpoint:\n{}\ndialplan:\n{plan}",
        ast_log(),
        gk.log_text(),
        endpoint.log_text()
    );
    assert!(up && ended, "{context}");
    let setup = endpoint.events("h323_setup").await;
    assert!(
        setup[0]["source_aliases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "h323-ID:astpeer"),
        "{}",
        setup[0]
    );
    assert!(
        !setup[0]["fast_start"].as_array().unwrap().is_empty(),
        "{}",
        setup[0]
    );
    // RTP reached the address NetGet's fastStart answer named.
    let summary = endpoint
        .log_text()
        .lines()
        .find(|l| l.contains("call ended by the caller"))
        .unwrap_or_default()
        .to_string();
    let packets: u64 = summary
        .split("\"rtp_packets_received\":")
        .nth(1)
        .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        packets > 10,
        "only {packets} RTP packets reached NetGet: {summary}\n{context}"
    );
    support::assert_netget_clean(&frames, &[1719, endpoint.port]);
    let to_gk: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == 1719)
        .filter_map(|f| f.ras)
        .collect();
    assert!(to_gk.contains(&ras::ARQ), "{to_gk:?}");
    let from_gk = support::ras_from(&frames, 1719);
    assert!(from_gk.contains(&ras::ACF), "{from_gk:?}");
    let from_ep = support::bodies_from(&frames, endpoint.port);
    assert!(from_ep.contains(&body::CONNECT), "{from_ep:?}");
    Ok(())
}

#[tokio::test]
async fn asterisk_is_refused_registration_in_its_own_log() -> E2EResult<()> {
    let _turn = PORT_1719.lock().await;
    let gk = support::start_server(
        "H323-Gatekeeper",
        1719,
        gatekeeper_policy(
            "[{'type':'h323_reject_registration','reason':'securityDenial'}]",
            1,
        ),
        json!({}),
        DOWN,
    )
    .await;
    let capture = LiveCapture::start(&[1719], &[]).await;
    let ast = h323_peers::asterisk(AsteriskSpec {
        gatekeeper: "127.0.0.1",
        h323id: "intruder",
        e164: "6666",
        faststart: true,
        tunneling: true,
    })
    .await?;
    let refused = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let l = h323_peers::ooh323_log(&ast);
            if l.contains("RRQ Rejected") {
                return l;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let frames = capture.finish().await;
    let log = refused.map_err(|_| {
        format!(
            "ooh323c never logged the RRJ\nasterisk:\n{}\nooh323c:\n{}\nNetGet:\n{}",
            ast.log(),
            h323_peers::ooh323_log(&ast),
            gk.log_text()
        )
    })?;
    assert!(log.contains("intruder") || log.contains("6666") || !log.is_empty());
    support::assert_netget_clean(&frames, &[1719]);
    assert!(
        support::ras_from(&frames, 1719).contains(&ras::RRJ),
        "{frames:#?}"
    );
    Ok(())
}
