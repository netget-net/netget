//! NetGet's H.323 client against third-party H.323 servers:
//!
//! - **GNU Gatekeeper** (H323Plus): NetGet discovers it (GRQ), registers (RRQ) and appears in
//!   GnuGk's own registration table on its status port, is admitted (ARQ) to call an alias
//!   that H323Plus's `simph323` registered, places the call, which simph323 answers, hangs up
//!   (Release Complete, DRQ) and unregisters (URQ) — gone from GnuGk's table. An alias nobody
//!   registered is refused admission (ARJ) and the model hears why.
//! - **Asterisk's chan_ooh323** (ooh323c): NetGet calls it directly; Asterisk answers from its
//!   dialplan, plays a tone for four seconds and hangs up. NetGet counts the RTP that arrives on
//!   the address its fastStart offer named, and reports the release with Asterisk's cause.
//!
//! tshark's h225, q931 and h245 dissectors read every message NetGet sent from a live loopback
//! capture. The peers are required: a missing one fails the test, naming how to install it.
use crate::helpers::h323::{self as support, body, ras, LiveCapture};
use crate::helpers::h323_peers::{self, AsteriskSpec, H323PLUS};
use crate::helpers::real_server::ToolProcess;
use crate::helpers::E2EResult;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const DOWN: &str = "http://127.0.0.1:1";

/// The client's model: call `destination` once registered (or straight away without a
/// gatekeeper), hang up when connected if `hang_up`, and unregister once the call is over.
fn policy(destination: &str, hang_up: bool) -> Option<Vec<serde_json::Value>> {
    support::script(&format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='h323_client_ready' and (e.get('registration') or {{}}).get('result')!='rejected': a=[{{'type':'h323_place_call','destination':'{destination}'}}]
elif t=='h323_call_connected' and {hang}: a=[{{'type':'h323_hangup'}}]
elif t=='h323_call_released' and e.get('released_by')=='local' and e.get('disengage'): a=[{{'type':'h323_unregister'}}]
print(json.dumps({{'actions':a}}))"#,
        hang = if hang_up { "True" } else { "False" }
    ))
}

#[tokio::test]
async fn registers_with_gnugk_is_admitted_and_calls_simph323() -> E2EResult<()> {
    let gk = h323_peers::gnugk().await?;
    let peer_port = support::free_port(false);
    let capture = LiveCapture::start(&[gk.port], &[peer_port]).await;
    let mut c = Command::new("simph323");
    c.args([
        "-g",
        &format!("127.0.0.1:{}", gk.port),
        "-u",
        "bob",
        "-l",
        "-a",
        "-f",
        "-x",
        &peer_port.to_string(),
        "-i",
        "127.0.0.1",
        "-S",
    ]);
    let bob = ToolProcess::spawn(c, "simph323", H323PLUS)?;
    bob.wait_for_line("its registration", Duration::from_secs(30), |l| {
        l.contains("Gatekeeper set:")
    })
    .await
    .map_err(|e| format!("{e}\nGnuGk:\n{}", gk.log()))?;

    let client = support::start_client(
        &gk.addr(),
        policy("h323-ID:bob", true),
        json!({"mode": "gatekeeper", "aliases": ["h323-ID:netget", "1003"]}),
        DOWN,
    )
    .await?;
    let ready = client.wait_for_events("h323_client_ready", 1).await;
    // GnuGk's own table, while NetGet is registered.
    let table = h323_peers::gnugk_status(&gk, "PrintAllRegistrations").await?;
    let connected = client.wait_for_events("h323_call_connected", 1).await;
    let released = client.wait_for_events("h323_call_released", 1).await;
    let unregistered = client.wait_for_events("h323_registration", 1).await;
    let table_after = h323_peers::gnugk_status(&gk, "PrintAllRegistrations").await?;
    let cleared = bob
        .wait_for_line("the call clearing", Duration::from_secs(20), |l| {
            l.contains("has cleared the call")
        })
        .await;
    let frames = capture.finish().await;
    let context = format!(
        "NetGet:\n{}\nsimph323:\n{}\nGnuGk trace:\n{}",
        client.log_text(),
        bob.lines().join("\n"),
        h323_peers::gnugk_trace(&gk)
            .lines()
            .rev()
            .take(80)
            .collect::<Vec<_>>()
            .join("\n")
    );

    assert_eq!(ready.len(), 1, "{context}");
    assert_eq!(ready[0]["gatekeeper"]["result"], "confirmed", "{context}");
    assert_eq!(ready[0]["gatekeeper"]["gatekeeper_id"], "GnuGkTest");
    assert_eq!(ready[0]["registration"]["result"], "confirmed", "{context}");
    assert!(
        table.contains("netget") && table.contains("1003"),
        "GnuGk does not list NetGet:\n{table}"
    );
    assert_eq!(connected.len(), 1, "{context}");
    let call = &connected[0]["call"];
    assert_eq!(connected[0]["admission"]["result"], "confirmed");
    assert_eq!(
        connected[0]["admission"]["destination_address"],
        format!("127.0.0.1:{peer_port}")
    );
    assert_eq!(call["media"]["negotiated_by"], "fastStart", "{call}");
    assert!(
        call["media"]["codec"] == "g711u" || call["media"]["codec"] == "g711a",
        "{call}"
    );
    assert!(call["media"]["remote_rtp"].as_str().is_some(), "{call}");
    assert!(
        bob.lines().iter().any(|l| l.contains("In call with")),
        "{context}"
    );
    assert_eq!(released[0]["released_by"], "local", "{context}");
    assert_eq!(released[0]["disengage"], "DCF");
    cleared.map_err(|e| format!("{e}\n{context}"))?;
    assert_eq!(unregistered[0]["request"], "URQ", "{context}");
    assert_eq!(unregistered[0]["result"], "confirmed");
    assert!(
        !table_after.contains("netget"),
        "GnuGk still lists NetGet after URQ:\n{table_after}"
    );

    support::assert_clean_towards(&frames, &[gk.port, peer_port]);
    let to_gk: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == gk.port)
        .filter_map(|f| f.ras)
        .collect();
    // simph323's own RRQ is in there too; NetGet's GRQ, RRQ, ARQ, DRQ and URQ must be.
    for want in [ras::GRQ, ras::RRQ, ras::ARQ, ras::DRQ, ras::URQ] {
        assert!(to_gk.contains(&want), "towards GnuGk: {to_gk:?}");
    }
    let from_gk = support::ras_from(&frames, gk.port);
    for want in [ras::GCF, ras::RCF, ras::ACF, ras::DCF, ras::UCF] {
        assert!(from_gk.contains(&want), "from GnuGk: {from_gk:?}");
    }
    let to_bob: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == peer_port)
        .filter_map(|f| f.body)
        .collect();
    assert_eq!(to_bob.first(), Some(&body::SETUP), "{frames:#?}");
    assert!(to_bob.contains(&body::RELEASE_COMPLETE), "{to_bob:?}");
    assert!(support::bodies_from(&frames, peer_port).contains(&body::CONNECT));
    Ok(())
}

#[tokio::test]
async fn gnugk_refuses_admission_to_an_alias_nobody_registered() -> E2EResult<()> {
    let gk = h323_peers::gnugk().await?;
    let capture = LiveCapture::start(&[gk.port], &[]).await;
    let client = support::start_client(
        &gk.addr(),
        policy("h323-ID:nobody", true),
        json!({"mode": "gatekeeper", "aliases": ["h323-ID:netget2"], "discover": false}),
        DOWN,
    )
    .await?;
    let failed = client.wait_for_events("h323_call_failed", 1).await;
    let frames = capture.finish().await;
    assert_eq!(failed.len(), 1, "{}\n{}", client.log_text(), gk.log());
    assert_eq!(failed[0]["stage"], "admission");
    assert!(
        failed[0]["reason"].as_str().unwrap().starts_with("ARJ "),
        "{}",
        failed[0]
    );
    support::assert_clean_towards(&frames, &[gk.port]);
    assert!(
        support::ras_from(&frames, gk.port).contains(&ras::ARJ),
        "{frames:#?}"
    );
    Ok(())
}

#[tokio::test]
async fn calls_asterisk_directly_and_receives_its_tone() -> E2EResult<()> {
    let ast = h323_peers::asterisk(AsteriskSpec {
        gatekeeper: "DISABLE",
        h323id: "astcallee",
        e164: "2001",
        faststart: true,
        tunneling: true,
    })
    .await?;
    let capture = LiveCapture::start(&[], &[ast.port]).await;
    let client = support::start_client(
        &ast.addr(),
        policy("2001", false),
        json!({"mode": "endpoint", "aliases": ["1003"]}),
        DOWN,
    )
    .await?;
    let connected = client.wait_for_events("h323_call_connected", 1).await;
    let released = client.wait_for_events("h323_call_released", 1).await;
    let frames = capture.finish().await;
    let context = format!(
        "NetGet:\n{}\nasterisk:\n{}\nooh323c:\n{}",
        client.log_text(),
        ast.log(),
        h323_peers::ooh323_log(&ast)
    );
    assert_eq!(connected.len(), 1, "{context}");
    assert_eq!(
        connected[0]["call"]["media"]["negotiated_by"], "fastStart",
        "{context}"
    );
    assert_eq!(released.len(), 1, "{context}");
    assert_eq!(released[0]["released_by"], "remote", "{context}");
    assert_eq!(released[0]["cause"], 16, "{}", released[0]);
    assert_eq!(released[0]["reached"], "connected");
    let packets = released[0]["call"]["media"]["rtp_packets_received"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        packets > 10,
        "only {packets} RTP packets of Asterisk's tone reached NetGet\n{context}"
    );
    support::assert_clean_towards(&frames, &[ast.port]);
    let to_ast: Vec<u32> = frames
        .iter()
        .filter(|f| f.dst_port == ast.port)
        .filter_map(|f| f.body)
        .collect();
    assert_eq!(to_ast.first(), Some(&body::SETUP), "{frames:#?}");
    let from_ast = support::bodies_from(&frames, ast.port);
    assert!(
        from_ast.contains(&body::CONNECT) && from_ast.contains(&body::RELEASE_COMPLETE),
        "{from_ast:?}"
    );
    Ok(())
}
