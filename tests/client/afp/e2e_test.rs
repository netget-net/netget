//! NetGet's AFP client against NetGet's own AFP server — a regression suite, not evidence (the
//! evidence is `real_server_test.rs`, against netatalk). It covers what netatalk cannot be
//! made to do unprivileged — the Cleartxt Passwrd login and its refusal — plus refusals,
//! timeouts, an oversized reply, the follow-up depth bound, and a model that never answers.
use super::support::{self, TOUR};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn the_tour_with_a_cleartext_login_and_the_models_actions_on_the_wire() {
    let s = support::server(json!({
        "username": "alice", "password": "pw", "guest_access": false, "volumes": ["Share"]
    }))
    .await;
    let c = support::connect(
        &s.addr(),
        support::script(TOUR),
        json!({"username": "alice", "password": "pw"}),
    )
    .await;
    let connected = c.wait_for_events("afp_connected", 1, 30).await;
    assert_eq!(connected[0]["user"], "alice");
    assert_eq!(connected[0]["uam"], "Cleartxt Passwrd");
    assert_eq!(connected[0]["version"], "AFP3.4");
    assert_eq!(connected[0]["server"]["machine_type"], "NetGet");
    assert!(!c.log_text().contains("\"pw\""));

    let dirs = c.wait_for_events("afp_directory", 2, 60).await;
    assert_eq!(dirs.len(), 2, "{}\n{}", c.log_text(), s.log_text());
    let files = c.wait_for_events("afp_file", 2, 30).await;
    let bin = files.iter().find(|f| f["path"] == "bin.dat").unwrap();
    assert_eq!(
        (bin["content"].clone(), bin["encoding"].clone()),
        (json!("000102ff"), json!("hex"))
    );
    // Every action the model gave reached the server as the operation it names.
    let writes = s.events("afp_write_file").await;
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0]["data"], "written by NetGet\n");
    assert_eq!(writes[0]["path"], "written.txt");
    let creates: Vec<_> = s
        .events("afp_create")
        .await
        .iter()
        .map(|e| {
            (
                e["path"].as_str().unwrap().to_string(),
                e["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        creates,
        [
            ("written.txt".to_string(), "file".to_string()),
            ("made".to_string(), "directory".to_string())
        ]
    );
    assert_eq!(s.events("afp_delete").await[0]["path"], "todelete.txt");
    let done = c.wait_for_events("afp_done", 3, 30).await;
    assert_eq!(done[0]["bytes_written"], 18);

    // A refusal the server's model made comes back as afp_error with its code.
    c.send(
        json!({"type": "afp_write_file", "volume": "Share", "path": "deny.txt", "content": "x"}),
    )
    .await;
    let errors = c.wait_for_events("afp_error", 1, 30).await;
    assert_eq!(errors[0]["code"], -5000);
    assert_eq!(errors[0]["operation"], "afp_write_file");
}

#[tokio::test]
async fn a_refused_login_fails_the_connect() {
    let s = support::server(json!({"username": "alice", "password": "pw", "guest_access": false}))
        .await;
    let e = support::try_connect(
        &s.addr(),
        None,
        json!({"username": "alice", "password": "nope"}),
    )
    .await
    .err()
    .expect("a wrong password must not connect");
    assert!(e.contains("kFPUserNotAuth"), "{e}");
    let e = support::try_connect(&s.addr(), None, json!({}))
        .await
        .err()
        .expect("a guest must not connect");
    assert!(e.contains("no guest login"), "{e}");
    let e = support::try_connect(&s.addr(), None, json!({"username": "alice"}))
        .await
        .err()
        .expect("a user without a password is refused before connecting");
    assert!(e.contains("together"), "{e}");
}

#[tokio::test]
async fn a_chain_of_follow_ups_stops_at_the_depth_bound() {
    let s = support::server(json!({"volumes": ["Share"]})).await;
    let c = support::connect(
        &s.addr(),
        support::script(
            "import json\nprint(json.dumps({'actions':[{'type':'afp_list_volumes'}]}))",
        ),
        json!({}),
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_secs(30), async {
            while !c.log_text().contains("chain of follow-ups") {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok(),
        "{}",
        c.log_text()
    );
    // Events are recorded as they reach the model: depths 1 to MAX - 1. The one at MAX is
    // the one the chain stopped at.
    let n = c.events("afp_volumes").await.len() as u32;
    assert_eq!(n, netget::client::afp::MAX_FOLLOWUP_DEPTH - 1);
}

#[tokio::test]
async fn with_no_model_the_client_does_nothing() {
    let s = support::server(json!({"volumes": ["Share"]})).await;
    let c = support::connect(&s.addr(), None, json!({})).await;
    c.wait_for_events("afp_connected", 1, 30).await;
    // The model call fails; nothing is listed, read or written on its behalf. There is no
    // event to wait for when nothing happens, so give it a moment.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(s.events("afp_list_directory").await.is_empty());
    assert!(c.events("afp_volumes").await.is_empty());
}

/// A server that accepts and never answers: the connect fails at the response timeout.
#[tokio::test]
async fn a_silent_server_times_out_and_an_oversized_reply_is_refused() {
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let started = std::time::Instant::now();
    let e = support::try_connect(&addr.to_string(), None, json!({"response_timeout_ms": 300}))
        .await
        .err()
        .expect("nobody answered");
    assert!(e.contains("did not answer"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(10));

    // A server whose reply declares more than a DSI message may carry.
    let liar = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = liar.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = liar.accept().await {
            let mut h = [0u8; 16];
            if s.read_exact(&mut h).await.is_ok() {
                let mut reply = netget::server::afp::dsi::Header::parse(&h);
                reply.flags = 1;
                reply.length = (netget::server::afp::dsi::MAX_PAYLOAD_LEN + 1) as u32;
                let _ = s.write_all(&reply.encode()).await;
            }
            tokio::time::sleep(Duration::from_millis(5000)).await;
        }
    });
    let e = support::try_connect(&addr.to_string(), None, json!({}))
        .await
        .err()
        .expect("an oversized reply is refused");
    assert!(e.contains("declares"), "{e}");
}
