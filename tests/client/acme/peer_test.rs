//! NetGet's ACME client against Pebble 2.10.1 (independent, unchanged) with pebble-challtestsrv
//! as its DNS: registration, an order for two names, http-01 answered by the client's own
//! responder and validated by Pebble's VA, dns-01 with the TXT record published through
//! challtestsrv, finalization, download, revocation (Pebble refuses a second one), a name on
//! Pebble's blocklist and deactivation. Fails, never skips.
use crate::helpers::acme::*;
use netget::state::{client_handles::ClientSendOutcome, AccessLogOwner};
use serde_json::{json, Value};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn client_works_against_pebble() {
    // Hold the http-01 port while Pebble and challtestsrv probe for theirs: a port that was
    // only probed and released can be handed out again, and challtestsrv's DNS once took it.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http01 = reserved.local_addr().unwrap().port();
    let pebble = start_pebble(http01).await.unwrap();
    drop(reserved);
    let state = state();
    let certs = peer("NETGET_ACME_PEBBLE_CERTS");
    let cid = client_in(
        &state,
        pebble.directory_host(),
        json!({"directory_path": "/dir", "ca_file": format!("{certs}/minica.pem"), "http01_listen": format!("127.0.0.1:{http01}")}),
    )
    .await
    .unwrap();
    let owner = AccessLogOwner::Client(cid.as_u32());
    let connected = logs(&state, owner, "acme_connected", 1).await;
    assert!(connected[0].request["directory"]
        .as_str()
        .unwrap()
        .ends_with("/dir"));
    let send = |a: Value| state.send_to_client(cid, a, Duration::from_secs(60));
    let ok = |o: ClientSendOutcome| assert!(matches!(o, ClientSendOutcome::Sent { .. }), "{o:?}");

    ok(send(
        json!({"type": "acme_register", "contact": ["mailto:ops@example.test"], "agree_tos": true}),
    )
    .await
    .unwrap());
    ok(send(
        json!({"type": "acme_order", "identifiers": ["www.example.test", "dns.example.test"]}),
    )
    .await
    .unwrap());
    let r = logs(&state, owner, "acme_response", 2).await;
    assert_eq!(r[0].request["status"], 201, "{}", r[0].request);
    assert!(r[0].request["account"]
        .as_str()
        .unwrap()
        .contains("/my-account/"));
    let order = &r[1].request;
    assert_eq!(
        (order["status"].as_u64(), order["order_status"].as_str()),
        (Some(201), Some("pending")),
        "{order}"
    );
    let dns = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["identifier"] == "dns.example.test")
        .unwrap();
    let txt = dns["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "dns-01")
        .unwrap();
    assert_eq!(txt["dns_txt_name"], "_acme-challenge.dns.example.test");

    // Publish the dns-01 record the way an operator would, in Pebble's DNS.
    let published = reqwest::Client::new()
        .post(format!("http://{}/set-txt", pebble.dns_management()))
        .json(&json!({"host": "_acme-challenge.dns.example.test.", "value": txt["dns_txt_value"]}))
        .send()
        .await
        .unwrap();
    assert!(published.status().is_success());

    ok(send(json!({"type": "acme_validate", "identifier": "www.example.test", "challenge_type": "http-01"})).await.unwrap());
    ok(send(json!({"type": "acme_validate", "identifier": "dns.example.test", "challenge_type": "dns-01"})).await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("key.pem");
    ok(
        send(json!({"type": "acme_finalize", "key_file": key_file.display().to_string()}))
            .await
            .unwrap(),
    );
    let r = logs(&state, owner, "acme_response", 5).await;
    for v in &r[2..4] {
        assert_eq!(
            (
                v.request["challenge_status"].as_str(),
                v.request["authorization_status"].as_str()
            ),
            (Some("valid"), Some("valid")),
            "Pebble validated: {}",
            v.request
        );
    }
    let fin = &r[4].request;
    assert_eq!(fin["order_status"], "valid", "{fin}");
    let chain = fin["certificate"].as_str().unwrap();
    assert!(
        chain.matches("-----BEGIN CERTIFICATE-----").count() >= 2,
        "{chain}"
    );
    let key = std::fs::read_to_string(&key_file).unwrap();
    assert!(key.contains("PRIVATE KEY"));
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&key_file).unwrap().permissions()
        ) & 0o777,
        0o600
    );

    ok(send(json!({"type": "acme_revoke", "reason": 4}))
        .await
        .unwrap());
    ok(send(json!({"type": "acme_revoke", "reason": 4}))
        .await
        .unwrap());
    ok(
        send(json!({"type": "acme_order", "identifiers": ["blocked-domain.example"]}))
            .await
            .unwrap(),
    );
    ok(send(json!({"type": "acme_deactivate"})).await.unwrap());
    let r = logs(&state, owner, "acme_response", 9).await;
    assert_eq!(r[5].request["status"], 200, "{}", r[5].request);
    assert_eq!(
        r[6].request["problem"]["type"], "urn:ietf:params:acme:error:alreadyRevoked",
        "{}",
        r[6].request
    );
    assert_eq!(
        r[7].request["problem"]["type"], "urn:ietf:params:acme:error:rejectedIdentifier",
        "{}",
        r[7].request
    );
    assert_eq!(
        r[8].request["account_status"], "deactivated",
        "{}",
        r[8].request
    );
    state.remove_client(cid).await;
}
