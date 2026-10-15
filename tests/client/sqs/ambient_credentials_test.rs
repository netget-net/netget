//! A SQS client with a custom endpoint and no credentials must not connect.
//!
//! The SDK's default chain (environment, ~/.aws/credentials, IMDS) would otherwise sign
//! every request to that endpoint — a startup parameter the model can set — with the
//! operator's ambient AWS identity, session token included. See `client::aws_support`.
//! Zero LLM calls; the endpoint is a listener that counts what reaches it.


use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::aws_support::{refuse_ambient_credentials, validate_region};
use netget::state::app_state::AppState;
use tokio::sync::mpsc;

#[test]
fn the_policy_allows_aws_itself_or_explicit_credentials_only() {
    assert!(
        refuse_ambient_credentials("X", None, false).is_ok(),
        "AWS proper, ambient"
    );
    assert!(refuse_ambient_credentials("X", None, true).is_ok());
    assert!(refuse_ambient_credentials("X", Some("http://127.0.0.1:8000"), true).is_ok());
    let err = refuse_ambient_credentials("X", Some("http://attacker.example"), false)
        .expect_err("a custom endpoint needs explicit credentials");
    let text = err.to_string();
    assert!(
        text.contains("access_key_id") && text.contains("attacker.example"),
        "{text}"
    );
}

async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn a_custom_endpoint_without_credentials_is_refused_before_anything_is_sent() {
    let (port, accepted) = counting_listener().await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let result = ClientForm {
        protocol: "sqs".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({"region": "us-east-1","queue_url": format!("http://127.0.0.1:{port}/000000000000/q")})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await;
    let err = match result {
        Err(e) => e,
        Ok(id) => {
            // Creation may report the refusal through the client's status instead.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let status = state.get_client(id).await.map(|c| c.status);
            match status {
                Some(netget::state::ClientStatus::Error(e)) => anyhow::anyhow!(e),
                other => panic!("the client must not come up without credentials: {other:?}"),
            }
        }
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("access_key_id") && text.contains("ambient"),
        "the refusal should name the parameter and the reason: {text}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "nothing may reach the endpoint"
    );
}

/// The SDK builds the request host as `<service>.` + region + `.amazonaws.com`, and the
/// region is a parameter the model sets — so a region carrying a `.` or `/` names another
/// host, which then receives requests signed with the ambient identity.
#[test]
fn only_a_region_shaped_label_is_accepted() {
    for good in [
        "us-east-1",
        "eu-west-2",
        "us-gov-west-1",
        "ap-southeast-4",
        "local",
        "a",
    ] {
        assert!(validate_region("X", good).is_ok(), "{good}");
    }
    let too_long = "a".repeat(33);
    for bad in [
        "attacker.example/x",
        "us-east-1.attacker.example",
        "attacker.example#",
        "us-east-1@attacker.example",
        "us-east-1:443",
        "",
        "-us-east-1",
        "us-east-1-",
        "US-EAST-1",
        "us east 1",
        "us-east-1\n",
        too_long.as_str(),
    ] {
        let err = validate_region("X", bad).expect_err(bad);
        assert!(err.to_string().contains("region"), "{err}");
    }
}

#[tokio::test]
async fn a_hostile_region_is_refused_before_anything_is_sent() {
    let (port, accepted) = counting_listener().await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let result = ClientForm {
        protocol: "sqs".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "region": "attacker.example/x",
            "access_key_id": "test",
            "secret_access_key": "test",
            "queue_url": format!("http://127.0.0.1:{port}/000000000000/q")
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await;
    let err = match result {
        Err(e) => e,
        Ok(id) => {
            // Creation may report the refusal through the client's status instead.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let status = state.get_client(id).await.map(|c| c.status);
            match status {
                Some(netget::state::ClientStatus::Error(e)) => anyhow::anyhow!(e),
                other => panic!("the client must not come up with a hostile region: {other:?}"),
            }
        }
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("region") && text.contains("attacker.example/x"),
        "the refusal should name the parameter and the value: {text}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "nothing may reach the endpoint"
    );
}
