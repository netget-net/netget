//! Zabbix end to end with a mocked model, over raw sockets.
//!
//! `real_client_test.rs` is the evidence that `zabbix_sender` accepts what this server writes.
//! This file pins the exact response, covers what `zabbix_sender` never sends — the large
//! header, another request type, malformed JSON, an empty batch — and asserts that the ones
//! NetGet answers itself cost no model call (`expect_calls`).
//!
//! LLM budget: 3 calls (open_server, two sender-data requests).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::e2e --test-threads=100

use super::common::{exchange, response, sender_data};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::zabbix::wire;

#[tokio::test]
async fn a_zabbix_trapper_against_a_mocked_model() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via zabbix. A trapper.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via zabbix")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "zabbix",
                    "instruction": "A trapper"
                }]))
                .expect_calls(1)
                .and()
                .on_event("zabbix_sender_data")
                // Matches only when the event carries the per-request hint naming its hosts.
                .and_event_data_contains("answer_with", "this request carries")
                .respond_with_actions_from_event(|e| {
                    // Counts derived from what the model was shown, so the reply proves the
                    // items, their values and item_count reached it.
                    let items = e["items"].as_array().cloned().unwrap_or_default();
                    let ok = items
                        .iter()
                        .filter(|i| {
                            i["value"]
                                .as_str()
                                .is_some_and(|v| v.parse::<f64>().is_ok())
                        })
                        .count() as u64;
                    let total = e["item_count"].as_u64().unwrap_or(0);
                    serde_json::json!([{
                        "type": "send_zabbix_result",
                        "processed": ok,
                        "failed": total - ok
                    }])
                })
                .expect_calls(2)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    // Standard header, three values, one of them not a number.
    let packet = wire::encode(&sender_data(&[
        ("web1", "cpu.load", "0.42"),
        ("web1", "cpu.util", "17"),
        ("web1", "status", "degraded"),
    ]));
    let (flags, _, body) = response(&exchange(port, &packet, 30).await);
    assert_eq!(
        flags,
        wire::FLAG_PROTOCOL,
        "responses are uncompressed, standard header"
    );
    assert_eq!(body["response"], "success");
    let info = body["info"].as_str().unwrap();
    let re = regex::Regex::new(r"^processed: 2; failed: 1; total: 3; seconds spent: \d+\.\d{6}$")
        .unwrap();
    assert!(
        re.is_match(info),
        "info must be zabbix_sender's format: {info:?}"
    );

    // The large (8-byte length) header is accepted too.
    let packet = wire::encode_large(&sender_data(&[("db1", "q", "5")]));
    let (_, _, body) = response(&exchange(port, &packet, 30).await);
    assert!(
        body["info"]
            .as_str()
            .unwrap()
            .starts_with("processed: 1; failed: 0; total: 1;"),
        "{body}"
    );

    // Everything below is NetGet's own answer; the mock would count a model call.
    let empty = wire::encode(br#"{"request":"sender data","data":[]}"#);
    let (_, _, body) = response(&exchange(port, &empty, 10).await);
    assert_eq!(body["response"], "success");
    assert!(body["info"]
        .as_str()
        .unwrap()
        .starts_with("processed: 0; failed: 0; total: 0;"));

    let other = wire::encode(br#"{"request":"active checks","host":"web1"}"#);
    let (_, _, body) = response(&exchange(port, &other, 10).await);
    assert_eq!(
        body,
        serde_json::json!({"response": "failed", "info": "unsupported request"})
    );

    let not_json = wire::encode(b"sender data please");
    let (_, _, body) = response(&exchange(port, &not_json, 10).await);
    assert_eq!(body["response"], "failed");
    assert_eq!(body["info"], "cannot parse request as a JSON object");

    let no_data = wire::encode(br#"{"request":"sender data","data":"x"}"#);
    let (_, _, body) = response(&exchange(port, &no_data, 10).await);
    assert_eq!(body["info"], "cannot parse the \"data\" array");

    let items: Vec<(&str, &str, &str)> = vec![("h", "k", "1"); wire::MAX_ITEMS + 1];
    let too_many = wire::encode(&sender_data(&items));
    let (_, _, body) = response(&exchange(port, &too_many, 10).await);
    assert_eq!(body["info"], "too many values in one request");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
