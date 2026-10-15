//! `--llm-seed` and `--llm-temperature` reach the backend — and, without them, nothing new does.
//!
//! The real-model eval could not be repeated run to run because NetGet sent Ollama exactly one
//! option, `num_predict`, and nothing that pins the sampler. The two flags fix that, and the
//! half of this that matters most is the negative one: an operator who sets neither must see
//! the same request bodies as before, so the model's own Modelfile keeps deciding. Both halves
//! are asserted here from the **wire**, by the mock Ollama recording every top-level field of
//! every `/api/generate` and `/api/chat` body it receives — not from NetGet's own idea of what
//! it sent.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test llm_sampling_options_test -- --test-threads=100

#![allow(dead_code, unused_imports)]

mod helpers;

use clap::Parser;
use helpers::{E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Start a TCP server through the model, provoke one network event, and return every
/// request body's top-level fields as the mock received them.
async fn run_exchange(extra_args: &[&str]) -> E2EResult<Vec<(String, serde_json::Value)>> {
    let prompt =
        "listen on port {AVAILABLE_PORT} via tcp. When a client sends 'PING', reply with 'PONG'";
    let config = NetGetConfig::new(prompt)
        .with_extra_args(extra_args.iter().map(|s| s.to_string()))
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("tcp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "TCP server that replies PONG to PING"
                }]))
                .expect_calls(1)
                .and()
                .on_event("tcp_data_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_tcp_data",
                    "data": "PONG\n"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(b"PING").await?;
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await??;
    assert!(
        String::from_utf8_lossy(&buf[..n]).contains("PONG"),
        "the exchange must complete, or the recorded bodies describe nothing"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    let fields = server.recorded_request_fields();
    server.stop().await?;
    Ok(fields)
}

#[tokio::test]
async fn sampling_flags_reach_the_wire_and_their_absence_changes_nothing() -> E2EResult<()> {
    // --- Control: no flags. `/api/generate` carries `num_predict` and nothing else in
    // `options`; `/api/chat` carries no `options` object at all. This is the request shape
    // NetGet has always sent, and it must not move.
    let without = run_exchange(&[]).await?;
    assert!(
        without.len() >= 2,
        "the setup call and the network event must both reach the model; recorded {:?}",
        without
    );
    for (endpoint, fields) in &without {
        match endpoint.as_str() {
            "/api/generate" => {
                let options = fields
                    .get("options")
                    .and_then(|o| o.as_object())
                    .unwrap_or_else(|| panic!("/api/generate always sends options: {fields}"));
                let keys: Vec<&String> = options.keys().collect();
                assert_eq!(
                    keys,
                    vec!["num_predict"],
                    "with no sampling flag, options must hold num_predict alone: {fields}"
                );
            }
            "/api/chat" => assert!(
                fields.get("options").is_none(),
                "with no sampling flag, /api/chat must carry no options object: {fields}"
            ),
            other => panic!("unexpected endpoint {other}"),
        }
        assert!(
            fields.get("seed").is_none() && fields.get("temperature").is_none(),
            "sampling fields belong inside options for Ollama, never top-level: {fields}"
        );
    }

    // --- With both flags: every request carries both, inside `options`, beside num_predict.
    let with = run_exchange(&["--llm-seed", "4242", "--llm-temperature", "0"]).await?;
    assert!(with.len() >= 2, "recorded {:?}", with);
    for (endpoint, fields) in &with {
        let options = fields.get("options").unwrap_or_else(|| {
            panic!("{endpoint} must carry options once a flag is set: {fields}")
        });
        assert_eq!(
            options["seed"],
            serde_json::json!(4242),
            "{endpoint}: {fields}"
        );
        assert_eq!(
            options["temperature"],
            serde_json::json!(0.0),
            "{endpoint}: {fields}"
        );
        if endpoint == "/api/generate" {
            assert_eq!(
                options["num_predict"],
                serde_json::json!(netget::llm::ollama_client::DEFAULT_MAX_TOKENS),
                "the sampling options are added to num_predict, not in place of it: {fields}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_temperature_that_is_not_a_finite_non_negative_number_is_refused_at_parse_time() {
    for bad in ["-0.5", "NaN", "inf", "warm"] {
        let parsed = netget::cli::Args::try_parse_from(["netget", "--llm-temperature", bad]);
        assert!(parsed.is_err(), "--llm-temperature {bad} must be refused");
    }
    let ok = netget::cli::Args::try_parse_from([
        "netget",
        "--llm-temperature",
        "0.2",
        "--llm-seed",
        "18446744073709551615",
    ])
    .expect("a valid temperature and a u64 seed parse");
    assert_eq!(ok.llm_temperature, Some(0.2));
    assert_eq!(ok.llm_seed, Some(u64::MAX));
}
