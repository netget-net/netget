//! Gemini against a real, independent client: the `ignition` library.
//!
//! `ignition` (MPL-2.0, `pip install ignition-gemini`) is a Python Gemini client: it opens the
//! TLS connection with CPython's `ssl` module (OpenSSL — not rustls, which the server uses),
//! pins the certificate trust-on-first-use into a known-hosts file, sends the request line and
//! parses the response header and body itself. It is run as a subprocess and what it *parsed*
//! is asserted: the response class it chose, the status, the meta, and the decoded body.
//!
//! Every request after the first re-validates the server's certificate against the pin
//! ignition stored, so a server whose certificate changed between connections would fail here
//! with a TOFU rejection.
//!
//! **These tests FAIL, they do not skip, when python3 or ignition is absent.** A skip gate
//! returns `Ok(())` on a runner without the library and the rating built on it rests on
//! nothing; `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The capsule is a Python script handler (`common::CAPSULE_SCRIPT`), so the script-driven
//! cases are deterministic; the last test puts a mocked model behind the same client.
//!
//! The first test also relays its connection through a recorder and runs the pcap oracle over
//! the captured bytes with Wireshark's TLS dissector: there is no gemini dissector, but a
//! malformed record — or a plaintext byte written outside TLS — shows up there.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::real_client --test-threads=100

use super::common::{self, capsule_handler, Chunk, Recorder, HOME_PAGE};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// Requests each URL with ignition and prints one JSON object per response: the class name
/// ignition chose, the status and meta it parsed, and the body decoded as text for a 2x.
const IGNITION_DRIVER: &str = r#"import json, sys
# ignition 1.0.0 reaches cryptography.hazmat.primitives.serialization as an attribute
# without importing it, which works only if something else already imported it.
import cryptography.hazmat.primitives.serialization
import ignition
ignition.set_default_hosts_file(sys.argv[1])
ignition.set_default_timeout(60)
out = []
for url in sys.argv[2:]:
    r = ignition.request(url)
    body = None
    if r.status.startswith('2'):
        body = r.raw_body.decode('utf-8')
    out.append({'url': url, 'class': type(r).__name__, 'status': r.status,
                'meta': str(r.meta), 'body': body})
print(json.dumps(out))
"#;

/// Fail, never skip, when the client is missing — naming it and how to install it.
fn require_ignition() {
    let probe = std::process::Command::new("python3")
        .args(["-c", "import ignition"])
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        other => panic!(
            "the Python Gemini client `ignition` is not importable ({other:?}). These tests \
             drive it against NetGet's Gemini server, and it is the only independent check \
             that our TLS, response header and body are acceptable to a client we did not \
             write. Skipping would leave the Gemini evidence resting on nothing, so this is a \
             failure and not a skip. Install with `python3 -m pip install ignition-gemini`."
        ),
    }
}

/// Run the driver against `urls`; returns ignition's parsed responses.
async fn ignition(urls: &[String]) -> Vec<serde_json::Value> {
    require_ignition();
    let hosts = tempfile::tempdir().expect("tempdir");
    let hosts_file = hosts.path().join("known_hosts");
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-c")
        .arg(IGNITION_DRIVER)
        .arg(&hosts_file)
        .args(urls)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .expect("ignition did not finish within 120s")
        .expect("run python3");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- python3 -c IGNITION_DRIVER {} {} (exit {:?}) ---\n{stdout}{stderr}",
        hosts_file.display(),
        urls.join(" "),
        output.status.code()
    );
    assert!(output.status.success(), "the driver failed: {stderr}");
    let known = std::fs::read_to_string(&hosts_file).unwrap_or_default();
    assert!(
        !known.trim().is_empty(),
        "ignition stored no TOFU pin, so it never validated a certificate"
    );
    serde_json::from_str(stdout.trim()).expect("driver prints JSON")
}

fn field<'a>(r: &'a serde_json::Value, key: &str) -> &'a str {
    r[key].as_str().unwrap_or("")
}

#[tokio::test]
async fn ignition_fetches_a_gemtext_page_and_the_pcap_oracle_reads_clean_tls() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![capsule_handler()], None).await;
    let relay = Recorder::start(port).await;

    let responses = ignition(&[format!("gemini://127.0.0.1:{}/", relay.port)]).await;
    let r = &responses[0];
    assert_eq!(field(r, "class"), "SuccessResponse", "{r}");
    assert_eq!(field(r, "status"), "20", "{r}");
    assert_eq!(
        field(r, "meta"),
        "text/gemini; charset=utf-8; lang=en",
        "{r}"
    );
    assert_eq!(
        field(r, "body"),
        HOME_PAGE,
        "ignition read exactly the gemtext NetGet rendered — the text line starting with => \
         kept as text, the ``` inside the block defused"
    );

    // Everything that crossed the wire, read by Wireshark's own TLS dissector.
    let chunks = relay.finished(30).await;
    let mut oracle = PcapOracle::tcp("gemini");
    for chunk in &chunks {
        oracle = match chunk {
            Chunk::ToServer(b) => oracle.to_server(b),
            Chunk::FromServer(b) => oracle.from_server(b),
        };
    }
    oracle.assert_clean();
}

#[tokio::test]
async fn ignition_parses_input_redirect_slow_down_and_not_found() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![capsule_handler()], None).await;
    let base = format!("gemini://127.0.0.1:{port}");
    let responses = ignition(&[
        format!("{base}/search"),
        format!("{base}/search?hello%20gemini%21"),
        format!("{base}/secret"),
        format!("{base}/old"),
        format!("{base}/slow"),
        format!("{base}/missing"),
    ])
    .await;

    let expect = [
        ("InputResponse", "10", "Search for"),
        ("SuccessResponse", "20", "text/gemini; charset=utf-8"),
        ("InputResponse", "11", "Password"),
        ("RedirectResponse", "31", "/new"),
        ("TempFailureResponse", "44", "30"),
        ("PermFailureResponse", "51", "No such page"),
    ];
    for (r, (class, status, meta)) in responses.iter().zip(expect) {
        assert_eq!(field(r, "class"), class, "{r}");
        assert_eq!(field(r, "status"), status, "{r}");
        assert_eq!(field(r, "meta"), meta, "{r}");
    }
    assert_eq!(
        field(&responses[1], "body"),
        "You searched for: hello gemini!\n",
        "the query reached the handler percent-decoded"
    );
}

/// The model path behind the same real client.
#[tokio::test]
async fn ignition_reads_a_page_the_model_wrote() -> E2EResult<()> {
    require_ignition();
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gemini. A tiny capsule.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via gemini")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gemini",
                    "instruction": "A tiny capsule"
                }]))
                .expect_calls(1)
                .and()
                .on_event("gemini_request")
                .respond_with_actions_from_event(|e| {
                    let path = e["path"].as_str().unwrap_or("/").to_string();
                    serde_json::json!([{
                        "type": "send_gemtext",
                        "lines": [
                            {"type": "heading1", "text": format!("Page {path}")},
                            {"type": "text", "text": "Written by the model."}
                        ]
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let responses = ignition(&[format!("gemini://127.0.0.1:{}/hello", server.port)]).await;
    let r = &responses[0];
    assert_eq!(field(r, "status"), "20", "{r}");
    assert_eq!(
        field(r, "body"),
        "# Page /hello\nWritten by the model.\n",
        "{r}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
