//! DICT end to end with a mocked model, over a raw socket.
//!
//! `real_client_test.rs` is the evidence that a real client accepts what this server writes.
//! This file covers what `dict(1)` never sends — a malformed command, an unknown one, a
//! pipelined burst, AUTH, an unsupported OPTION, HELP, STATUS — and asserts the exact bytes,
//! plus the one property a client cannot see: that the commands NetGet answers itself cost no
//! model call. The mock's `expect_calls` counts pin that.
//!
//! LLM budget: 5 calls (open_server, DEFINE, MATCH, SHOW DB, SHOW INFO).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::e2e --test-threads=100


use super::common::Peer;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

#[tokio::test]
async fn a_whole_dict_session_against_a_mocked_model() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via dict. A tiny dictionary.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via dict")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "dict",
                    "instruction": "A tiny dictionary with one database, wn"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dict_define")
                .and_event_data_contains("word", "hello")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dict_definitions",
                        "word": e["word"],
                        "definitions": [{
                            "database": "wn",
                            "database_description": "WordNet (r) 3.0",
                            "text": "hello\n    n : an expression of greeting"
                        }]
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dict_match")
                .and_event_data_contains("strategy", "prefix")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_dict_matches",
                    "matches": [
                        {"database": "wn", "word": "hello"},
                        {"database": "wn", "word": "help"}
                    ]
                }]))
                .expect_calls(1)
                .and()
                // One rule for dict_show that branches on `what`: two rules on the same
                // event cannot be told apart, and the first would answer both.
                .on_event("dict_show")
                .respond_with_actions_from_event(|e| match e["what"].as_str() {
                    Some("databases") => serde_json::json!([{
                        "type": "send_dict_databases",
                        "databases": [{"name": "wn", "description": "WordNet (r) 3.0"}]
                    }]),
                    _ => serde_json::json!([{"type": "send_dict_error", "code": 550}]),
                })
                .expect_calls(2)
                .and()
        });

    let server = start_netget_server(config).await?;
    let mut peer = Peer::connect(server.port).await;

    let banner = peer.line(10).await;
    let re = regex::Regex::new(r"^220 [^<>\r\n]* <mime> <\d+\.\d+\.\d+@netget>\r\n$").unwrap();
    assert!(
        re.is_match(&banner),
        "banner must be `220 text capabilities msg-id`: {banner:?}"
    );

    // Answered by NetGet, no model call.
    peer.send(r#"CLIENT "e2e test""#).await;
    assert_eq!(peer.line(10).await, "250 ok\r\n");

    peer.send(r#"define * "hello""#).await;
    assert_eq!(
        peer.until_status(&["250"], 30).await,
        [
            "150 1 definitions retrieved - definitions follow\r\n",
            "151 \"hello\" wn \"WordNet (r) 3.0\" - text follows\r\n",
            "hello\r\n",
            "    n : an expression of greeting\r\n",
            ".\r\n",
            "250 ok\r\n",
        ]
    );

    peer.send("MATCH wn prefix hel").await;
    assert_eq!(
        peer.until_status(&["250"], 30).await,
        [
            "152 2 matches found - text follows\r\n",
            "wn \"hello\"\r\n",
            "wn \"help\"\r\n",
            ".\r\n",
            "250 ok\r\n",
        ]
    );

    peer.send("SHOW DB").await;
    assert_eq!(
        peer.until_status(&["250"], 30).await,
        [
            "110 1 databases present - text follows\r\n",
            "wn \"WordNet (r) 3.0\"\r\n",
            ".\r\n",
            "250 ok\r\n",
        ]
    );

    peer.send("SHOW INFO nosuch").await;
    assert_eq!(
        peer.line(30).await,
        "550 Invalid database, use \"SHOW DB\" for list of databases\r\n"
    );

    // Everything below is NetGet's own answer; the mock would count a model call.
    peer.send("XYZZY plugh").await;
    assert_eq!(
        peer.line(10).await,
        "500 Syntax error, command not recognized\r\n"
    );
    peer.send("DEFINE onlyone").await;
    assert_eq!(
        peer.line(10).await,
        "501 Syntax error, illegal parameters\r\n"
    );
    peer.send("AUTH user digest").await;
    assert_eq!(peer.line(10).await, "502 Command not implemented\r\n");
    peer.send("OPTION GZIP").await;
    assert_eq!(
        peer.line(10).await,
        "503 Command parameter not implemented\r\n"
    );
    peer.send("STATUS").await;
    assert!(peer.line(10).await.starts_with("210 "));
    peer.send("HELP").await;
    let help = peer.until_status(&["250"], 10).await;
    assert_eq!(help[0], "113 help text follows\r\n");
    assert!(help.iter().any(|l| l.starts_with("DEFINE database word")));
    assert_eq!(help[help.len() - 2], ".\r\n");

    // Pipelined: three commands in one write, answered in order.
    {
        use tokio::io::AsyncWriteExt;
        peer.reader
            .get_mut()
            .write_all(b"STATUS\r\nOPTION MIME\r\nQUIT\r\n")
            .await?;
    }
    assert!(peer.line(10).await.starts_with("210 "));
    assert_eq!(peer.line(10).await, "250 ok\r\n");
    assert_eq!(peer.line(10).await, "221 Closing Connection\r\n");
    assert_eq!(peer.line(10).await, "", "QUIT must close the connection");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
