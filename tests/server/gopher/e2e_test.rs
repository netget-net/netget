//! End-to-end Gopher (RFC 1436) tests.
//!
//! Two of the five tests drive the real `curl(1)` binary, and they are what the `Beta` rating
//! rests on: a raw socket only proves bytes arrived, whereas curl fetching the URL and exiting
//! 0 proves the framing, the CRLF endings and — critically — the **close** are acceptable to an
//! independent implementation. curl reads a Gopher reply until EOF, so a server that does not
//! hang up leaves it hanging until `--max-time` and exiting 28.
//!
//! Both curl tests **hard-fail** when curl is absent or lacks gopher support. They do not skip:
//! a skip-when-missing gate is a silent pass on any runner without the binary, which would
//! leave this protocol's maturity rating resting on nothing.
//!
//! Four facts about `curl`'s gopher support, measured rather than assumed, that shape these
//! tests:
//!
//! - **curl strips the item-type character from the URL path.** `gopher://h/1/menu` and
//!   `gopher://h/0/menu` both put the selector `/menu` on the wire; `gopher://h/` sends an
//!   empty selector and `gopher://h/1/` sends `/`. The type in a Gopher URL describes the
//!   reply the caller expects — the server never sees it — so curl cannot be used to test
//!   anything type-dependent on the request side.
//! - **curl does no Gopher-level parsing at all.** The reply reaches stdout verbatim: the
//!   terminating `.` line is still there, and doubled leading dots are *not* undone. So the
//!   escaping and the terminator are asserted here as literal bytes in curl's output.
//! - **A type-3 error item is still exit 0.** curl has no concept of a Gopher error, so an
//!   error reply must be asserted on stdout, never on the exit status.
//! - **`%09` in the URL becomes a real tab**, which is how a type-7 search request is spelled.
mod gopher_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Send one selector line and read to EOF, which is what a Gopher client does.
    ///
    /// Reading to EOF rather than to a fixed byte count is deliberate: it is also the
    /// assertion that the server closes after one reply. If it ever stopped closing, this
    /// helper would block and the test would fail on its timeout rather than passing on a
    /// partial read.
    async fn gopher_request(addr: &str, request_line: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to Gopher server");

        stream
            .write_all(format!("{}\r\n", request_line).as_bytes())
            .await
            .expect("Failed to send selector");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut response))
            .await
            .expect(
                "Timed out reading the Gopher reply. RFC 1436 has the server close after one \
             reply, and this read waits for that EOF — a timeout here means it did not close.",
            )
            .expect("Failed to read response");

        String::from_utf8_lossy(&response).to_string()
    }

    /// Fail — never skip — unless a curl with gopher support is on PATH.
    ///
    /// The whole point of the two curl tests is that an independent client accepts what this
    /// server writes. A machine without curl must say so: a vacuous green is exactly how a
    /// maturity claim outlives the thing that justified it.
    async fn require_curl_with_gopher() -> E2EResult<()> {
        let version = tokio::process::Command::new("curl")
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| {
                format!(
                    "curl not available ({e}): these tests drive the real curl binary against \
                     NetGet's Gopher server, and skipping would leave Gopher's maturity rating \
                     resting on nothing"
                )
            })?;

        if !version.status.success() {
            return Err(format!(
                "`curl --version` exited {}: this test's whole point is driving the real curl \
                 client",
                version.status
            )
            .into());
        }

        let banner = String::from_utf8_lossy(&version.stdout).to_string();
        let protocols_line = banner
            .lines()
            .find(|l| l.starts_with("Protocols:"))
            .unwrap_or_default()
            .to_string();
        if !protocols_line.split_whitespace().any(|p| p == "gopher") {
            return Err(format!(
                "this curl was built without gopher support, so it cannot be the independent \
                 client behind Gopher's maturity rating.\n{protocols_line}"
            )
            .into());
        }

        println!("curl: {}", banner.lines().next().unwrap_or_default());
        Ok(())
    }

    /// Run curl against a gopher URL and return its stdout, failing loudly on a timeout.
    async fn curl_gopher(port: u16, path: &str) -> E2EResult<String> {
        let url = format!("gopher://127.0.0.1:{}{}", port, path);
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new("curl")
                .arg("-sS")
                // curl reads a gopher reply until EOF. If the server ever stopped closing,
                // this bound is what turns the hang into a diagnosis instead of a stall.
                .arg("--max-time")
                .arg("15")
                .arg("--")
                .arg(&url)
                .stdin(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| format!("curl did not exit within 30s for {url}"))?
        .map_err(|e| format!("could not run curl: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(format!(
                "curl exited {:?} for {url}. Exit 28 means it timed out waiting for EOF — the \
                 server answered but never closed the connection, which RFC 1436 requires.\
                 \nstdout: {stdout}\nstderr: {stderr}",
                output.status
            )
            .into());
        }

        Ok(stdout)
    }

    /// The real `curl` must fetch a menu, and get the exact bytes RFC 1436 describes.
    #[tokio::test]
    async fn test_gopher_menu_with_real_curl() -> E2EResult<()> {
        require_curl_with_gopher().await?;

        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gopher")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("gopher")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "gopher",
                            "instruction": "Serve a root menu"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // curl sends an empty selector for `gopher://host/`, so there is nothing
                    // to filter on: one rule, one request.
                    .on_event("gopher_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_gopher_menu",
                            "items": [
                                {"type": "i", "display": "Welcome to the hole"},
                                {"type": "0", "display": "About this server",
                                 "selector": "/about.txt", "host": "127.0.0.1", "port": 70},
                                {"type": "1", "display": "Files", "selector": "/files",
                                 "host": "127.0.0.1", "port": 70},
                                {"type": "7", "display": "Search", "selector": "/search",
                                 "host": "127.0.0.1", "port": 70}
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        let stdout = curl_gopher(server.port, "/").await?;

        // An informational line takes the conventional fake selector / (NULL) host / port 0,
        // which the server fills in - the model supplied only type and display.
        assert!(
            stdout.contains("iWelcome to the hole\tfake\t(NULL)\t0\r\n"),
            "informational line was not assembled as convention requires.\nstdout: {stdout:?}"
        );
        assert!(
            stdout.contains("0About this server\t/about.txt\t127.0.0.1\t70\r\n"),
            "text-file item line is wrong.\nstdout: {stdout:?}"
        );
        assert!(
            stdout.contains("1Files\t/files\t127.0.0.1\t70\r\n"),
            "directory item line is wrong.\nstdout: {stdout:?}"
        );
        assert!(
            stdout.contains("7Search\t/search\t127.0.0.1\t70\r\n"),
            "search item line is wrong.\nstdout: {stdout:?}"
        );
        // curl does no Gopher parsing, so the terminator is still in its output - which is
        // how we can assert on it at all.
        assert!(
            stdout.ends_with(".\r\n"),
            "menu was not terminated by a lone period line.\nstdout: {stdout:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The real `curl` must fetch a document, including the leading-dot escaping.
    #[tokio::test]
    async fn test_gopher_document_with_real_curl() -> E2EResult<()> {
        require_curl_with_gopher().await?;

        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gopher")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("gopher")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "gopher",
                            "instruction": "Serve /about.txt as a document"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("gopher_request")
                    .and_event_data_contains("selector", "/about.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_gopher_text",
                            "text": "About this server\n. a line that starts with a period\nend\n"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        // The `0` in the path is curl's own note about the reply it expects; it is stripped
        // before anything is sent, so the server sees the selector `/about.txt`.
        let stdout = curl_gopher(server.port, "/0/about.txt").await?;

        assert!(
            stdout.starts_with("About this server\r\n"),
            "document did not start with the first line, CRLF-terminated.\nstdout: {stdout:?}"
        );
        // Periodating: the server doubled the leading dot so the line cannot be mistaken for
        // the terminator. curl does not undo it, so the doubled form is what lands on stdout.
        assert!(
            stdout.contains(".. a line that starts with a period\r\n"),
            "leading dot was not escaped by doubling.\nstdout: {stdout:?}"
        );
        assert!(
            stdout.ends_with("end\r\n.\r\n"),
            "document was not terminated by a lone period line, or grew a spurious blank \
             final line from the trailing newline in the source text.\nstdout: {stdout:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A type-7 search request splits at the first tab, and only then.
    ///
    /// Raw socket rather than curl: curl can send the tab (`%09`), but only a socket can send
    /// a query that itself contains tabs, which is the case the split rule is about.
    #[tokio::test]
    async fn test_gopher_search_request_over_socket() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gopher")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("gopher")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "gopher",
                            "instruction": "Answer searches"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // One rule, branching on the event: two rules on the same event with no
                    // way to tell them apart would have the first answer both.
                    .on_event("gopher_request")
                    .respond_with_actions_from_event(|e| {
                        // A tab inside the display field would be sanitised to a space by the
                        // server (it would otherwise forge an extra menu field), so the query's
                        // own tab is spelled out here instead - the point of the assertion is
                        // that it survived the split, not how it renders.
                        let query = e["search_query"]
                            .as_str()
                            .map(|q| q.replace('\t', "|TAB|"))
                            .unwrap_or_else(|| "__ABSENT__".to_string());
                        serde_json::json!([{
                            "type": "send_gopher_menu",
                            "items": [{
                                "type": "i",
                                "display": format!(
                                    "selector={} query={}",
                                    e["selector"].as_str().unwrap_or("__ABSENT__"),
                                    query
                                )
                            }]
                        }])
                    })
                    .expect_calls(2)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        // A query containing its own tab: the split must take the FIRST tab only, so the
        // remaining tab belongs to the query.
        let searched = gopher_request(&addr, "/search\tterm one\ttwo").await;
        assert!(
            searched.contains("selector=/search query=term one|TAB|two"),
            "the search request did not split at the first tab only.\nreply: {searched:?}"
        );

        // No tab at all: `search_query` must be absent, not empty. The distinction is what
        // separates "open the search form" from "search for nothing".
        let plain = gopher_request(&addr, "/search").await;
        assert!(
            plain.contains("selector=/search query=__ABSENT__"),
            "a request with no tab still carried a search_query.\nreply: {plain:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// When the model cannot be reached, the peer gets a type-3 item carrying a *category* —
    /// never netget's own error text.
    ///
    /// The mock answers HTTP 500 to any request no rule matches, and this config deliberately
    /// declares no rule for `gopher_request`, so the event's LLM call fails for real. What is
    /// asserted is the two halves of the repo-wide rule: the peer is answered rather than left
    /// hanging on a silent close, and the answer names no backend, model, URL or retry
    /// machinery.
    #[tokio::test]
    async fn test_gopher_llm_failure_is_a_type_3_category_not_an_error_string() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gopher")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("gopher")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "gopher",
                            "instruction": "Serve a menu"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                // No rule for gopher_request: the mock 500s, and the server has to answer
                // the peer anyway.
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let reply = gopher_request(&addr, "/anything").await;

        assert!(
            reply.starts_with("3netget: ") && reply.ends_with("\t\terror.host\t1\r\n.\r\n"),
            "a backend failure must still be a well-formed type-3 item, not silence.\n\
             reply: {reply:?}"
        );
        for leaked in [
            "LLM", "llm", "ollama", "http://", "model", "retries", "Error:", "anyhow",
        ] {
            assert!(
                !reply.contains(leaked),
                "the peer-visible failure item leaked {leaked:?} - it must carry a category \
                 from crate::utils::WireFailure and nothing derived from the error.\n\
                 reply: {reply:?}"
            );
        }

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// An unknown selector gets a type-3 item, and the connection is logged and then closed.
    ///
    /// Raw socket: curl exits 0 on a type-3 reply (it has no notion of a Gopher error), so the
    /// error is only observable in the bytes.
    #[tokio::test]
    async fn test_gopher_error_item_and_connection_logging() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gopher")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("gopher")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "gopher",
                            "instruction": "Error on unknown selectors"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("gopher_request")
                    .and_event_data_contains("selector", "/nope")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_gopher_error",
                            "message": "No such selector: /nope"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let reply = gopher_request(&addr, "/nope").await;

        // Type 3, the display text, an empty selector, and the conventional error.host:1 that
        // no client will follow.
        assert_eq!(
            reply, "3No such selector: /nope\t\terror.host\t1\r\n.\r\n",
            "type-3 error item was not assembled as expected"
        );

        server
            .wait_for_log("Gopher client connected from", 10)
            .await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
