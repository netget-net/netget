//! A WHOIS query is a *line*, not a TCP segment.
//!
//! The read loop used to raise one `whois_query` event per `read()`, so a query split across
//! two segments became two events carrying two fragments — and a peer dripping one byte at a
//! time bought one LLM call per byte from a socket nothing authenticates. Both tests here are
//! about that boundary; neither needs a model to answer the query itself.
//!
//! WHOIS is the protocol other simple protocols in this repo were told to copy, so a framing
//! defect here is the kind that gets inherited.

mod whois_line_framing_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Read until `needle` shows up or the deadline passes — a condition, not a fixed sleep.
    async fn read_until(stream: &mut TcpStream, needle: &str, secs: u64) -> String {
        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        let mut buf = [0u8; 1024];
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    seen.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// A query arriving in four writes must raise **one** event carrying the whole query.
    ///
    /// `expect_calls(1)` on a rule keyed to the complete domain is what makes this decisive.
    /// Per-segment framing raised four events whose `query` values were `exam`, `ple`, `.com`
    /// and the empty string; none matches, so the rule would report zero calls and each
    /// fragment would instead fall through to a real model call.
    #[tokio::test]
    async fn a_query_split_across_segments_is_one_query() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Answer example.com, then close"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Split Registrar"
                        },
                        {"type": "close_connection"}
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

        // Four writes, flushed separately, with a pause between them so they cannot coalesce
        // into one segment. The last carries the terminator alone.
        for piece in ["exam", "ple", ".com", "\r\n"] {
            stream.write_all(piece.as_bytes()).await?;
            stream.flush().await?;
            tokio::time::sleep(Duration::from_millis(80)).await;
        }

        let seen = read_until(&mut stream, "Registrar:", 20).await;
        assert!(
            seen.contains("Domain Name: example.com"),
            "the four segments were not reassembled into one query. Saw: {seen:?}"
        );
        assert!(
            seen.contains("Registrar: Split Registrar"),
            "the record was incomplete. Saw: {seen:?}"
        );

        // The count is the real assertion: one query in, one event out.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A peer that never sends a newline must be refused rather than buffered without limit.
    ///
    /// The refusal is a `%` comment, which is a remark in every WHOIS dialect, so a client
    /// cannot read it as a record. It is fixed text: nothing about netget's internals, and no
    /// placeholder an internal error could reach.
    #[tokio::test]
    async fn a_query_with_no_newline_is_bounded_and_refused() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "",
                            "event_handlers": [{
                                "event_pattern": "whois_query",
                                "handler": {
                                    "type": "static",
                                    "actions": [{
                                        "type": "send_whois_response",
                                        "response": "ANSWERED"
                                    }]
                                }
                            }]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

        // Past the 4 KiB cap, and not one newline in it. Written in chunks because the server
        // stops reading partway through and the socket then fills.
        let chunk = vec![b'a'; 2048];
        for _ in 0..8 {
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = stream.flush().await;

        let seen = read_until(&mut stream, "too long", 20).await;
        assert!(
            seen.contains("% netget: query too long"),
            "a peer sending 16 KiB with no newline was not refused; the loop buffered it \
             instead. Saw: {seen:?}"
        );
        assert!(
            !seen.contains("ANSWERED"),
            "an unterminated run of bytes was treated as a query and reached the handler: \
             {seen:?}"
        );

        // The handler never ran, so the only LLM call in the whole test is the startup one.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A record field is one line, so CR/LF in one must not forge another.
    ///
    /// This is the family's signature defect — FTP's `send_ftp_response` documented that text
    /// must not contain CR/LF and checked nothing, so a `message` of
    /// `"Password required\r\n230 User logged in"` turned a 331 into a successful login.
    /// A WHOIS record has no authentication in it, but it is still `Key: value` lines, and a
    /// forged `Registrant Name:` is indistinguishable to whoever reads the output from one the
    /// model asserted. `send_whois_response` is free text and deliberately unfiltered; a
    /// *record* is not free text.
    #[tokio::test]
    async fn crlf_in_a_record_field_cannot_forge_another_field() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "",
                            "event_handlers": [{
                                "event_pattern": "whois_query",
                                "handler": {
                                    "type": "static",
                                    "actions": [
                                        {
                                            "type": "send_whois_record",
                                            "domain": "example.com",
                                            // Every one of these tries to end its line early.
                                            "registrar": "Good Registrar\r\nRegistrant Name: FORGED",
                                            "registrant": "Real Org\r\nAdmin Name: FORGED",
                                            // Given, so exactly one real `Admin Name:` line
                                            // exists for the forged one to be counted against:
                                            // an omitted field is no longer printed.
                                            "admin_contact": "Real Admin",
                                            "name_servers": [
                                                "ns1.example.com\r\nName Server: forged.example"
                                            ]
                                        },
                                        {"type": "close_connection"}
                                    ]
                                }
                            }]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        stream.write_all(b"example.com\r\n").await?;
        stream.flush().await?;

        let seen = read_until(&mut stream, "Name Server:", 20).await;

        // The guarantee is structural: **no forged line**. The words `Registrant Name: FORGED`
        // are still in the output, and should be — sanitising is not censoring. What matters
        // is that they are inside the `Registrar:` field's own line, where a line-oriented
        // reader attributes them correctly, instead of starting a line of their own.
        let lines: Vec<&str> = seen.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("Registrant Name:"))
                .count(),
            1,
            "exactly one line may begin `Registrant Name:`; a CR/LF in `registrar` forged \
             another: {lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("Admin Name:"))
                .count(),
            1,
            "exactly one line may begin `Admin Name:`; a CR/LF in `registrant` forged \
             another: {lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("Name Server:"))
                .count(),
            1,
            "one name server was asked for, so exactly one line may begin `Name Server:`: \
             {lines:?}"
        );
        // Positively: the forged name server is still there, *inside* the real one's line.
        // Asserting its absence would be asserting censorship, which is not the property.
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("Name Server: ns1.example.com")
                    && l.contains("forged.example")),
            "the forged name server should have been folded into the real one's line: \
             {lines:?}"
        );

        // The text survives, with each of CR and LF becoming a space rather than being
        // deleted — deleting would concatenate the two sides into `Good RegistrarRegistrant`,
        // which reads as a single value and is its own small lie.
        assert!(
            seen.contains("Registrar: Good Registrar  Registrant Name: FORGED"),
            "the field's text should be preserved with the line break turned into spaces: \
             {seen:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
