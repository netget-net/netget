//! CPU-only regressions for the client/easy/pipe review. No model endpoints are used.

use netget::pipe::{render_payload, PipeSpec, MAX_PAYLOAD_BYTES, MAX_RENDERED_BYTES};
use serde_json::json;
use std::collections::BTreeMap;

fn pipe(data: &str, encoding: &str) -> PipeSpec {
    PipeSpec {
        id: 1,
        from: 1,
        to: 2,
        on: "event".into(),
        as_action: "send_tcp_data".into(),
        map: BTreeMap::from([
            ("data".into(), data.into()),
            ("encoding".into(), encoding.into()),
        ]),
    }
}

#[test]
fn pipe_accepts_exact_decoded_bound_in_utf8_and_separated_hex() {
    let text = "a".repeat(MAX_PAYLOAD_BYTES);
    assert_eq!(
        render_payload(&pipe("{text}", "utf8"), &json!({"text": text})).unwrap(),
        text.as_bytes()
    );
    let hex = "61: ".repeat(MAX_PAYLOAD_BYTES);
    assert_eq!(
        render_payload(&pipe("{hex}", "hex"), &json!({"hex": hex})).unwrap(),
        text.as_bytes()
    );
    assert!(render_payload(&pipe("{text}a", "utf8"), &json!({"text": text})).is_err());
}

#[test]
fn pipe_refuses_excessive_expansion_before_decoding() {
    let whitespace = " ".repeat(MAX_RENDERED_BYTES);
    let error =
        render_payload(&pipe("{text}{text}", "hex"), &json!({"text": whitespace})).unwrap_err();
    assert!(error.to_string().contains("rendered mapping"), "{error:#}");
}

#[test]
fn pipe_bounds_non_string_json_substitutions_and_encoding() {
    let huge = json!({"nested": "x".repeat(MAX_RENDERED_BYTES)});
    assert!(render_payload(&pipe("{value}", "utf8"), &json!({"value": huge})).is_err());
    let error = render_payload(
        &pipe("a", "{encoding}"),
        &json!({"encoding": "x".repeat(MAX_RENDERED_BYTES + 1)}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("rendered mapping"), "{error:#}");
}

#[test]
fn pipe_preserves_missing_fields_json_values_and_unterminated_placeholders() {
    let rendered = render_payload(
        &pipe("{missing}:{nested.count}:{items}:{unfinished", "utf8"),
        &json!({"nested": {"count": 3}, "items": [true, false]}),
    )
    .unwrap();
    assert_eq!(rendered, b":3:[true,false]:{unfinished");
}

#[tokio::test]
async fn pipe_rejects_malformed_explicit_source_and_mapping() {
    use netget::pipe::execute_pipe_action;
    use netget::state::{app_state::AppState, server::ServerInstance, ServerId};
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let from = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "tcp".into(),
            String::new(),
        ))
        .await;
    let to = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "tcp".into(),
            String::new(),
        ))
        .await;
    for bad_from in [
        json!("invalid"),
        json!(-1),
        json!(4294967296_u64),
        json!(null),
    ] {
        let action = json!({"from": bad_from, "to": to.as_u32(), "on": "*", "as": "send_tcp_data", "map": {"data": "hello"}});
        let err = execute_pipe_action("create_pipe", &action, &state, Some(from))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("'from'"), "{err:#}");
    }
    let action = json!({"to": to.as_u32(), "on": "*", "as": "send_tcp_data", "map": {"data": "hello", "encoding": 1}});
    let err = execute_pipe_action("create_pipe", &action, &state, Some(from))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("encoding"), "{err:#}");
    let valid =
        json!({"to": to.as_u32(), "on": "*", "as": "send_tcp_data", "map": {"data": "hello"}});
    execute_pipe_action("create_pipe", &valid, &state, Some(from))
        .await
        .unwrap();
}

mod http {
    use netget::client::http_fetch::transport;
    use netget::easy::http::actions::markdown_to_html;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn easy_markdown_pairs_tags_and_preserves_code_contents() {
        let html =
            markdown_to_html("**bold** __also bold__ *italic* _also italic_ `**literal** <tag>`");
        assert!(html.contains("<strong>bold</strong> <strong>also bold</strong> <em>italic</em> <em>also italic</em> <code>**literal** &lt;tag&gt;</code>"), "{html}");
    }

    #[test]
    fn easy_markdown_keeps_unmatched_delimiters_and_identifiers_literal() {
        let html = markdown_to_html("some_identifier_name **unfinished <script>");
        assert!(
            html.contains("<p>some_identifier_name **unfinished &lt;script&gt;</p>"),
            "{html}"
        );
    }

    #[test]
    fn easy_markdown_closes_a_list_before_starting_a_code_block() {
        let html = markdown_to_html("- item\n```\n<tag>\n```");
        assert!(
            html.contains("</li>\n</ul>\n<pre><code>&lt;tag&gt;\n</code></pre>"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn transport_preserves_extension_method_case_and_normalizes_known_methods() {
        for (method, wire_method) in [
            ("PROPFIND", "PROPFIND"),
            ("MKCOL", "MKCOL"),
            ("COPY", "COPY"),
            ("MOVE", "MOVE"),
            ("LOCK", "LOCK"),
            ("UNLOCK", "UNLOCK"),
            ("Custom", "Custom"),
            ("custom", "custom"),
            ("gEt", "GET"),
            ("post", "POST"),
        ] {
            let (client, mut peer) = tokio::io::duplex(4096);
            let expected = format!("{wire_method} /resource HTTP/1.1\r\n");
            let server = tokio::spawn(async move {
                let mut request = Vec::new();
                loop {
                    request.push(peer.read_u8().await.unwrap());
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(
                    request.starts_with(expected.as_bytes()),
                    "{}",
                    String::from_utf8_lossy(&request)
                );
                peer.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            });
            let target = transport::parse_http_url("http://localhost/resource").unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(3),
                transport::exchange_response(client, method, &target, &[], None, 1024),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), 204);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_http1_exchange_releases_its_io() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let target = transport::parse_http_url("http://localhost/").unwrap();
            transport::exchange_response(client, "GET", &target, &[], None, 1024).await
        });
        let mut request = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                request.push(peer.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), peer.read_to_end(&mut tail))
            .await
            .expect("cancellation must close the driver's socket")
            .unwrap();
        assert!(tail.is_empty());
    }

    #[tokio::test]
    async fn cancelled_http2_exchange_releases_its_io() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let target = transport::parse_http_url("http://localhost/").unwrap();
            transport::exchange_response_h2(client, "GET", &target, &[], None, 1024).await
        });
        let mut preface = [0; 24];
        tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut preface))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), peer.read_to_end(&mut tail))
            .await
            .expect("cancellation must close the driver's socket")
            .unwrap();
    }
}

mod torrent_peer {
    use netget::client::torrent_peer::{read_peer_message, MAX_PEER_MESSAGE_BYTES};

    #[tokio::test]
    async fn peer_frames_reject_oversized_lengths_before_reading_a_body() {
        for length in [MAX_PEER_MESSAGE_BYTES as u32 + 1, u32::MAX] {
            let header = length.to_be_bytes();
            let error = read_peer_message(&mut &header[..]).await.unwrap_err();
            assert!(error.to_string().contains("exceeds"), "{error:#}");
        }
    }

    #[tokio::test]
    async fn peer_frames_preserve_keepalives_boundaries_and_fragment_errors() {
        let mut input = &[0, 0, 0, 0, 0, 0, 0, 1, 2][..];
        assert!(read_peer_message(&mut input).await.unwrap().is_empty());
        assert_eq!(read_peer_message(&mut input).await.unwrap(), [2]);
        let mut at_bound = (MAX_PEER_MESSAGE_BYTES as u32).to_be_bytes().to_vec();
        at_bound.resize(4 + MAX_PEER_MESSAGE_BYTES, 7);
        assert_eq!(
            read_peer_message(&mut at_bound.as_slice())
                .await
                .unwrap()
                .len(),
            MAX_PEER_MESSAGE_BYTES
        );
        assert!(read_peer_message(&mut &[0, 0, 0, 2, 7][..]).await.is_err());
    }
}

mod vnc {
    use netget::client::vnc::{discard_raw_rectangle, read_server_text, MAX_TEXT_BYTES};

    #[tokio::test]
    async fn vnc_strings_are_bounded_before_allocating_or_reading() {
        for length in [MAX_TEXT_BYTES as u32 + 1, u32::MAX] {
            let error = read_server_text(&mut &b""[..], length).await.unwrap_err();
            assert!(error.to_string().contains("exceeds"), "{error:#}");
        }
        let text = vec![b'a'; MAX_TEXT_BYTES];
        assert_eq!(
            read_server_text(&mut text.as_slice(), text.len() as u32)
                .await
                .unwrap(),
            text
        );
        assert!(read_server_text(&mut &b"abc"[..], 4).await.is_err());
    }

    #[tokio::test]
    async fn vnc_raw_pixels_preserve_the_next_message_and_reject_invalid_sizes() {
        let mut input = &[1, 2, 3, 4, 2][..];
        discard_raw_rectangle(&mut input, 1, 1).await.unwrap();
        assert_eq!(input, &[2], "the following Bell byte remains untouched");
        assert!(discard_raw_rectangle(&mut &b"abc"[..], 1, 1).await.is_err());
        let error = discard_raw_rectangle(&mut &b""[..], u16::MAX, u16::MAX)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("over"), "{error:#}");
    }
}

#[cfg(unix)]
mod ssh_agent {
    use futures::StreamExt;
    use netget::client::ssh_agent::{response_reader, SshAgentClient, MAX_RESPONSE_BYTES};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn ssh_agent_strips_prefixes_and_separates_coalesced_responses() {
        let wire = &[0, 0, 0, 5, 12, 0, 0, 0, 0, 0, 0, 0, 1, 6][..];
        let mut reader = response_reader(wire);
        let identities = reader.next().await.unwrap().unwrap();
        let decoded = SshAgentClient::parse_response(&identities).unwrap();
        assert_eq!(decoded["response_type"], "identities");
        assert_eq!(decoded["response_data"]["count"], 0);
        let success = reader.next().await.unwrap().unwrap();
        assert_eq!(
            SshAgentClient::parse_response(&success).unwrap()["response_type"],
            "success"
        );
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    async fn ssh_agent_keeps_partial_frames_across_cancelled_reads() {
        let (client, mut peer) = tokio::io::duplex(64);
        let mut reader = response_reader(client);
        peer.write_all(&[0, 0]).await.unwrap();
        // Polling once must consume the prefix fragment and then wait. Dropping
        // this future mirrors an injected command winning the read-loop select.
        assert!(futures::poll!(reader.next()).is_pending());
        peer.write_all(&[0, 1, 5]).await.unwrap();
        let frame = reader.next().await.unwrap().unwrap();
        assert_eq!(
            SshAgentClient::parse_response(&frame).unwrap()["response_type"],
            "failure"
        );
    }

    #[tokio::test]
    async fn ssh_agent_rejects_oversized_and_truncated_frames() {
        let header = (MAX_RESPONSE_BYTES as u32 + 1).to_be_bytes();
        let mut reader = response_reader(header.as_slice());
        assert!(reader.next().await.unwrap().is_err());
        let mut reader = response_reader(&[0, 0, 0, 2, 6][..]);
        assert!(reader.next().await.unwrap().is_err());
    }
}

mod text_responses {
    use netget::client::response_reader::{
        read_dot_response, read_response_line, MAX_MULTILINE_BYTES, MAX_RESPONSE_LINE_BYTES,
    };
    use tokio::io::BufReader;

    #[tokio::test]
    async fn bounded_response_lines_accept_the_limit_and_leave_the_next_line() {
        let mut input = vec![b'a'; MAX_RESPONSE_LINE_BYTES - 2];
        input.extend_from_slice(b"\r\nnext\r\n");
        let mut reader = BufReader::new(input.as_slice());
        let mut line = String::new();
        assert_eq!(
            read_response_line(&mut reader, &mut line).await.unwrap(),
            MAX_RESPONSE_LINE_BYTES
        );
        assert_eq!(read_response_line(&mut reader, &mut line).await.unwrap(), 6);
        assert_eq!(line, "next\r\n");
        assert_eq!(read_response_line(&mut reader, &mut line).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn response_lines_reject_overflow_and_truncated_eof() {
        let too_long = vec![b'a'; MAX_RESPONSE_LINE_BYTES + 1];
        let mut reader = BufReader::new(too_long.as_slice());
        let error = read_response_line(&mut reader, &mut String::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let mut reader = BufReader::new(&b"unfinished"[..]);
        let error = read_response_line(&mut reader, &mut String::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn dot_responses_unstuff_preserve_whitespace_and_stop_exactly_at_terminator() {
        let mut reader = BufReader::new(&b"..literal\r\n . \r\n  indented  \r\n.\r\nnext\r\n"[..]);
        let response = read_dot_response(&mut reader, "+OK".into()).await.unwrap();
        assert_eq!(response, "+OK\n.literal\n . \n  indented  ");
        let mut next = String::new();
        read_response_line(&mut reader, &mut next).await.unwrap();
        assert_eq!(next, "next\r\n");
    }

    #[tokio::test]
    async fn dot_responses_fail_on_eof_and_aggregate_overflow() {
        let mut reader = BufReader::new(&b"line\r\n"[..]);
        let error = read_dot_response(&mut reader, "+OK".into())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        let mut reader = BufReader::new(&b"x\r\n.\r\n"[..]);
        let error = read_dot_response(&mut reader, "x".repeat(MAX_MULTILINE_BYTES))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
