//! CPU-only client audit follow-up: no model endpoints, remote services, or hardware.
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn wire_values_reject_overflow_and_invalid_array_elements() {
    use netget::client::wire_values::{bytes, number};
    assert_eq!(
        number::<u16>(&json!({"port":65535}), "port", 0).unwrap(),
        65535
    );
    for value in [json!(-1), json!(65536), json!("80"), json!(1.5)] {
        assert!(number::<u16>(&json!({"port":value}), "port", 0).is_err());
    }
    assert_eq!(bytes(&[json!(0), json!(255)]).unwrap(), [0, 255]);
    for value in [json!(256), json!(-1), json!(null), json!("1")] {
        assert!(bytes(&[json!(0), value]).is_err());
    }
}

#[test]
fn http_target_refuses_invalid_explicit_ports_and_userinfo() {
    use netget::client::http_fetch::transport::parse_http_url;
    for url in [
        "http://host:65536/",
        "http://host:999999/",
        "http://host:abc/",
        "http://host:/",
        "http://user:pass@host/",
        "http:///path",
    ] {
        assert!(parse_http_url(url).is_err(), "{url}");
    }
    let target = parse_http_url("http://[::1]:8080/path?q=1").unwrap();
    assert_eq!(
        (
            target.host.as_str(),
            target.port,
            target.path_and_query.as_str()
        ),
        ("::1", 8080, "/path?q=1")
    );
}

#[tokio::test]
async fn bounded_native_response_helpers_keep_charset_and_json() {
    use netget::client::http_fetch::{read_response_bytes, read_response_json, read_response_text};
    let response = hyper::Response::builder()
        .header("content-type", "text/plain; charset=windows-1252")
        .body(vec![0x80])
        .unwrap();
    assert_eq!(
        read_response_text(reqwest::Response::from(response), 1)
            .await
            .unwrap(),
        "€"
    );
    let response = hyper::Response::new(bytes::Bytes::from_static(br#"{"ok":true}"#));
    let body: serde_json::Value = read_response_json(reqwest::Response::from(response), 11)
        .await
        .unwrap();
    assert_eq!(body, json!({"ok":true}));
    let response = reqwest::Response::from(hyper::Response::new(vec![0; 5]));
    assert!(read_response_bytes(response, 4).await.is_err());
}

async fn response_server(response: &'static [u8]) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(peer.read_u8().await.unwrap());
        }
        let _ = peer.write_all(response).await;
    });
    url
}

#[tokio::test]
async fn native_buffered_cap_counts_chunked_body_but_download_chunks_still_stream() {
    use netget::client::http_fetch::FetchClient;
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
    let client = FetchClient::from_reqwest(reqwest::Client::builder().no_proxy().build().unwrap())
        .with_max_body(4);
    let response = client
        .get(&response_server(RESPONSE).await)
        .send()
        .await
        .unwrap();
    assert!(response
        .bytes()
        .await
        .unwrap_err()
        .to_string()
        .contains("cap"));
    let mut response = client
        .get(&response_server(RESPONSE).await)
        .send()
        .await
        .unwrap();
    let mut streamed = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        streamed.extend_from_slice(&chunk);
    }
    assert_eq!(streamed, b"abcdef");
}

#[tokio::test]
async fn incomplete_text_lines_have_a_deadline_after_the_first_byte() {
    use netget::client::response_reader::read_response_line_with_timeout;
    let (client, mut peer) = tokio::io::duplex(64);
    peer.write_all(b"+OK partial").await.unwrap();
    let error = read_response_line_with_timeout(
        &mut tokio::io::BufReader::new(client),
        &mut String::new(),
        Duration::from_millis(20),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn binary_frame_deadline_excludes_idle_and_completed_event_handling() {
    use netget::client::response_reader::FrameReader;
    let (client, mut peer) = tokio::io::duplex(64);
    let mut reader = FrameReader::new(client);
    reader.start_frame(Duration::from_millis(20));
    assert_eq!(
        reader.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    reader.end_frame();
    peer.write_all(&[7]).await.unwrap();
    assert_eq!(reader.read_u8().await.unwrap(), 7);
}

#[tokio::test]
async fn pop3_framing_tracks_each_written_command_not_status_wording() {
    use netget::client::pop3::CommandWriter;
    let (writer, mut peer) = tokio::io::duplex(1024);
    let mut writer = CommandWriter::new(writer);
    for command in [
        "USER alice",
        "PASS password",
        "LIST",
        "LIST 1",
        "UIDL",
        "UIDL 1",
        "RETR 1",
        "TOP 1 0",
        "CAPA",
        "QUIT",
    ] {
        writer.send(command).await.unwrap();
    }
    for multiline in [
        false, false, true, false, true, false, true, true, true, false,
    ] {
        assert_eq!(
            writer
                .next_response_is_multiline("+OK arbitrary wording with messages and octets")
                .unwrap(),
            multiline
        );
    }
    writer.send("RETR 2").await.unwrap();
    assert!(!writer
        .next_response_is_multiline("-ERR unavailable")
        .unwrap());
    assert!(writer
        .next_response_is_multiline("+OK unsolicited")
        .is_err());
    assert!(writer.send("USER alice\r\nDELE 1").await.is_err());
    let mut sent = vec![0; 10];
    peer.read_exact(&mut sent).await.unwrap();
    assert_eq!(sent, b"USER alice");
}

#[tokio::test]
async fn pop3_interrupted_write_poisoning_prevents_wrong_response_correlation() {
    use netget::client::pop3::CommandWriter;
    let (writer, _peer) = tokio::io::duplex(1);
    let mut writer = CommandWriter::new(writer);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), writer.send("RETR 1"))
            .await
            .is_err()
    );
    assert!(writer.send("USER alice").await.is_err());
    assert!(writer.next_response_is_multiline("+OK").is_err());
}

#[test]
fn vnc_des_matches_independent_openssl_fixture_and_password_truncation() {
    use netget::client::vnc::vnc_auth_response;
    let challenge = std::array::from_fn(|index| index as u8);
    // OpenSSL DES-ECB, key bit-reversed bytewise from ASCII "password", no padding.
    assert_eq!(
        hex::encode(vnc_auth_response(b"password", challenge)),
        "b866924125c8eebb9debc1db61c538e2"
    );
    assert_eq!(
        vnc_auth_response(b"passwordignored", challenge),
        vnc_auth_response(b"password", challenge)
    );
    assert_eq!(
        vnc_auth_response(b"pass", challenge),
        vnc_auth_response(b"pass\0\0\0\0", challenge)
    );
}

#[test]
fn vnc_actions_reject_values_before_custom_results_can_truncate_them() {
    use netget::llm::actions::client_trait::Client;
    let protocol = netget::client::vnc::VncClientProtocol::new();
    for action in [
        json!({"type":"request_framebuffer_update","x":65536}),
        json!({"type":"send_pointer_event","x":1,"y":2,"button_mask":256}),
    ] {
        assert!(protocol.execute_action(action).is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn injected_agent_request_writes_a_framed_packet_and_reports_actual_bytes() {
    use netget::{
        client::ssh_agent::SshAgentClient,
        state::{
            client_handles::{ClientCommand, ClientSendOutcome},
            AppState, ClientId,
        },
    };
    use std::sync::Arc;
    let (writer, mut peer) = tokio::io::duplex(64);
    let writer = Arc::new(tokio::sync::Mutex::new(
        netget::client::ssh_agent::AgentWriter::new(writer),
    ));
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let (status, _) = tokio::sync::mpsc::unbounded_channel();
    let state = Arc::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".into(),
    ));
    assert!(
        !SshAgentClient::handle_injected_command(
            &writer,
            ClientCommand {
                action: json!({"type":"request_identities"}),
                reply_tx
            },
            ClientId::new(1),
            &state,
            &status
        )
        .await
    );
    assert!(matches!(
        reply_rx.await.unwrap().unwrap(),
        ClientSendOutcome::Sent { bytes_sent: 5 }
    ));
    let mut packet = [0; 5];
    peer.read_exact(&mut packet).await.unwrap();
    assert_eq!(packet, [0, 0, 0, 1, 11]);
    assert!(SshAgentClient::encode_custom_action(
        "sign_request",
        &json!({"public_key_blob_hex":"", "data_hex":"", "flags":4294967296u64})
    )
    .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn agent_partial_body_deadline_survives_cancelled_next_calls() {
    use futures::StreamExt;
    let (reader, mut peer) = tokio::io::duplex(64);
    let mut reader =
        netget::client::ssh_agent::response_reader_with_timeout(reader, Duration::from_millis(40));
    peer.write_all(&[0, 0, 0, 8]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), reader.next())
            .await
            .is_err()
    );
    let error = tokio::time::timeout(Duration::from_secs(1), reader.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[cfg(unix)]
#[tokio::test]
async fn agent_expired_deadline_rejects_a_body_completed_between_polls() {
    use futures::StreamExt;
    let (reader, mut peer) = tokio::io::duplex(64);
    let mut reader =
        netget::client::ssh_agent::response_reader_with_timeout(reader, Duration::from_millis(30));
    peer.write_all(&[0, 0, 0, 1]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), reader.next())
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    peer.write_all(&[6]).await.unwrap();
    let error = reader.next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(reader.next().await.is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn agent_incomplete_writes_close_and_poison_the_transport() {
    use netget::client::ssh_agent::{AgentWriter, SshAgentClient};
    use std::sync::Arc;
    for cancelled_by_caller in [false, true] {
        let (writer, mut peer) = tokio::io::duplex(1);
        let writer = Arc::new(tokio::sync::Mutex::new(AgentWriter::new(writer)));
        let packet = bytes::Bytes::from_static(&[11]);
        if cancelled_by_caller {
            assert!(tokio::time::timeout(
                Duration::from_millis(20),
                SshAgentClient::send_message_with_timeout(
                    packet.clone(),
                    &writer,
                    Duration::from_secs(5)
                )
            )
            .await
            .is_err());
        } else {
            assert!(SshAgentClient::send_message_with_timeout(
                packet.clone(),
                &writer,
                Duration::from_millis(20)
            )
            .await
            .is_err());
        }
        let error =
            SshAgentClient::send_message_with_timeout(packet, &writer, Duration::from_secs(1))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("unusable"), "{error:#}");
        let mut partial = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut partial))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            partial,
            [0],
            "only the original partial prefix may reach the peer"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn agent_write_deadline_covers_lock_wait_without_poisoning_an_untouched_transport() {
    use netget::client::ssh_agent::{AgentWriter, SshAgentClient};
    use std::sync::Arc;
    let (writer, mut peer) = tokio::io::duplex(64);
    let writer = Arc::new(tokio::sync::Mutex::new(AgentWriter::new(writer)));
    let held = writer.lock().await;
    let packet = bytes::Bytes::from_static(&[11]);
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        SshAgentClient::send_message_with_timeout(
            packet.clone(),
            &writer,
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("the internal deadline must include lock acquisition")
    .unwrap_err();
    assert!(error.to_string().contains("deadline"));
    drop(held);
    assert_eq!(
        SshAgentClient::send_message_with_timeout(packet, &writer, Duration::from_secs(1))
            .await
            .unwrap(),
        5
    );
    let mut frame = [0; 5];
    peer.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame, [0, 0, 0, 1, 11]);
}

#[tokio::test]
async fn peer_partial_headers_have_an_absolute_deadline() {
    let (mut reader, mut peer) = tokio::io::duplex(64);
    peer.write_all(&[0]).await.unwrap();
    assert!(
        netget::client::torrent_peer::read_peer_message_with_timeout(
            &mut reader,
            Duration::from_millis(20)
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("deadline")
    );
}

#[cfg(all(unix, feature = "libsmbclient"))]
#[test]
fn smb_buffered_file_read_refuses_oversize_without_returning_partial_success() {
    use netget::client::smb::{read_file_bounded, MAX_FILE_BYTES};
    assert_eq!(read_file_bounded(&b"abc"[..]).unwrap(), b"abc");
    assert!(read_file_bounded(std::io::Read::take(
        std::io::repeat(0),
        MAX_FILE_BYTES as u64 + 1
    ))
    .is_err());
}

#[tokio::test]
async fn aborted_client_owner_closes_the_webrtc_peer() {
    use std::sync::Arc;
    use webrtc::{
        api::APIBuilder,
        peer_connection::{
            configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        },
    };
    let peer = Arc::new(
        APIBuilder::new()
            .build()
            .new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let guard = netget::client::webrtc::PeerConnectionGuard::new(peer.clone());
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = guard;
        let _ = started.send(());
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while peer.connection_state() != RTCPeerConnectionState::Closed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
