//! End-to-end test for the Tor relay: a real ntor client, a real circuit, a real exit stream.
//!
//! The peer here is a Tor client written from tor-spec in this file — the ntor handshake
//! (5.1.4), its 92-byte KDF layout (5.2.2) and AES-128-CTR relay-cell crypto (6.1) — not a
//! call into the server's own `circuit.rs`. That independence is the whole point: if the
//! relay's key derivation, its direction assignment, or its cell layout is wrong by a single
//! byte, this client derives different keys, the AUTH check fails, and the test fails.
//!
//! What it proves:
//!
//! - The reader frames an 11-byte VERSIONS cell (2-byte circuit id, variable length) instead
//!   of blocking on a 514-byte `read_exact`, and answers it.
//! - CREATE2/CREATED2 completes a genuine Curve25519 ntor handshake whose server AUTH value
//!   this client recomputes and checks.
//! - RELAY/BEGIN opens a real TCP stream to a localhost HTTP server and answers CONNECTED.
//! - RELAY/DATA carries an HTTP request out and the response back, decrypting correctly with
//!   the backward key — which means Kf/Kb are the right way round and the keystreams stay in
//!   step across cells.
//!
//! What it does **not** prove, and why this protocol stays `Experimental`: the link handshake
//! stops after VERSIONS (no CERTS / AUTH_CHALLENGE / NETINFO), relay-cell digests are never
//! computed or verified, and there is no EXTEND — so a real `tor` binary still cannot use
//! this relay. Those are listed in `src/server/tor_relay/CLAUDE.md`.

#[cfg(unix)]
mod tests {
    // The Tor client itself lives in `peer.rs`, shared with `llm_failure_test.rs`.
    use super::super::super::helpers::server::NetGetServer;
    use super::super::super::helpers::{self, E2EResult, NetGetConfig};
    use super::super::peer::{
        read_relay_identity, RelayPeer, RELAY_BEGIN, RELAY_CONNECTED, RELAY_DATA,
    };
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const HTTP_BODY: &str = "Hello from Tor exit relay!";

    /// Minimal HTTP/1.0 server used as the exit destination. Answers one request per
    /// connection and closes, which is what makes the relay's forwarder emit RELAY/DATA.
    async fn start_test_http_server() -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    // Request line + headers, ending at the blank line.
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => return,
                            Ok(_) => {
                                if line == "\r\n" || line == "\n" {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }

                    let response = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{}",
                        HTTP_BODY.len(),
                        HTTP_BODY
                    );
                    let mut stream = reader.into_inner();
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        (port, handle)
    }

    /// Start the relay and return its port, the server handle, and the relay identity a
    /// peer needs in order to run the ntor handshake at all.
    async fn start_netget_relay() -> E2EResult<(u16, NetGetServer, [u8; 20], [u8; 32])> {
        let prompt = "listen on port {AVAILABLE_PORT} via tor-relay. Handle TLS connections \
                      and Tor cells. Allow exit connections to localhost for testing.";
        let config = NetGetConfig::new_no_scripts(prompt)
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("tor-relay")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            // The registry name is "Tor Relay", with the space. The previous
                            // (permanently `#[ignore]`d) version of this test said
                            // "TorRelay", which `open_server` rejects outright — so it could
                            // never have started a server even if it had been run.
                            "base_stack": "Tor Relay",
                            "instruction": "Tor exit relay allowing localhost connections"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // The relay raises this once the ntor handshake completes. It must not
                    // answer with anything that produces output: an Output action replaces
                    // the CREATED2 cell the relay was about to send.
                    .on_event("tor_relay_circuit_created")
                    .respond_with_actions(json!([
                        {"type": "detect_relay_cell", "message": "circuit up"}
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = helpers::start_netget_server(config).await?;

        let (fingerprint, onion_key) = read_relay_identity(&server).await?;

        let port = server.port;
        Ok((port, server, fingerprint, onion_key))
    }

    /// VERSIONS → ntor circuit → exit stream → HTTP response, all the way back.
    ///
    /// 2 LLM calls: server startup, and the circuit-created event.
    #[tokio::test]
    async fn test_tor_relay_exit_stream_round_trip() -> E2EResult<()> {
        let (http_port, _http_handle) = start_test_http_server().await;
        let (relay_port, server, fingerprint, onion_key) = start_netget_relay().await?;

        let mut peer = RelayPeer::connect(relay_port).await?;

        // ---- link handshake, as far as it goes ----------------------------------------
        let versions = peer.versions_handshake().await?;
        assert!(
            versions.contains(&4),
            "the relay frames link protocol v4 cells, so its VERSIONS reply must offer 4; \
             got {:?}",
            versions
        );

        // ---- ntor circuit --------------------------------------------------------------
        peer.create_circuit(&fingerprint, &onion_key).await?;

        // ---- exit stream ---------------------------------------------------------------
        let stream_id: u16 = 1;
        let mut begin_data = format!("127.0.0.1:{}\0", http_port).into_bytes();
        begin_data.extend_from_slice(&[0u8; 4]); // BEGIN flags
        peer.send_relay(RELAY_BEGIN, stream_id, &begin_data).await?;

        let (cmd, got_stream, _) = peer.recv_relay("the reply to RELAY/BEGIN").await;
        assert_eq!(
            cmd, RELAY_CONNECTED,
            "BEGIN to a listening localhost port must be answered with RELAY/CONNECTED (4), \
             got relay command {}",
            cmd
        );
        assert_eq!(got_stream, stream_id, "CONNECTED must name the same stream");

        // ---- data both ways ------------------------------------------------------------
        let request = format!(
            "GET / HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            http_port
        );
        peer.send_relay(RELAY_DATA, stream_id, request.as_bytes())
            .await?;

        let mut response = String::new();
        for _ in 0..8 {
            let (cmd, _, data) = peer
                .recv_relay("a RELAY cell carrying the HTTP response")
                .await;
            if cmd == RELAY_DATA {
                response.push_str(&String::from_utf8_lossy(&data));
                if response.contains(HTTP_BODY) {
                    break;
                }
            } else {
                panic!(
                    "expected RELAY/DATA carrying the HTTP response, got relay command {} \
                     after receiving {:?}",
                    cmd, response
                );
            }
        }

        assert!(
            response.starts_with("HTTP/1.0 200 OK"),
            "the exit stream did not carry the HTTP status line back: {:?}",
            response
        );
        assert!(
            response.contains(HTTP_BODY),
            "the exit stream did not carry the HTTP body back: {:?}",
            response
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
