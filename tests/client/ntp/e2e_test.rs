//! E2E tests for the NTP client.
//!
//! These tests spawn the NetGet binary and drive its NTP client as a black box against a local
//! responder: a plain `tokio::net::UdpSocket` on 127.0.0.1 that answers every 48-byte client
//! request (mode 3) with a minimal valid server reply (mode 4) carrying a fixed stratum and a
//! fixed transmit timestamp. Nothing here leaves the machine.
//!
//! Each test makes three mocked LLM calls: the startup prompt (`open_client`), the
//! `ntp_connected` event (answered with `query_time`) and the `ntp_response_received` event.
//! The response rule matches on the stratum and transmit timestamp the responder sent, so a
//! reply that did not come from the responder, or was misparsed, leaves it uncalled and fails
//! `verify_mocks`.

mod ntp_client_tests {
    use crate::helpers::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// 2024-01-01T00:00:00Z in NTP seconds (Unix seconds + 2 208 988 800).
    const RESPONDER_TRANSMIT_NTP_SECS: u32 = 3_913_056_000;
    /// The same instant in Unix seconds, which is what the client reports to the model.
    const RESPONDER_TRANSMIT_UNIX_SECS: &str = "1704067200";

    /// A local NTP server: answers client requests on 127.0.0.1 and counts them.
    struct NtpResponder {
        addr: SocketAddr,
        queries: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for NtpResponder {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// The server reply to one client request (RFC 5905 §7.3): LI 0, VN 4, mode 4, the given
    /// stratum, the request's transmit timestamp echoed as the origin timestamp, and
    /// `RESPONDER_TRANSMIT_NTP_SECS` as the reference, receive and transmit timestamps.
    fn ntp_server_reply(request: &[u8], stratum: u8) -> [u8; 48] {
        let mut reply = [0u8; 48];
        reply[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
        reply[1] = stratum;
        reply[2] = 6; // poll: 64s
        reply[3] = (-20i8) as u8; // precision: ~1us
        reply[12..16].copy_from_slice(&[127, 0, 0, 1]); // reference id
        let ts = RESPONDER_TRANSMIT_NTP_SECS.to_be_bytes();
        reply[16..20].copy_from_slice(&ts); // reference timestamp
        reply[24..32].copy_from_slice(&request[40..48]); // origin = client's transmit
        reply[32..36].copy_from_slice(&ts); // receive timestamp
        reply[40..44].copy_from_slice(&ts); // transmit timestamp
        reply
    }

    async fn start_ntp_responder(stratum: u8) -> E2EResult<NtpResponder> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = queries.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                // Only a 48-byte client-mode (3) request gets an answer.
                if n != 48 || buf[0] & 0x07 != 3 {
                    continue;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = ntp_server_reply(&buf[..48], stratum);
                let _ = socket.send_to(&reply, from).await;
            }
        });
        Ok(NtpResponder {
            addr,
            queries,
            task,
        })
    }

    /// Start a client against `remote_addr` with the three-call mock, wait for the exchange,
    /// verify the mocks, and return how many requests the responder answered.
    async fn query_through_client(
        remote_addr: String,
        responder: &NtpResponder,
        stratum: u8,
    ) -> E2EResult<usize> {
        let prompt = format!("Query the NTP server at {remote_addr} and report its time.");
        let open_client_addr = remote_addr.clone();
        let client_config = NetGetConfig::new(prompt).with_mock(move |mock| {
            mock
                // Event rules first: they never match the startup call, which carries no event.
                .on_event("ntp_connected")
                .respond_with_actions(serde_json::json!([{"type": "query_time"}]))
                .expect_calls(1)
                .and()
                .on_event("ntp_response_received")
                .and_event_data_contains("stratum", stratum.to_string())
                .and_event_data_contains("transmit_timestamp", RESPONDER_TRANSMIT_UNIX_SECS)
                .respond_with_actions(serde_json::json!([{"type": "analyze_response"}]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("Query the NTP server at")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": open_client_addr,
                    "protocol": "NTP",
                    "instruction": "Ask for the time once and report the reply"
                }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        assert_eq!(client.protocol, "NTP", "Client should be NTP protocol");

        client.wait_for_mocks(30).await;
        let verified = client.verify_mocks().await;
        let answered = responder.queries.load(Ordering::SeqCst);
        if verified.is_err() {
            println!(
                "NTP client output ({} queries answered): {:?}",
                answered,
                client.get_output().await
            );
        }
        client.stop().await?;
        verified?;
        Ok(answered)
    }

    /// The client queries a literal-IP server, reads the reply, and hands its timestamps to
    /// the model. One `query_time` puts exactly one request on the wire.
    #[tokio::test]
    async fn test_ntp_client_query_time_server() -> E2EResult<()> {
        let responder = start_ntp_responder(2).await?;
        let answered = query_through_client(responder.addr.to_string(), &responder, 2).await?;
        assert_eq!(
            answered, 1,
            "one query_time must send exactly one request to the responder"
        );
        Ok(())
    }

    /// The stratum in the server's reply reaches the model unchanged.
    #[tokio::test]
    async fn test_ntp_client_stratum_analysis() -> E2EResult<()> {
        let responder = start_ntp_responder(3).await?;
        let answered = query_through_client(responder.addr.to_string(), &responder, 3).await?;
        assert!(answered >= 1, "the responder never received a query");
        Ok(())
    }

    /// A `host:port` target is resolved: `localhost:<port>` reaches the responder on
    /// 127.0.0.1, even where `localhost` resolves to `::1` first.
    #[tokio::test]
    async fn test_ntp_client_resolves_hostname_target() -> E2EResult<()> {
        let responder = start_ntp_responder(2).await?;
        let target = format!("localhost:{}", responder.addr.port());
        let answered = query_through_client(target, &responder, 2).await?;
        assert_eq!(
            answered,
            1,
            "the query for localhost:{} never reached the responder on 127.0.0.1",
            responder.addr.port()
        );
        Ok(())
    }
}
