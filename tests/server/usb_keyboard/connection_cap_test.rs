//! A USB server admits a bounded number of connections, and says so in the log.
//!
//! # Why the USB family needed this separately
//!
//! `src/server/accept_bounded.rs` landed with 37 adopters and none of them was a USB server, so
//! all six accepted without limit. A USB/IP connection is not a request: each one costs a
//! `usbip::UsbIpServer`, a live `UsbInterfaceHandler` with its own session state, an `AppState`
//! connection entry and up to `MAX_TRANSFER_BUFFER_BYTES` in flight — and none of that is behind
//! any authentication, because USB/IP has none. So the per-connection bounds the screen already
//! applies were "bounded per connection" rather than "bounded", exactly as that module's own
//! docs describe.
//!
//! # What the refusal looks like, and why it is silence
//!
//! USB/IP has no "busy" message. Its only server-to-client messages are `OP_REP_DEVLIST`,
//! `OP_REP_IMPORT` and the URB replies, each a positive assertion about a device, and a peer
//! that has only completed a TCP handshake has asked no question to answer. So the refusal is a
//! plain close — `accept_bounded`'s empty-slice arm — and the reason lives in the log under the
//! `decision=fail_closed_connection_cap` tag this project greps for.
//!
//! # The three things asserted, because one of them alone would be satisfied by a bug
//!
//! 1. The connection past the cap is **closed**, promptly.
//! 2. The server is **still serving** — a cap that killed the listener or the process would
//!    satisfy (1) perfectly.
//! 3. Releasing one admitted connection **frees exactly one slot**. A permit dropped early
//!    un-caps the server silently; a permit never released wedges it shut after `MAX` peers have
//!    ever connected, which is far worse than no cap at all.

#[cfg(all(unix, feature = "libusb"))]
mod usb_keyboard_connection_cap {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    /// `src/server/usb/guard.rs::MAX_USBIP_CONNECTIONS`. Duplicated rather than imported
    /// because this suite compiles without `netget`'s USB modules in scope, and because a
    /// *deliberate* copy is the point: if the constant moves, this test should be re-read, not
    /// silently follow it.
    const MAX_USBIP_CONNECTIONS: usize = 32;

    const REFUSAL_TAG: &str = "decision=fail_closed_connection_cap";

    fn config() -> NetGetConfig {
        NetGetConfig::new("Create a USB keyboard.".to_string()).with_mock(|mock| {
            mock.on_instruction_containing("USB keyboard")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Keyboard",
                    "instruction": "Type 'x' when a host attaches"
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_keyboard_attached")
                .respond_with_actions(serde_json::json!([
                    {"type": "type_text", "text": "x"}
                ]))
                .expect_at_least(0)
                .and()
                .on_event("usb_keyboard_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
        })
    }

    /// Is this socket closed by the far end within `secs`?
    async fn closed_by_peer(stream: &mut TcpStream, secs: u64) -> bool {
        let mut buf = [0u8; 8];
        match tokio::time::timeout(Duration::from_secs(secs), stream.read(&mut buf)).await {
            // A clean close, or a reset. Both are the refusal.
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn the_connection_past_the_cap_is_closed_and_the_slot_comes_back() -> E2EResult<()> {
        let mut server = start_netget_server(config()).await?;
        assert!(server.is_running(), "USB keyboard server should be running");
        wait_for_server_listening(&server, Duration::from_secs(20)).await?;

        let baseline = server
            .llm_call_count()
            .await
            .expect("this suite runs against the mock model");

        // Fill the cap. These peers say nothing, which is the cheapest way to hold a slot and
        // the reason a cap is needed at all.
        let mut held = Vec::with_capacity(MAX_USBIP_CONNECTIONS);
        for i in 0..MAX_USBIP_CONNECTIONS {
            held.push(
                TcpStream::connect(("127.0.0.1", server.port))
                    .await
                    .map_err(|e| format!("connection {i} of the cap was refused: {e}"))?,
            );
        }

        // (1) One more must be refused. `connect` itself still succeeds — the listen backlog
        // completes the handshake before our accept loop ever sees it, which is precisely why
        // the refusal has to be observable as a *close* rather than as a connect error.
        let mut over = TcpStream::connect(("127.0.0.1", server.port)).await?;
        assert!(
            closed_by_peer(&mut over, 20).await,
            "the connection past the cap of {MAX_USBIP_CONNECTIONS} was neither answered nor \
             closed. Unbounded, it would simply have been served."
        );
        server.wait_for_log(REFUSAL_TAG, 20).await?;

        // (3) Give a slot back and take it again. Two failures hide here: a permit released
        // early (the cap does nothing) and a permit never released (the server wedges shut
        // after MAX peers have *ever* connected, which is worse than no cap).
        drop(held.pop().expect("the cap is not zero"));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let readmitted = loop {
            // `connect` itself can fail with ECONNRESET here: the refusal shuts the socket down
            // from the far end, and macOS reports that to a connect racing it. That is the
            // refusal, not a test error.
            if let Ok(mut candidate) = TcpStream::connect(("127.0.0.1", server.port)).await {
                if !closed_by_peer(&mut candidate, 2).await {
                    break candidate;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "the slot freed by a closed connection never came back: the \
                            connection permit is not being released"
                        .into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        // (2) The control. A refusal that took the listener or the process with it would have
        // satisfied everything above.
        //
        // Retried rather than attempted once: the 32 sessions just dropped take a moment to
        // wind up (the screen waits on the crate side before returning, and only then is the
        // permit released), so a control connection made immediately is refused *correctly* and
        // would report the cap as a broken listener. This is the same release delay asserted in
        // (3), seen from the other side.
        drop(readmitted);
        drop(held);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let devices = loop {
            match UsbIpClient::connect(server.port).await {
                Ok(mut client) => match client.list_devices().await {
                    Ok(devices) => break devices,
                    // Refused: a closed socket, or a reset on the read. Both mean the slots have
                    // not all come back yet.
                    Err(_) => {}
                },
                Err(_) => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err("the server stopped answering OP_REQ_DEVLIST after refusing a                             connection: the cap took the listener with it"
                    .into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        assert_eq!(
            devices.len(),
            1,
            "the server must still export its device after refusing a connection"
        );

        assert_eq!(
            server.llm_call_count().await.unwrap(),
            baseline,
            "none of {} connections spoke USB/IP, so none of them may cost a model call",
            MAX_USBIP_CONNECTIONS + 2
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
