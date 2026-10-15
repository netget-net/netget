//! A TCP handshake is not an attachment, and must cost nothing.
//!
//! # The defect
//!
//! Every USB server used to make its `*_attached` LLM call the moment `accept()` returned —
//! before the peer had sent a byte. USB/IP authenticates nothing (`OP_REQ_IMPORT` carries a bus
//! id and no credential), so `nc <host> <port>` bought a model round-trip from a three-packet
//! TCP handshake, and closing the socket bought a second one for `*_detached`. Anything that
//! scans a port — a health check, a monitoring probe, `nmap` — spent the operator's model
//! budget without ever speaking the protocol.
//!
//! The screen in `src/server/usb/guard.rs` already reads and classifies every inbound message,
//! so it is the one place that knows when a peer has actually asked to import a device. It
//! fires a `oneshot` on the first admitted `OP_REQ_IMPORT` and the attach event hangs off that.
//! `OP_REQ_DEVLIST` deliberately does not fire it: listing what a host exports is not attaching
//! to it, and it is exactly the enumeration a scanner would do.
//!
//! # Why the test is shaped like this
//!
//! Proving a *negative* about an asynchronous system needs a control, or a zero is
//! indistinguishable from a mock nobody reached. So the same test does both halves against one
//! server: three bare connects that say nothing, then one real import, then the count. The
//! import is the control — it proves the attach path is alive and reachable, which is what
//! makes the preceding zero mean something. Before the fix the total would be 7 rather than 2
//! (startup + three attaches + three detaches + the import's attach); after it, exactly 2.
//!
//! The import also orders the measurement: the bare connects were made *first*, so any call
//! they were going to provoke had its chance before the import's did. The short settle
//! afterwards is a backstop against a call still in flight, not the assertion's only defence.

#[cfg(all(unix, feature = "libusb"))]
mod usb_keyboard_attach_on_import {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// Emitted after the attach LLM call returns — the post-call line, so waiting on it does
    /// not race the mock's own bookkeeping.
    const ATTACH_LOG: &str = "USB keyboard LLM call completed for connection";

    /// Emitted on `accept()`, before anything has been read. Waiting on it proves the server
    /// saw the bare connection, which is the thing being asserted to be free.
    const ACCEPTED_LOG: &str = "USB/IP connection";

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
                .expect_calls(1)
                .and()
                .on_event("usb_keyboard_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
        })
    }

    #[tokio::test]
    async fn a_bare_tcp_connect_costs_no_llm_call_and_an_import_costs_one() -> E2EResult<()> {
        let mut server = start_netget_server(config()).await?;
        assert!(server.is_running(), "USB keyboard server should be running");
        wait_for_server_listening(&server, Duration::from_secs(20)).await?;

        let baseline = server
            .llm_call_count()
            .await
            .expect("this suite runs against the mock model");

        // Three peers that complete a TCP handshake and say nothing — a port scan, a health
        // check, `nc`. One of them writes a byte that is not USB/IP at all, because "sent
        // nothing" and "sent nothing the protocol recognises" must both be free.
        for i in 0..3 {
            let mut probe = TcpStream::connect(("127.0.0.1", server.port)).await?;
            if i == 2 {
                probe.write_all(b"\n").await?;
                probe.flush().await?;
            }
            // The server must have *seen* it, or the zero below is about a connection that
            // never arrived rather than about one that cost nothing.
            server.wait_for_log(ACCEPTED_LOG, 20).await?;
            drop(probe);
        }

        // The control: a real `OP_REQ_IMPORT`. This is the peer asking for the device, and it
        // is the one thing here that should cost a call.
        let mut client = UsbIpClient::connect(server.port).await?;
        let devices = client.list_devices().await?;
        assert_eq!(
            devices.len(),
            1,
            "the server must still export its device after three silent connections"
        );
        assert_eq!(
            server.llm_call_count().await.unwrap(),
            baseline,
            "OP_REQ_DEVLIST is enumeration, not attachment, and must also be free"
        );

        client.import("0-0-0").await?;
        server.wait_for_log(ATTACH_LOG, 20).await?;

        // A backstop against a call still in flight; the ordering above is the real argument.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let after = server.llm_call_count().await.unwrap();
        assert_eq!(
            after,
            baseline + 1,
            "exactly one model call may follow: the import's attach. {} extra call(s) means a \
             bare TCP connect, a stray byte or a devlist is still buying a model round-trip on \
             a protocol that authenticates nothing.",
            after.saturating_sub(baseline + 1)
        );

        drop(client);
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
