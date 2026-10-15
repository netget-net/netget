//! The pre-auth allocation bomb `src/server/usb/guard.rs` exists to stop.
//!
//! `usbip` 0.9.0 reads `transfer_buffer_length` and `number_of_packets` off the wire and
//! allocates from both without a bound: `vec![0; transfer_buffer_length as usize]` and
//! `vec![0; 16 * number_of_packets as usize]`. USB/IP authenticates nothing — `OP_REQ_IMPORT`
//! carries a bus id and no credential — so **forty-eight bytes from an unimported peer** are
//! enough to ask for 4 GiB.
//!
//! These tests send exactly those forty-eight bytes and nothing else: no payload follows, which
//! is the point. Without the guard the crate allocates the whole declared length and then parks
//! in `read_exact` waiting for bytes that never come, so the connection stays open, nothing is
//! logged, and the memory is gone for as long as the peer cares to hold the socket. With it,
//! the screen decides from the number the peer *announced*, closes, and says why.
//!
//! The third connection is the control. A refusal that killed the process, or the listener,
//! would satisfy every other assertion here — so the last thing each test does is enumerate
//! the device over a fresh connection.

#[cfg(all(unix, feature = "libusb"))]
mod usb_msc_guard {
    use crate::helpers::server::NetGetServer;
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// The `decision=` tags `Refusal::decision_tag` promises an operator.
    const OVERSIZED_URB_TAG: &str = "decision=fail_closed_oversized_urb";
    const OVERSIZED_ISO_TAG: &str = "decision=fail_closed_oversized_iso";

    /// A `USBIP_CMD_SUBMIT` header, the 48 bytes that precede any payload.
    ///
    /// Built by hand rather than through `helpers::usbip_client`: the helper only produces
    /// headers whose declared lengths match the bytes it goes on to send, which is exactly the
    /// invariant under attack here.
    fn cmd_submit_header(transfer_buffer_length: u32, number_of_packets: u32) -> [u8; 48] {
        let mut h = [0u8; 48];
        h[0..4].copy_from_slice(&0x0000_0001u32.to_be_bytes()); // USBIP_CMD_SUBMIT
        h[4..8].copy_from_slice(&1u32.to_be_bytes()); // seqnum
        h[8..12].copy_from_slice(&0u32.to_be_bytes()); // devid
        h[12..16].copy_from_slice(&0u32.to_be_bytes()); // direction: OUT, so a payload follows
        h[16..20].copy_from_slice(&1u32.to_be_bytes()); // ep
        h[20..24].copy_from_slice(&0u32.to_be_bytes()); // transfer_flags
        h[24..28].copy_from_slice(&transfer_buffer_length.to_be_bytes());
        h[28..32].copy_from_slice(&0u32.to_be_bytes()); // start_frame
        h[32..36].copy_from_slice(&number_of_packets.to_be_bytes());
        h[36..40].copy_from_slice(&0u32.to_be_bytes()); // interval
        h // setup[8] stays zero
    }

    /// Mock covering the startup instruction and every event an MSC connection can raise.
    ///
    /// **Every per-connection rule expects zero calls, and that is now an assertion rather than
    /// bookkeeping.** Nothing in these tests sends `OP_REQ_IMPORT`, and the attach event follows
    /// the import rather than the accept, so a peer that opens a socket and fires one malformed
    /// URB header must cost the operator no model budget at all — not one call for attaching,
    /// not one for detaching, and not one for the refused URB, which never reaches
    /// `UsbInterfaceHandler::handle_urb`.
    fn guard_config() -> NetGetConfig {
        NetGetConfig::new_no_scripts("Pretend to be a USB drive.".to_string()).with_mock(|mock| {
            mock.on_instruction_containing("USB drive")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-MassStorage",
                    "instruction": "Serve one file"
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_msc_attached")
                .respond_with_actions(serde_json::json!([{
                    "type": "serve_files",
                    "volume_label": "GUARD",
                    "files": [{"name": "a.txt", "content": "x"}]
                }]))
                .expect_calls(0)
                .and()
                .on_event("usb_msc_detached")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "detached" }
                ]))
                .expect_calls(0)
                .and()
                .on_event("usb_msc_read")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(0)
                .and()
                .on_event("usb_msc_write")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(0)
                .and()
        })
    }

    /// Connect and send `bytes` — nothing else. No `OP_REQ_IMPORT`, which is the point: this is
    /// what a peer that has never asked for the device can do.
    ///
    /// This used to wait for the attach LLM call first, because one arrived on every TCP
    /// connection. It no longer does, and the mock above asserts that.
    async fn connect_and_send(server: &NetGetServer, bytes: &[u8]) -> E2EResult<TcpStream> {
        let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
        stream.write_all(bytes).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// The server must close the connection, and it must do so without the payload arriving.
    async fn assert_closed(mut stream: TcpStream, what: &str) -> E2EResult<()> {
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(std::time::Duration::from_secs(20), stream.read(&mut buf))
            .await
            .map_err(|_| {
                format!(
                    "{what}: the server neither answered nor closed within 20s. Unguarded, \
                     `usbip` allocates the declared length and parks in read_exact, which is \
                     exactly this: a held socket and a held allocation."
                )
            })?;
        match read {
            // Ok(0) is a clean close; an error here is a reset, which is the same refusal.
            Ok(0) | Err(_) => Ok(()),
            Ok(n) => Err(format!(
                "{what}: expected the connection to be closed, got {n} byte(s): {:?}",
                &buf[..n]
            )
            .into()),
        }
    }

    /// The control: the listener and the process both survive a refusal.
    async fn assert_still_serving(server: &NetGetServer) -> E2EResult<()> {
        let mut client = UsbIpClient::connect(server.port).await?;
        let devices = client.list_devices().await?;
        assert_eq!(
            devices.len(),
            1,
            "the server must still export its device after refusing a connection"
        );
        Ok(())
    }

    /// 48 bytes declaring a 4 GiB transfer buffer, with no payload behind them.
    ///
    /// LLM calls: 1 (startup, and nothing else — neither connection imports a device).
    #[tokio::test]
    async fn test_oversized_transfer_buffer_is_refused_before_allocation() -> E2EResult<()> {
        let mut server = start_netget_server(guard_config()).await?;
        assert!(server.is_running(), "USB MSC server should be running");
        wait_for_server_listening(&server, std::time::Duration::from_secs(20)).await?;

        let header = cmd_submit_header(u32::MAX, 0);
        let stream = connect_and_send(&server, &header).await?;

        server.wait_for_log(OVERSIZED_URB_TAG, 20).await?;
        assert_closed(stream, "oversized transfer buffer").await?;

        assert_still_serving(&server).await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The second allocation in the same function: `16 * number_of_packets`.
    ///
    /// `0xFFFFFFFE` is used rather than `0xFFFFFFFF`, because that value and `0` are the two
    /// the protocol defines as "not isochronous" and both are exempt by design.
    ///
    /// LLM calls: 1 (startup, and nothing else — neither connection imports a device).
    #[tokio::test]
    async fn test_oversized_iso_descriptor_count_is_refused() -> E2EResult<()> {
        let mut server = start_netget_server(guard_config()).await?;
        assert!(server.is_running(), "USB MSC server should be running");
        wait_for_server_listening(&server, std::time::Duration::from_secs(20)).await?;

        // A transfer buffer the screen would admit, so the refusal can only be the ISO count.
        let header = cmd_submit_header(0, 0xFFFF_FFFE);
        let stream = connect_and_send(&server, &header).await?;

        server.wait_for_log(OVERSIZED_ISO_TAG, 20).await?;
        assert_closed(stream, "oversized ISO descriptor count").await?;

        assert_still_serving(&server).await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
