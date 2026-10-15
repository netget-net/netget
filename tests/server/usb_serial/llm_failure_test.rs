//! What a serial host gets when the LLM backend fails.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. Every event
//! the protocol raises then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! A serial port has no request/response framing, so there is no reply to fail with an error
//! code the way DNS fails with SERVFAIL. It does have a notification channel: CDC PSTN 1.2
//! §6.5.4's `SERIAL_STATE`, sent on the interrupt IN endpoint, whose `bOverRun` bit means
//! *"received data has been discarded due to overrun in the device"*. That is precisely what
//! happened — the host wrote, nobody could answer, the bytes are gone — so that is what the port
//! now says. A Linux `cdc-acm` host counts it as a receive overrun on the tty.
//!
//! Silence is the alternative and it is the wrong one here: a port that says nothing is
//! indistinguishable from a port with nothing to say, so an outage would look exactly like a
//! quiet peer.
//!
//! Only `usb_serial_data_received` earns a notification. `attached` has had nothing written to
//! it yet and by `detached` the port is gone; both log and stop.
//!
//! ## Wire detail worth knowing
//!
//! The notification is 10 bytes and the interrupt endpoint's `wMaxPacketSize` is **8** (from the
//! `usbip` crate's CDC endpoint table). So it crosses as two packets, 8 then 2, and the host
//! reassembles — which is what a real host does and what this test does below. A single URB
//! returning all 10 bytes would be a protocol violation, not a convenience.

#[cfg(all(unix, feature = "libusb"))]
mod usb_serial_llm_failure {
    use crate::helpers::usbip_client::{UsbIpClient, DIR_IN};
    use crate::helpers::*;
    use std::time::Duration;

    /// The dual-logged ERROR the LLM-failure path emits.
    const LLM_FAILURE_LOG: &str = "LLM call failed for USB serial connection";
    /// Emitted *after* the notification has been queued.
    const OVERRUN_LOG: &str = "queued a SERIAL_STATE overrun notification";

    /// CDC ACM endpoint numbers, from `UsbCdcAcmHandler::endpoints()`: interrupt IN is 0x81
    /// (endpoint 1), bulk IN 0x82 and bulk OUT 0x02 (endpoint 2 both ways).
    const INTERRUPT_EP: u32 = 1;
    const INTERRUPT_MAX_PACKET: u32 = 8;
    const BULK_EP: u32 = 2;

    /// The bytes a `SERIAL_STATE` notification with `bOverRun` set must be, written out from
    /// CDC PSTN 1.2 rather than taken from netget's encoder:
    ///
    /// | field | value |
    /// |---|---|
    /// | `bmRequestType` | `0xA1` — device-to-host, class, interface |
    /// | `bNotification` | `0x20` — SERIAL_STATE |
    /// | `wValue` | 0 |
    /// | `wIndex` | 0 — the communications interface |
    /// | `wLength` | 2 |
    /// | UART state bitmap | `0x0040` — D6, `bOverRun` |
    const EXPECTED_NOTIFICATION: [u8; 10] =
        [0xA1, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x40, 0x00];

    /// Poll the interrupt IN endpoint until `want` bytes have been reassembled, the way a host
    /// does across `wMaxPacketSize` packets.
    async fn read_notification(
        client: &mut UsbIpClient,
        want: usize,
        timeout: Duration,
    ) -> E2EResult<Vec<u8>> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buffer = Vec::with_capacity(want);
        while buffer.len() < want {
            let chunk = client
                .submit(INTERRUPT_EP, DIR_IN, INTERRUPT_MAX_PACKET, [0u8; 8], &[])
                .await?;
            if chunk.is_empty() {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "port sent no CDC notification within {:?} (have {} of {} bytes)",
                        timeout,
                        buffer.len(),
                        want
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            assert!(
                chunk.len() as u32 <= INTERRUPT_MAX_PACKET,
                "an interrupt transfer must not exceed wMaxPacketSize ({} bytes), got {}",
                INTERRUPT_MAX_PACKET,
                chunk.len()
            );
            buffer.extend_from_slice(&chunk);
        }
        Ok(buffer)
    }

    #[tokio::test]
    async fn test_usb_serial_signals_overrun_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Create a USB serial port on port {AVAILABLE_PORT}.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB serial port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Serial",
                    "instruction": "Answer whatever the host writes"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for usb_serial_data_received: the mock answers 500, which is
            // what drives the server down its LLM-failure path.
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB serial server should be running");

        let mut client = UsbIpClient::attach(server.port)
            .await?
            .with_bulk_endpoints(BULK_EP, BULK_EP);

        // The attach event fails first. It gets no notification — nothing has been written to
        // the port yet — but it proves the backend really is unreachable.
        server.wait_for_log(LLM_FAILURE_LOG, 15).await?;

        // Before the write there must be nothing waiting on the notification endpoint, or the
        // assertion below would pass on an artefact of the attach failure.
        let idle = client
            .submit(INTERRUPT_EP, DIR_IN, INTERRUPT_MAX_PACKET, [0u8; 8], &[])
            .await?;
        assert!(
            idle.is_empty(),
            "the notification endpoint must be quiet before the host writes; got {:02x?}",
            idle
        );

        // The host writes. This is the event whose answer it is actually waiting for.
        client.bulk_out(b"PING\r\n").await?;
        server.wait_for_log(OVERRUN_LOG, 15).await?;

        let notification = read_notification(
            &mut client,
            EXPECTED_NOTIFICATION.len(),
            Duration::from_secs(10),
        )
        .await?;
        assert_eq!(
            notification,
            EXPECTED_NOTIFICATION.to_vec(),
            "the port must report SERIAL_STATE with bOverRun set; got {:02x?}",
            notification
        );

        // And it must not have invented anything to say on the data endpoint. Fabricating a
        // reply would be worse than the silence this replaced.
        let echoed = client.bulk_in(64).await?;
        assert!(
            echoed.is_empty(),
            "the port must not synthesise data when the model could not be reached; got {:02x?}",
            echoed
        );

        // Exactly one notification: a single failed write is a single overrun, not a stream.
        let extra = client
            .submit(INTERRUPT_EP, DIR_IN, INTERRUPT_MAX_PACKET, [0u8; 8], &[])
            .await?;
        assert!(
            extra.is_empty(),
            "one failed write must produce one notification; got a second: {:02x?}",
            extra
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
