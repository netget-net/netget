//! E2E tests for the USB CDC ACM Serial server.
//!
//! These drive a real USB/IP client over TCP — `OP_REQ_IMPORT` followed by bulk OUT and bulk IN
//! URBs — so a passing test means bytes actually crossed the virtual serial port, not merely
//! that an event fired. That matters here: the previous version of this server registered the
//! connection and then logged `"placeholder - full USB/IP integration needed"`, so a test that
//! only checked "did an event happen" would have been the only thing standing between a stub
//! and a green suite.
//!
//! No `usbip` kernel module, no root, no `/dev/ttyACM0`: the USB/IP protocol is spoken directly
//! over the loopback socket. Attaching from a real Linux host is the one path these tests
//! cannot cover.

#[cfg(all(unix, feature = "libusb"))]
mod usb_serial_e2e {
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Log line the server emits after each LLM call on a serial connection.
    const LLM_CALL_LOG: &str = "USB serial LLM call completed for connection";

    const USBIP_VERSION: u16 = 0x0111;
    const OP_REQ_IMPORT: u16 = 0x8003;
    const USBIP_CMD_SUBMIT: u32 = 0x0001;

    /// USB/IP wire direction. Note this is *not* rusb's `Direction`, whose discriminants are
    /// the other way round.
    const DIR_OUT: u32 = 0;
    const DIR_IN: u32 = 1;

    /// The CDC ACM endpoint numbers, from `UsbCdcAcmHandler::endpoints()`: bulk IN is 0x82 and
    /// bulk OUT is 0x02, i.e. endpoint 2 in both directions.
    const BULK_EP: u32 = 2;
    const BULK_MAX_PACKET: u32 = 512;

    /// A minimal USB/IP client: enough of the protocol to import the device and push URBs.
    struct UsbIpClient {
        stream: TcpStream,
        seqnum: u32,
    }

    impl UsbIpClient {
        /// Connect and import the exported device (bus id `0-0-0`, as set by
        /// `usbip::UsbDevice::new`).
        async fn attach(port: u16) -> E2EResult<Self> {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;

            let mut req = Vec::new();
            req.extend_from_slice(&USBIP_VERSION.to_be_bytes());
            req.extend_from_slice(&OP_REQ_IMPORT.to_be_bytes());
            req.extend_from_slice(&0u32.to_be_bytes()); // status
            let mut busid = [0u8; 32];
            busid[..5].copy_from_slice(b"0-0-0");
            req.extend_from_slice(&busid);
            stream.write_all(&req).await?;
            stream.flush().await?;

            // OP_REP_IMPORT: 8-byte header + the 312-byte device struct.
            let mut rep = [0u8; 320];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut rep))
                .await
                .map_err(|_| "timed out waiting for OP_REP_IMPORT")??;

            let status = u32::from_be_bytes([rep[4], rep[5], rep[6], rep[7]]);
            if status != 0 {
                return Err(format!("OP_REP_IMPORT failed with status {}", status).into());
            }

            Ok(Self { stream, seqnum: 0 })
        }

        /// Submit one URB and return the transfer buffer the device answered with.
        async fn submit(
            &mut self,
            ep: u32,
            direction: u32,
            transfer_buffer_length: u32,
            setup: [u8; 8],
            data: &[u8],
        ) -> E2EResult<Vec<u8>> {
            self.seqnum += 1;

            let mut cmd = Vec::new();
            cmd.extend_from_slice(&USBIP_CMD_SUBMIT.to_be_bytes());
            cmd.extend_from_slice(&self.seqnum.to_be_bytes());
            cmd.extend_from_slice(&0u32.to_be_bytes()); // devid
            cmd.extend_from_slice(&direction.to_be_bytes());
            cmd.extend_from_slice(&ep.to_be_bytes());
            cmd.extend_from_slice(&0u32.to_be_bytes()); // transfer_flags
            cmd.extend_from_slice(&transfer_buffer_length.to_be_bytes());
            cmd.extend_from_slice(&0u32.to_be_bytes()); // start_frame
            cmd.extend_from_slice(&0u32.to_be_bytes()); // number_of_packets
            cmd.extend_from_slice(&0u32.to_be_bytes()); // interval
            cmd.extend_from_slice(&setup);
            if direction == DIR_OUT {
                cmd.extend_from_slice(data);
            }
            self.stream.write_all(&cmd).await?;
            self.stream.flush().await?;

            // USBIP_RET_SUBMIT: 20-byte basic header + 28 bytes of fields and padding.
            let mut hdr = [0u8; 48];
            tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut hdr))
                .await
                .map_err(|_| "timed out waiting for USBIP_RET_SUBMIT")??;

            let status = i32::from_be_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
            if status != 0 {
                return Err(format!("USBIP_RET_SUBMIT reported status {}", status).into());
            }

            let actual_length = u32::from_be_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]) as usize;
            if direction == DIR_OUT {
                if actual_length != data.len() {
                    return Err(format!(
                        "device acknowledged {} of {} bytes written",
                        actual_length,
                        data.len()
                    )
                    .into());
                }
                return Ok(Vec::new());
            }

            let mut payload = vec![0u8; actual_length];
            if !payload.is_empty() {
                tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut payload))
                    .await
                    .map_err(|_| "timed out reading the URB transfer buffer")??;
            }
            Ok(payload)
        }

        /// Write bytes to the port, as a host would.
        async fn write_serial(&mut self, data: &[u8]) -> E2EResult<()> {
            self.submit(BULK_EP, DIR_OUT, data.len() as u32, [0u8; 8], data)
                .await?;
            Ok(())
        }

        /// Read whatever the device has queued right now (possibly nothing).
        async fn read_serial(&mut self) -> E2EResult<Vec<u8>> {
            self.submit(BULK_EP, DIR_IN, BULK_MAX_PACKET, [0u8; 8], &[])
                .await
        }

        /// Poll the bulk IN endpoint until the device produces something, as a real host does.
        async fn read_serial_until_data(&mut self, timeout: Duration) -> E2EResult<Vec<u8>> {
            let deadline = std::time::Instant::now() + timeout;
            loop {
                let data = self.read_serial().await?;
                if !data.is_empty() {
                    return Ok(data);
                }
                if std::time::Instant::now() >= deadline {
                    return Err("device sent nothing on the bulk IN endpoint".into());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        /// CDC `GET_LINE_CODING`: device-to-host, class request, interface recipient.
        async fn get_line_coding(&mut self) -> E2EResult<Vec<u8>> {
            let setup = [0xA1, 0x21, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00];
            self.submit(0, DIR_IN, 7, setup, &[]).await
        }
    }

    /// Startup mock shared by every test: the model opens a USB serial server on a free port.
    fn open_server_actions(instruction: &str) -> serde_json::Value {
        serde_json::json!([
            {
                "type": "open_server",
                "port": 0,
                "base_stack": "USB-Serial",
                "instruction": instruction
            }
        ])
    }

    /// The port greets the host on attach, and the host reads the greeting.
    ///
    /// LLM calls: 2 (startup, attach)
    #[tokio::test]
    async fn test_usb_serial_attach_and_send_data() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Create a USB serial port on port {AVAILABLE_PORT}. Send a banner when attached."
                .to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("usb_serial_attached")
                .respond_with_actions(serde_json::json!([
                    { "type": "send_data", "data": "READY\r\n" }
                ]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("USB serial")
                .respond_with_actions(open_server_actions("Send a banner when attached"))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB serial server should be running");

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(LLM_CALL_LOG, 10).await?;

        let banner = client
            .read_serial_until_data(Duration::from_secs(5))
            .await?;
        assert_eq!(
            String::from_utf8_lossy(&banner),
            "READY\r\n",
            "the host must read exactly what send_data queued"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The host writes, the handler answers: `usb_serial_data_received` end to end.
    ///
    /// LLM calls: 3 (startup, attach, data received)
    #[tokio::test]
    async fn test_usb_serial_echo() -> E2EResult<()> {
        let config =
            NetGetConfig::new("Create a USB serial port. Answer PING with PONG.".to_string())
                .with_mock(|mock| {
                    mock.on_event("usb_serial_data_received")
                        .and_event_data_contains("data", "PING")
                        .respond_with_actions(serde_json::json!([
                            { "type": "send_data", "data": "PONG\r\n" }
                        ]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_serial_attached")
                        .respond_with_actions(serde_json::json!([
                            { "type": "wait_for_more" }
                        ]))
                        .expect_calls(1)
                        .and()
                        .on_instruction_containing("USB serial")
                        .respond_with_actions(open_server_actions("Answer PING with PONG"))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(LLM_CALL_LOG, 10).await?;

        // Nothing queued yet: the attach handler chose wait_for_more.
        assert!(
            client.read_serial().await?.is_empty(),
            "wait_for_more must not put anything on the wire"
        );

        client.write_serial(b"PING\n").await?;

        let reply = client
            .read_serial_until_data(Duration::from_secs(5))
            .await?;
        assert_eq!(
            String::from_utf8_lossy(&reply),
            "PONG\r\n",
            "the host write must reach the handler and its answer must come back"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// `set_line_coding` must change what the port reports to a host that asks.
    ///
    /// LLM calls: 2 (startup, attach)
    #[tokio::test]
    async fn test_usb_serial_line_coding() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Create a USB serial port. Set the baud rate to 9600 when attached.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("usb_serial_attached")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "set_line_coding",
                        "baud_rate": 9600,
                        "data_bits": 8,
                        "parity": "none",
                        "stop_bits": 1
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("USB serial")
                .respond_with_actions(open_server_actions("Set baud rate to 9600"))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(LLM_CALL_LOG, 10).await?;

        let coding = client.get_line_coding().await?;
        assert_eq!(
            coding.len(),
            7,
            "GET_LINE_CODING returns a 7-byte structure"
        );

        let baud = u32::from_le_bytes([coding[0], coding[1], coding[2], coding[3]]);
        assert_eq!(
            baud, 9600,
            "the host must see the baud rate the handler set"
        );
        assert_eq!(coding[4], 0, "1 stop bit encodes as 0");
        assert_eq!(coding[5], 0, "no parity encodes as 0");
        assert_eq!(coding[6], 8, "8 data bits");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Closing the USB/IP session must raise `usb_serial_detached`.
    ///
    /// LLM calls: 3 (startup, attach, detach)
    #[tokio::test]
    async fn test_usb_serial_detach() -> E2EResult<()> {
        let config =
            NetGetConfig::new("Create a USB serial port. Log when the host detaches.".to_string())
                .with_mock(|mock| {
                    mock.on_event("usb_serial_detached")
                        .respond_with_actions(serde_json::json!([
                            { "type": "show_message", "message": "Serial port detached" }
                        ]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_serial_attached")
                        .respond_with_actions(serde_json::json!([
                            { "type": "wait_for_more" }
                        ]))
                        .expect_calls(1)
                        .and()
                        .on_instruction_containing("USB serial")
                        .respond_with_actions(open_server_actions("Log when detached"))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(config).await?;

        let client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(LLM_CALL_LOG, 10).await?;

        // Detach: drop the USB/IP session.
        drop(client);

        // Two LLM calls on this connection: attach, then detach.
        server.wait_for_log_count(LLM_CALL_LOG, 2, 10).await?;
        server
            .wait_for_log("USB serial host detached on connection", 10)
            .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A line configuration the wire cannot carry must be refused, not wrapped into one it can.
    ///
    /// `baud_rate` was read as `as_u64()? as u32` and `data_bits` as `as_u64()? as u8`, both of
    /// which wrap in silence: `baud_rate: 5000000000` became 705032704 and `data_bits: 264`
    /// became 8. The port then reported a configuration to the host through GET_LINE_CODING
    /// that no one had asked for, and nothing in the log said a value had been altered.
    #[tokio::test]
    async fn a_line_coding_that_does_not_fit_the_wire_is_refused() {
        use ::netget::llm::actions::Server;
        use ::netget::server::usb::serial::actions::UsbSerialProtocol;

        let protocol = UsbSerialProtocol::new();

        for (label, action) in [
            (
                "baud_rate past 32 bits",
                serde_json::json!({"type": "set_line_coding", "baud_rate": 5_000_000_000u64}),
            ),
            (
                "baud_rate of zero",
                serde_json::json!({"type": "set_line_coding", "baud_rate": 0}),
            ),
            (
                "data_bits past a byte",
                serde_json::json!({
                    "type": "set_line_coding", "baud_rate": 115200, "data_bits": 264
                }),
            ),
            (
                "data_bits the class does not define",
                serde_json::json!({
                    "type": "set_line_coding", "baud_rate": 115200, "data_bits": 9
                }),
            ),
        ] {
            assert!(
                protocol.execute_action(action).is_err(),
                "{label}: must be refused rather than silently narrowed"
            );
        }

        // The ordinary case must still get past the range check -- a guard that refused
        // everything would satisfy the loop above. No port is attached, so this fails at
        // handler resolution, which is after the checks being pinned.
        let err = protocol
            .execute_action(serde_json::json!({
                "type": "set_line_coding", "baud_rate": 115200, "data_bits": 8,
                "parity": "none", "stop_bits": 1
            }))
            .expect_err("no port is attached in this test");
        let message = format!("{err}");
        assert!(
            !message.contains("baud_rate") && !message.contains("data_bits"),
            "a valid line coding must not be refused by the range checks: {message}"
        );
    }
}
