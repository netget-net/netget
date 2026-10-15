//! E2E tests for the USB Smart Card (CCID) server.
//!
//! These drive a real USB/IP client over TCP — `OP_REQ_IMPORT` followed by bulk OUT and bulk
//! IN URBs carrying CCID messages — and assert the **response bytes**: the ATR that
//! `PC_to_RDR_IccPowerOn` returns, the response APDU that `PC_to_RDR_XfrBlock` returns, and
//! the slot status when there is no card. A stub cannot pass them.
//!
//! That matters here: the previous version of this protocol was `Incomplete`, its `spawn`
//! was `bail!("not yet implemented")`, and its whole test file was `#[ignore]`d — so nothing
//! in the suite would have noticed either way.
//!
//! No `usbip` kernel module, no root, no `pcscd`, no `vpcd`: the USB/IP protocol is spoken
//! directly over the loopback socket. Attaching from a real Linux host is the one path these
//! tests cannot cover.

#[cfg(all(unix, feature = "libusb"))]
mod usb_smartcard_e2e {
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Log line the server emits after each LLM call on a smart card connection.
    const ATTACH_LOG: &str = "USB smart card LLM call completed for connection";

    const USBIP_VERSION: u16 = 0x0111;
    const OP_REQ_IMPORT: u16 = 0x8003;
    const USBIP_CMD_SUBMIT: u32 = 0x0001;

    /// USB/IP wire direction. Note this is *not* rusb's `Direction`, whose discriminants are
    /// the other way round.
    const DIR_OUT: u32 = 0;
    const DIR_IN: u32 = 1;

    /// The CCID bulk endpoints, from `UsbCcidHandler::endpoints()`: bulk IN is 0x82 and bulk
    /// OUT is 0x02, i.e. endpoint 2 in both directions. 64-byte packets, as on a full-speed
    /// reader — so a long response arrives over several URBs and has to be reassembled.
    const BULK_EP: u32 = 2;
    const BULK_MAX_PACKET: u32 = 64;

    /// CCID message types (rev 1.1).
    const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
    const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
    const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;

    const CCID_HEADER_LEN: usize = 10;

    /// A CCID response message, parsed.
    #[derive(Debug)]
    struct CcidResponse {
        message_type: u8,
        seq: u8,
        /// `bStatus`: bits 0-1 are the ICC status, bits 6-7 the command status.
        status: u8,
        error: u8,
        data: Vec<u8>,
    }

    impl CcidResponse {
        fn icc_status(&self) -> u8 {
            self.status & 0x03
        }

        fn command_status(&self) -> u8 {
            (self.status >> 6) & 0x03
        }
    }

    /// A minimal USB/IP client: enough of the protocol to import the device and push URBs.
    struct UsbIpClient {
        stream: TcpStream,
        seqnum: u32,
        /// CCID `bSeq`, incremented per command so responses can be matched to commands.
        ccid_seq: u8,
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

            Ok(Self {
                stream,
                seqnum: 0,
                ccid_seq: 0,
            })
        }

        /// Submit one URB and return the transfer buffer the device answered with.
        async fn submit(
            &mut self,
            ep: u32,
            direction: u32,
            transfer_buffer_length: u32,
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
            cmd.extend_from_slice(&[0u8; 8]); // setup (unused for bulk)
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

        /// Send one CCID command on the bulk OUT endpoint and return its `bSeq`.
        async fn send_ccid(
            &mut self,
            message_type: u8,
            params: [u8; 3],
            payload: &[u8],
        ) -> E2EResult<u8> {
            self.ccid_seq = self.ccid_seq.wrapping_add(1);
            let seq = self.ccid_seq;

            let mut message = Vec::with_capacity(CCID_HEADER_LEN + payload.len());
            message.push(message_type);
            message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            message.push(0); // bSlot
            message.push(seq);
            message.extend_from_slice(&params);
            message.extend_from_slice(payload);

            self.submit(BULK_EP, DIR_OUT, message.len() as u32, &message)
                .await?;
            Ok(seq)
        }

        /// Poll the bulk IN endpoint until a complete CCID message has been reassembled.
        ///
        /// The reader uses 64-byte packets, so anything longer arrives in several URBs — the
        /// same way a real host would see it.
        async fn read_ccid(&mut self, timeout: Duration) -> E2EResult<CcidResponse> {
            let deadline = std::time::Instant::now() + timeout;
            let mut buffer: Vec<u8> = Vec::new();

            loop {
                let chunk = self.submit(BULK_EP, DIR_IN, BULK_MAX_PACKET, &[]).await?;
                if chunk.is_empty() {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "reader sent no CCID response within {:?} (have {} byte(s) so far)",
                            timeout,
                            buffer.len()
                        )
                        .into());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                buffer.extend_from_slice(&chunk);

                if buffer.len() < CCID_HEADER_LEN {
                    continue;
                }
                let declared =
                    u32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if buffer.len() < CCID_HEADER_LEN + declared {
                    continue;
                }

                return Ok(CcidResponse {
                    message_type: buffer[0],
                    seq: buffer[6],
                    status: buffer[7],
                    error: buffer[8],
                    data: buffer[CCID_HEADER_LEN..CCID_HEADER_LEN + declared].to_vec(),
                });
            }
        }

        /// `PC_to_RDR_IccPowerOn` — asks the card for its ATR.
        async fn power_on(&mut self) -> E2EResult<CcidResponse> {
            let seq = self
                .send_ccid(PC_TO_RDR_ICC_POWER_ON, [0x00, 0x00, 0x00], &[])
                .await?;
            let response = self.read_ccid(Duration::from_secs(5)).await?;
            assert_eq!(response.seq, seq, "CCID bSeq must be echoed back");
            Ok(response)
        }

        /// `PC_to_RDR_GetSlotStatus`.
        async fn slot_status(&mut self) -> E2EResult<CcidResponse> {
            let seq = self
                .send_ccid(PC_TO_RDR_GET_SLOT_STATUS, [0x00, 0x00, 0x00], &[])
                .await?;
            let response = self.read_ccid(Duration::from_secs(5)).await?;
            assert_eq!(response.seq, seq, "CCID bSeq must be echoed back");
            Ok(response)
        }

        /// `PC_to_RDR_XfrBlock` — sends a command APDU and waits for the response APDU.
        async fn transmit_apdu(&mut self, apdu: &[u8]) -> E2EResult<CcidResponse> {
            // bBWI = 0, wLevelParameter = 0 (short APDU level exchange).
            let seq = self
                .send_ccid(PC_TO_RDR_XFR_BLOCK, [0x00, 0x00, 0x00], apdu)
                .await?;
            let response = self.read_ccid(Duration::from_secs(10)).await?;
            assert_eq!(response.seq, seq, "CCID bSeq must be echoed back");
            Ok(response)
        }
    }

    /// Startup mock shared by every test: the model opens a smart card reader on a free port.
    fn open_server_actions(instruction: &str) -> serde_json::Value {
        serde_json::json!([
            {
                "type": "open_server",
                "port": 0,
                "base_stack": "usb-smartcard",
                "instruction": instruction,
                "startup_params": { "card_type": "generic" }
            }
        ])
    }

    /// The card powers up with the ATR the handler configured, answers an APDU with the body
    /// and status word the handler chose, and falls closed to `6F00` when the handler answers
    /// nothing -- **or answers without naming a status word**.
    ///
    /// That last case is the one worth stating plainly. `respond_to_apdu` defaulted `sw1`/`sw2`
    /// to `"90"`/`"00"` in two places, so
    /// `{"type": "respond_to_apdu", "data_text": "AUTH OK"}` put `AUTH OK 90 00` on the wire.
    /// This card carries a PIN and an RSA key, so that is an *omission* completing an
    /// authentication -- the OAuth2 fail-open shape the root `CLAUDE.md` calls the most
    /// dangerous pattern in this codebase, and the same defect `src/server/nfc/` had. Restore
    /// either default and this test fails with `41555448204F4B9000` on the wire.
    ///
    /// LLM calls: 6 (startup, reader_ready, attached, three APDUs)
    #[tokio::test]
    async fn test_usb_smartcard_atr_and_apdu_exchange() -> E2EResult<()> {
        // A distinctive ATR: 3B 8F 80 01 4E 65 74 47 65 74 ("NetGet" in the historical bytes),
        // long enough that the response spans more than one 64-byte URB is not needed, but
        // different enough from the default 3B901100 that a stub returning the default fails.
        const ATR_HEX: &str = "3B8F80014E6574476574";

        let config = NetGetConfig::new(
            "Create a USB smart card reader on port {AVAILABLE_PORT}. Answer SELECT with an \
             application label."
                .to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("usb_smartcard_reader_ready")
                .respond_with_actions(serde_json::json!([
                    { "type": "set_atr", "atr_hex": ATR_HEX }
                ]))
                .expect_calls(1)
                .and()
                .on_event("usb_smartcard_attached")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "Smart card host attached" }
                ]))
                .expect_calls(1)
                .and()
                // SELECT by AID: answer with a body and 9000.
                .on_event("usb_smartcard_apdu_received")
                .and_event_data_contains("ins_name", "SELECT_BY_AID")
                .respond_with_actions(serde_json::json!([
                    { "type": "respond_to_apdu", "data_text": "NetGet PIV", "sw1": "90", "sw2": "00" }
                ]))
                .expect_calls(1)
                .and()
                // VERIFY: the handler declines to answer at all, which must fail closed.
                .on_event("usb_smartcard_apdu_received")
                .and_event_data_contains("ins_name", "VERIFY")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "Refusing to answer VERIFY" }
                ]))
                .expect_calls(1)
                .and()
                // INTERNAL AUTHENTICATE: the handler answers with a body and *no status word
                // at all*. A card with a PIN and a key is an access-control device, so the
                // missing bytes must not be filled in with success.
                .on_event("usb_smartcard_apdu_received")
                .and_event_data_contains("ins", "88")
                .respond_with_actions(serde_json::json!([
                    { "type": "respond_to_apdu", "data_text": "AUTH OK" }
                ]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("smart card")
                .respond_with_actions(open_server_actions("Answer SELECT with an application label"))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        assert!(
            server.is_running(),
            "USB smart card server should be running"
        );

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // Power on: the reader must return the ATR the handler set, not the built-in default.
        let powered = client.power_on().await?;
        assert_eq!(
            powered.message_type, RDR_TO_PC_DATA_BLOCK,
            "IccPowerOn is answered by RDR_to_PC_DataBlock"
        );
        assert_eq!(
            powered.command_status(),
            0,
            "power-on must succeed with a card in the slot (bError {:#04x})",
            powered.error
        );
        assert_eq!(
            powered.icc_status(),
            0,
            "the card must report present and active after power-on"
        );
        assert_eq!(
            hex::encode_upper(&powered.data),
            ATR_HEX,
            "the host must see exactly the ATR set_atr configured"
        );

        // SELECT by AID for the PIV application: 00 A4 04 00 09 A0000003080000100 0
        let select = client
            .transmit_apdu(&[
                0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
                0x00,
            ])
            .await?;
        assert_eq!(
            select.message_type, RDR_TO_PC_DATA_BLOCK,
            "XfrBlock is answered by RDR_to_PC_DataBlock"
        );
        assert_eq!(
            select.command_status(),
            0,
            "the transfer itself must succeed (bError {:#04x})",
            select.error
        );
        assert_eq!(
            select.data,
            b"NetGet PIV\x90\x00".to_vec(),
            "the response APDU must be the handler's body followed by SW1 SW2"
        );

        // VERIFY, which the handler answers with no respond_to_apdu: the card must fail
        // closed with 6F00 rather than a success status word.
        let verify = client
            .transmit_apdu(&[
                0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            ])
            .await?;
        assert_eq!(
            verify.data,
            vec![0x6F, 0x00],
            "a handler that returns no respond_to_apdu must produce 6F00, never 9000"
        );

        // INTERNAL AUTHENTICATE (INS 0x88), answered with a body and no status word. The card
        // must refuse rather than complete the omission to 9000: naming no status word is not
        // approval, and on this protocol approval means an authentication succeeded.
        let auth = client
            .transmit_apdu(&[0x00, 0x88, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
            .await?;
        assert_eq!(
            auth.data,
            vec![0x6F, 0x00],
            "a respond_to_apdu naming no status word must fail closed, not be completed to \
             9000; got {}",
            hex::encode_upper(&auth.data)
        );
        assert!(
            !auth.data.ends_with(&[0x90, 0x00]),
            "the wire must not carry a success status word the handler never named"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// With the card removed the reader refuses power-on and APDU transfers on its own — no
    /// handler call is made — and detaching raises `usb_smartcard_detached`.
    ///
    /// LLM calls: 4 (startup, reader_ready, attached, detached)
    #[tokio::test]
    async fn test_usb_smartcard_no_card_fails_without_llm() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Create a USB smart card reader with an empty slot on port {AVAILABLE_PORT}."
                .to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("usb_smartcard_reader_ready")
                .respond_with_actions(serde_json::json!([
                    { "type": "set_card_present", "present": false }
                ]))
                .expect_calls(1)
                .and()
                .on_event("usb_smartcard_attached")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "Smart card host attached" }
                ]))
                .expect_calls(1)
                .and()
                .on_event("usb_smartcard_detached")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "Smart card host detached" }
                ]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("smart card")
                .respond_with_actions(open_server_actions("Keep the card slot empty"))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // The slot must report empty.
        let status = client.slot_status().await?;
        assert_eq!(status.message_type, RDR_TO_PC_SLOT_STATUS);
        assert_eq!(
            status.icc_status(),
            2,
            "bmICCStatus must be 2 (no ICC present) after set_card_present false"
        );

        // Power-on must be refused by the reader itself.
        let powered = client.power_on().await?;
        assert_eq!(
            powered.message_type, RDR_TO_PC_SLOT_STATUS,
            "a refused power-on is answered by RDR_to_PC_SlotStatus, not a data block"
        );
        assert_eq!(
            powered.command_status(),
            1,
            "bmCommandStatus must report failure"
        );
        assert_eq!(powered.error, 0xFE, "bError must be ICC_MUTE");

        // An APDU transfer must be refused too — and crucially without an LLM call, which the
        // mock would fail on since no usb_smartcard_apdu_received expectation is registered.
        let transfer = client
            .transmit_apdu(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00])
            .await?;
        assert_eq!(
            transfer.message_type, RDR_TO_PC_SLOT_STATUS,
            "XfrBlock with no card must be refused by the reader, not forwarded to the handler"
        );
        assert_eq!(transfer.command_status(), 1);

        // Detach: drop the USB/IP session.
        drop(client);
        server.wait_for_log_count(ATTACH_LOG, 2, 10).await?;
        server
            .wait_for_log("USB smart card host detached on connection", 10)
            .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
