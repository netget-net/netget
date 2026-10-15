//! What a smart card host gets when the LLM backend fails.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. Every event
//! the protocol raises then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! Unlike the rest of the USB family this protocol was already correct: `answer_apdu` returns
//! `ApduResponse::card_error()` — ISO 7816-4 **`6F00`**, "no precise diagnosis" — when the
//! handler errors, says nothing, or says something undecodable, and there is no path to `9000`.
//! This test exists to keep it that way, because the property is invisible from the source of
//! any one function: `6F00` is produced in three different arms and a refactor that lost one of
//! them would leave a card that answers `9000` during an outage.
//!
//! A status word is the right vocabulary here rather than a bare USB STALL: `6F00` is what the
//! *card* says, which is the layer the host's PC/SC stack is asking a question at. STALLing the
//! endpoint would fail the reader instead, and a host cannot tell a failed reader from an
//! unplugged one.
//!
//! Two further properties asserted below:
//!
//! * The **reader still works**. `IccPowerOn` returns the default ATR and the slot reports a
//!   card, because the startup event failing means "unconfigured", not "broken" — opening a
//!   socket must not require the model to be reachable.
//! * The card **keeps answering**. A second APDU also gets `6F00`, so the host is never left on
//!   its own timeout.

#[cfg(all(unix, feature = "libusb"))]
mod usb_smartcard_llm_failure {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;

    /// The dual-logged ERROR the LLM-failure path emits for an APDU.
    const APDU_FAILURE_LOG: &str = "USB smart card handler failed for";
    /// The dual-logged ERROR the startup path emits.
    const STARTUP_FAILURE_LOG: &str = "USB smart card startup configuration failed";

    /// The ATR the reader carries when the model never configured it (`DEFAULT_ATR`).
    const DEFAULT_ATR: [u8; 4] = [0x3B, 0x90, 0x11, 0x00];

    /// CCID bulk endpoints, from `UsbCcidHandler::endpoints()`: bulk IN 0x82, bulk OUT 0x02 —
    /// endpoint 2 in both directions, 64-byte packets.
    const BULK_EP: u32 = 2;
    const BULK_MAX_PACKET: u32 = 64;

    const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
    const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    const CCID_HEADER_LEN: usize = 10;

    /// A parsed `RDR_to_PC_*` message.
    struct CcidResponse {
        message_type: u8,
        seq: u8,
        status: u8,
        data: Vec<u8>,
    }

    impl CcidResponse {
        fn command_status(&self) -> u8 {
            (self.status >> 6) & 0x03
        }
    }

    /// Send one CCID command on the bulk OUT endpoint, returning its `bSeq`.
    async fn send_ccid(
        client: &mut UsbIpClient,
        seq: u8,
        message_type: u8,
        payload: &[u8],
    ) -> E2EResult<u8> {
        let mut message = Vec::with_capacity(CCID_HEADER_LEN + payload.len());
        message.push(message_type);
        message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        message.push(0); // bSlot
        message.push(seq);
        message.extend_from_slice(&[0u8; 3]); // bBWI / wLevelParameter
        message.extend_from_slice(payload);
        client.bulk_out(&message).await?;
        Ok(seq)
    }

    /// Poll the bulk IN endpoint until a whole CCID message has been reassembled. The reader
    /// uses 64-byte packets, so a long response arrives over several URBs.
    async fn read_ccid(client: &mut UsbIpClient, timeout: Duration) -> E2EResult<CcidResponse> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let chunk = client.bulk_in(BULK_MAX_PACKET).await?;
            if chunk.is_empty() {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "reader sent no CCID response within {:?} ({} byte(s) so far)",
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
                data: buffer[CCID_HEADER_LEN..CCID_HEADER_LEN + declared].to_vec(),
            });
        }
    }

    #[tokio::test]
    async fn test_usb_smartcard_answers_6f00_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Create a USB smart card reader on port {AVAILABLE_PORT}.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("smart card reader")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "usb-smartcard",
                    "instruction": "Answer APDUs",
                    "startup_params": { "card_type": "generic" }
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for usb_smartcard_apdu_received: the mock answers 500, which
            // is what drives the server down its fail-closed path.
        });

        let mut server = start_netget_server(config).await?;
        assert!(
            server.is_running(),
            "the reader must start even though the model is unreachable: opening a socket is \
             not something the LLM does"
        );
        server.wait_for_log(STARTUP_FAILURE_LOG, 15).await?;

        let mut client = UsbIpClient::attach(server.port)
            .await?
            .with_bulk_endpoints(BULK_EP, BULK_EP);

        // 1. The reader is usable: power on returns the default ATR. "Unconfigured" is not
        //    "broken", and a host must still see a card.
        let seq = send_ccid(&mut client, 1, PC_TO_RDR_ICC_POWER_ON, &[]).await?;
        let powered = read_ccid(&mut client, Duration::from_secs(10)).await?;
        assert_eq!(powered.seq, seq, "CCID bSeq must be echoed");
        assert_eq!(
            powered.message_type, RDR_TO_PC_DATA_BLOCK,
            "IccPowerOn must be answered with RDR_to_PC_DataBlock"
        );
        assert_eq!(
            powered.command_status(),
            0,
            "IccPowerOn must succeed; the card is present with its default ATR"
        );
        assert_eq!(
            powered.data,
            DEFAULT_ATR.to_vec(),
            "an unconfigured card must present the default ATR, got {:02x?}",
            powered.data
        );

        // 2. The APDU the model was supposed to answer. SELECT by DF name of the PIV AID —
        //    an ordinary thing for a host to ask, and the model is unreachable.
        let select_piv = [
            0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
            0x00,
        ];
        let seq = send_ccid(&mut client, 2, PC_TO_RDR_XFR_BLOCK, &select_piv).await?;
        let answer = read_ccid(&mut client, Duration::from_secs(20)).await?;
        assert_eq!(answer.seq, seq, "CCID bSeq must be echoed");
        assert_eq!(
            answer.message_type, RDR_TO_PC_DATA_BLOCK,
            "XfrBlock must be answered with RDR_to_PC_DataBlock"
        );
        assert_eq!(
            answer.data,
            vec![0x6F, 0x00],
            "an unreachable model must answer 6F00 (no precise diagnosis) and never 9000; \
             got {:02x?}",
            answer.data
        );
        server.wait_for_log(APDU_FAILURE_LOG, 10).await?;

        // 3. And it keeps answering: a card that stops talking leaves the host on its own
        //    timeout, which is the defect this whole sweep is about.
        let get_data = [0x00, 0xCA, 0x00, 0x00, 0x00];
        let seq = send_ccid(&mut client, 3, PC_TO_RDR_XFR_BLOCK, &get_data).await?;
        let again = read_ccid(&mut client, Duration::from_secs(20)).await?;
        assert_eq!(again.seq, seq, "CCID bSeq must be echoed");
        assert_eq!(
            again.data,
            vec![0x6F, 0x00],
            "every APDU must be answered while the model is unreachable, got {:02x?}",
            again.data
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
