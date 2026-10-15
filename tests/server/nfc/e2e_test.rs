//! NFC virtual tag E2E tests.
//!
//! The virtual tag binds a TCP socket and speaks the vsmartcard `vpcd` framing
//! (u16 big-endian length prefix; a 1-byte frame is a control code, anything
//! longer is an ISO 7816-4 APDU). That is exactly what these tests drive — a
//! real client on the real socket, asserting the response APDU **bytes**. No
//! reader, no vpcd daemon, no PC/SC.

#[cfg(unix)]
mod tests {
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// vpcd control code asking the card for its ATR.
    const VPCD_CTRL_ATR: u8 = 0x04;

    /// Every socket read is bounded so a regression surfaces as a failed
    /// assertion rather than the suite hanging until the harness timeout.
    const IO_TIMEOUT: Duration = Duration::from_secs(30);

    /// Write one length-prefixed frame to the virtual tag.
    async fn send_frame(stream: &mut TcpStream, payload: &[u8]) -> E2EResult<()> {
        stream.write_u16(payload.len() as u16).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Read one length-prefixed frame from the virtual tag.
    async fn recv_frame(stream: &mut TcpStream) -> E2EResult<Vec<u8>> {
        let read = async {
            let len = stream.read_u16().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        match tokio::time::timeout(IO_TIMEOUT, read).await {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(e)) => Err(format!("Failed to read frame from virtual NFC tag: {e}").into()),
            Err(_) => Err("Timed out waiting for a frame from the virtual NFC tag".into()),
        }
    }

    /// Send a command APDU and return the raw response APDU (body + SW1 SW2).
    async fn transceive(stream: &mut TcpStream, apdu: &[u8]) -> E2EResult<Vec<u8>> {
        send_frame(stream, apdu).await?;
        recv_frame(stream).await
    }

    /// Full APDU exchange against the bound virtual tag.
    ///
    /// LLM calls: 7 (startup instruction, nfc_server_started, nfc_tag_selected,
    /// and four nfc_apdu_received).
    ///
    /// It covers every way the tag can answer:
    /// - the ATR the handler configured with `set_atr` reaches the wire,
    /// - `nfc_tag_selected` fires for SELECT by AID and its status word is sent,
    /// - `nfc_apdu_received` fires for other APDUs and its response body is sent,
    /// - a handler status word that refuses (`6982`) is passed through verbatim,
    /// - a handler that answers without `respond_to_apdu` fails **closed** (`6F00`),
    /// - a `respond_to_apdu` that names **no status word** also fails closed (`6F00`)
    ///   rather than being completed to `9000`,
    /// - a malformed APDU is rejected (`6700`) without reaching the handler.
    #[tokio::test]
    async fn test_nfc_virtual_tag_apdu_exchange() -> E2EResult<()> {
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via NFC and emulate a Type 4 tag.")
                .with_mock(|mock| {
                    mock
                        // 1. Top-level instruction -> open the NFC server.
                        // "via NFC" appears only here, never in the server instruction
                        // below, so this rule cannot swallow the per-event calls.
                        .on_instruction_containing("via NFC")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "nfc",
                                "instruction": "Answer APDU commands as a Type 4 tag",
                                "startup_params": {
                                    "tag_type": "type4",
                                    "uid": "04A1B2C3D4E5F6"
                                }
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 2. Tag configuration at startup.
                        .on_event("nfc_server_started")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "set_atr",
                                "atr_hex": "3B8180018050"
                            },
                            {
                                "type": "set_ndef_message",
                                "records": [
                                    {"type": "text", "language": "en", "text": "Hello NFC!"}
                                ]
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 3. SELECT by AID -> nfc_tag_selected.
                        .on_event("nfc_tag_selected")
                        .and_event_data_contains("application_id", "D2760000850101")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "respond_to_apdu",
                                "sw1": "90",
                                "sw2": "00"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 4. READ BINARY -> body supplied as text.
                        .on_event("nfc_apdu_received")
                        .and_event_data_contains("ins", "B0")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "respond_to_apdu",
                                "data_text": "Hello NFC!",
                                "sw1": "90",
                                "sw2": "00"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 5. VERIFY -> explicit refusal, must reach the reader verbatim.
                        .on_event("nfc_apdu_received")
                        .and_event_data_contains("ins", "20")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "respond_to_apdu",
                                "sw1": "69",
                                "sw2": "82"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 6. GET CHALLENGE -> handler answers but produces no
                        //    respond_to_apdu. The tag must fail closed with 6F00, not
                        //    fall through to a success status word.
                        .on_event("nfc_apdu_received")
                        .and_event_data_contains("ins", "84")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "show_message",
                                "message": "Not answering GET CHALLENGE"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // 7. INTERNAL AUTHENTICATE -> the handler answers with a body and
                        //    *no status word at all*. A tag is an access-control device, so
                        //    the missing byte must not be filled in with success: naming no
                        //    status word is not approval.
                        .on_event("nfc_apdu_received")
                        .and_event_data_contains("ins", "88")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "respond_to_apdu",
                                "data_text": "AUTH OK"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        let mut reader =
            tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", server.port)))
                .await
                .map_err(|_| "Timed out connecting to the virtual NFC tag")??;

        // --- ATR: proves set_atr reached the wire ---------------------------
        send_frame(&mut reader, &[VPCD_CTRL_ATR]).await?;
        let atr = recv_frame(&mut reader).await?;
        assert_eq!(
            hex::encode_upper(&atr),
            "3B8180018050",
            "Virtual tag must return the ATR the handler configured with set_atr"
        );

        // --- SELECT by AID -> nfc_tag_selected ------------------------------
        // 00 A4 04 00 07 D2760000850101 00  (select the NDEF application)
        let select_ndef = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
        ];
        let response = transceive(&mut reader, &select_ndef).await?;
        assert_eq!(
            response,
            vec![0x90, 0x00],
            "SELECT by AID must be answered 9000 (got {})",
            hex::encode_upper(&response)
        );

        // --- READ BINARY -> nfc_apdu_received with a response body ----------
        // 00 B0 00 00 0F
        let read_binary = [0x00, 0xB0, 0x00, 0x00, 0x0F];
        let response = transceive(&mut reader, &read_binary).await?;
        let mut expected = b"Hello NFC!".to_vec();
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(
            response,
            expected,
            "READ BINARY must return the handler's body followed by 9000 (got {})",
            hex::encode_upper(&response)
        );

        // --- VERIFY -> the handler's refusal must survive unchanged ---------
        // 00 20 00 00 06 "123456"
        let mut verify = vec![0x00, 0x20, 0x00, 0x00, 0x06];
        verify.extend_from_slice(b"123456");
        let response = transceive(&mut reader, &verify).await?;
        assert_eq!(
            response,
            vec![0x69, 0x82],
            "VERIFY must return the handler's 6982 refusal (got {})",
            hex::encode_upper(&response)
        );

        // --- No respond_to_apdu -> fail closed ------------------------------
        // 00 84 00 00 08  (GET CHALLENGE)
        let get_challenge = [0x00, 0x84, 0x00, 0x00, 0x08];
        let response = transceive(&mut reader, &get_challenge).await?;
        assert_eq!(
            response,
            vec![0x6F, 0x00],
            "A handler that produces no respond_to_apdu must fail closed with 6F00 (got {})",
            hex::encode_upper(&response)
        );

        // --- respond_to_apdu with no status word -> fail closed -------------
        // 00 88 00 00 08  (INTERNAL AUTHENTICATE). The handler answered, and its answer
        // carries a body but no sw1/sw2. Defaulting that to 9000 would mean an omission
        // approves an authentication, so the tag must refuse and the body must not reach
        // the reader either.
        let internal_auth = [0x00, 0x88, 0x00, 0x00, 0x08];
        let response = transceive(&mut reader, &internal_auth).await?;
        assert_eq!(
            response,
            vec![0x6F, 0x00],
            "a respond_to_apdu with no status word must fail closed with 6F00, never 9000 \
             (got {})",
            hex::encode_upper(&response)
        );

        // --- Malformed APDU -> rejected without an LLM call -----------------
        // Three bytes cannot be an APDU header; answered 6700 locally, so the
        // mock call counts asserted below stay exact.
        let truncated = [0x00, 0xA4, 0x04];
        let response = transceive(&mut reader, &truncated).await?;
        assert_eq!(
            response,
            vec![0x67, 0x00],
            "A truncated APDU must be answered 6700 (got {})",
            hex::encode_upper(&response)
        );

        drop(reader);
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// The LLM-error path must answer a *category*, and the two categories must be
    /// different status words.
    ///
    /// This is the unit half of the fail-closed contract: `6400` (execution error,
    /// card state unchanged) tells the reader to retry a saturated backend, while
    /// `6F00` (no precise diagnosis) is the flat failure. Collapsing them back into
    /// one code would make a transient overload look like a broken card. Neither
    /// carries a single byte derived from the error — an APDU response has no
    /// free-text field, which is precisely why this protocol cannot leak one.
    #[test]
    fn wire_failure_categories_map_to_distinct_status_words() {
        use ::netget::server::nfc::apdu::ApduResponse;
        use ::netget::utils::WireFailure;

        let overloaded = ApduResponse::for_wire_failure(WireFailure::Overloaded);
        assert_eq!(
            overloaded.clone().into_bytes(),
            vec![0x64, 0x00],
            "an overloaded backend must answer 6400 so the reader retries"
        );

        let unavailable = ApduResponse::for_wire_failure(WireFailure::Unavailable);
        assert_eq!(
            unavailable.clone().into_bytes(),
            vec![0x6F, 0x00],
            "any other backend failure must answer 6F00"
        );

        assert_ne!(
            overloaded.status_word(),
            unavailable.status_word(),
            "the two categories must stay distinguishable on the wire"
        );
    }
}
