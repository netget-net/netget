//! E2E tests for the USB HID keyboard server.
//!
//! The question these answer: *the model says "type hello" — do the bytes a host reads off the
//! interrupt endpoint spell hello?*
//!
//! They drive a real USB/IP client over TCP (`tests/helpers/usbip_client.rs`): `OP_REQ_IMPORT`,
//! then interrupt transfers on endpoint 1. At the USB/IP layer an interrupt transfer is
//! indistinguishable from a bulk one — both are `USBIP_CMD_SUBMIT` carrying an endpoint
//! *number* — so `bulk_in`/`bulk_out` drive the HID endpoints. HID reports are decoded here
//! against the boot-protocol layout rather than against netget's encoder.
//!
//! **What this does not prove.** There is no `vhci-hcd`, no `/dev/input/eventX`, no `evtest` —
//! macOS has no USB/IP client. A passing run means netget emits the right HID reports for the
//! model's actions; it does not mean Linux turns them into key events.
//!
//! ## What this file replaced
//!
//! Six tests that opened a bare `TcpStream` to the USB/IP port and asserted only that a mock
//! rule fired. They could not observe a single HID report, so `type_text`, `press_key_combo` and
//! `release_all_keys` were "tested" without anything checking what went on the wire. Two were
//! `#[ignore]`d with accurate product-gap notes:
//!
//! - `usb_keyboard_led_status` was declared and never emitted, because the crate's
//!   `UsbHidKeyboardHandler` discards HID output reports. `handler.rs` now intercepts
//!   `SET_REPORT` and the event has a real emit site — so that test is live, and drives a real
//!   LED write.
//! - `usb_keyboard_detached` was noted as unreachable behind `sleep(u64::MAX)`. That was fixed
//!   in the source before this pass; the `#[ignore]` was simply stale.

#[cfg(all(unix, feature = "libusb"))]
mod usb_keyboard_e2e {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;

    /// Log line emitted by the server *after* the attach LLM call returns.
    ///
    /// Must be the post-call line, not the "Calling LLM for ..." line that precedes it: the
    /// pre-call line is printed before the HTTP request reaches the mock, so waiting on it
    /// races `verify_mocks()` under parallel load.
    const ATTACH_LOG: &str = "USB keyboard LLM call completed for connection";
    const LED_LOG: &str = "USB keyboard LLM call completed (led_status)";

    /// HID usage codes for the characters the tests type (HID Usage Tables, keyboard page).
    const KEY_H: u8 = 0x0b;
    const KEY_I: u8 = 0x0c;
    const KEY_C: u8 = 0x06;
    /// Left Control, as a modifier bit.
    const MOD_LEFT_CTRL: u8 = 0x01;

    /// A boot-protocol keyboard report: modifier, reserved, six key slots.
    const REPORT_LEN: usize = 8;

    /// Read `count` non-empty input reports off the interrupt IN endpoint.
    ///
    /// A real host polls every 10ms and takes one report per poll; this does the same, and
    /// gives up rather than hanging if the device stops producing.
    async fn read_reports(client: &mut UsbIpClient, count: usize) -> E2EResult<Vec<Vec<u8>>> {
        let mut reports = Vec::with_capacity(count);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while reports.len() < count {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "device produced {} of {} expected HID reports",
                    reports.len(),
                    count
                )
                .into());
            }
            let report = client.bulk_in(REPORT_LEN as u32).await?;
            if report.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            reports.push(report);
        }
        Ok(reports)
    }

    /// Build the 8-byte `SET_REPORT(Output)` setup packet a host uses to set keyboard LEDs.
    ///
    /// `0x21` = host-to-device | class | interface; `0x09` = SET_REPORT; wValue `0x0200` selects
    /// report type Output, report id 0.
    fn set_leds_setup() -> [u8; 8] {
        let mut setup = [0u8; 8];
        setup[0] = 0x21;
        setup[1] = 0x09;
        setup[2..4].copy_from_slice(&0x0200u16.to_le_bytes()); // wValue (LE on the wire)
        setup[4..6].copy_from_slice(&0u16.to_le_bytes()); // wIndex: interface 0
        setup[6..8].copy_from_slice(&1u16.to_le_bytes()); // wLength: one LED byte
        setup
    }

    /// The headline case: the model types, and the host reads the right keystrokes.
    ///
    /// Both actions are bundled into one attach response, so the whole keyboard vocabulary
    /// costs a single LLM call. LLM calls: 2 (startup, attach).
    #[tokio::test]
    async fn test_usb_keyboard_types_what_the_model_asked_for() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Create a USB keyboard. When attached, type 'hi' and then press Ctrl+C.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB keyboard")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Keyboard",
                    "instruction": "Type 'hi' then Ctrl+C when attached"
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_keyboard_attached")
                .respond_with_actions(serde_json::json!([
                    {"type": "type_text", "text": "hi"},
                    {"type": "press_key_combo", "keys": ["ctrl", "c"]}
                ]))
                .expect_calls(1)
                .and()
                .on_event("usb_keyboard_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        assert!(server.is_running(), "USB keyboard server should be running");

        // 1. Enumeration: what would `usbip list -r <host>` show?
        let mut client = UsbIpClient::connect(server.port).await?;
        let devices = client.list_devices().await?;
        assert_eq!(devices.len(), 1, "exactly one device should be exported");
        assert_eq!(
            devices[0].interfaces,
            vec![(0x03, 0x00, 0x00)],
            "the interface must advertise the HID class"
        );

        // 2. Attach. The attach event follows this import — a bare TCP connect raises nothing
        //    (`attach_on_import_test.rs`), so the log line below is the import being answered.
        client.import("0-0-0").await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // 3. Read the reports the model's two actions produced: 'h' down/up, 'i' down/up,
        //    Ctrl+C down/up.
        let reports = read_reports(&mut client, 6).await?;
        for (i, report) in reports.iter().enumerate() {
            assert_eq!(
                report.len(),
                REPORT_LEN,
                "report {} is {} bytes; a boot-protocol keyboard report is 8",
                i,
                report.len()
            );
        }

        assert_eq!(
            reports[0][2], KEY_H,
            "the first key down must be 'h' (usage {:#04x}), got {:#04x}",
            KEY_H, reports[0][2]
        );
        assert_eq!(reports[0][0], 0, "'h' needs no modifier");
        assert_eq!(
            reports[1],
            vec![0u8; REPORT_LEN],
            "every key down must be followed by an all-zero release, or the host sees the key \
             as held"
        );
        assert_eq!(
            reports[2][2], KEY_I,
            "the second key down must be 'i' (usage {:#04x})",
            KEY_I
        );
        assert_eq!(reports[3], vec![0u8; REPORT_LEN]);

        assert_eq!(
            reports[4][0], MOD_LEFT_CTRL,
            "Ctrl+C must set the left-control modifier bit"
        );
        assert_eq!(
            reports[4][2], KEY_C,
            "Ctrl+C must carry 'c' (usage {:#04x}) in the first key slot",
            KEY_C
        );
        assert_eq!(reports[5], vec![0u8; REPORT_LEN]);

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The host toggles Caps Lock, and the model hears about it.
    ///
    /// This was `#[ignore]`d as a product gap for the whole life of the protocol: the event was
    /// declared, carried a full action vocabulary, and had no emit site, because the crate's
    /// keyboard handler discards HID output reports — and would in fact have hit its own
    /// `unimplemented!()` and panicked the session on this very request.
    ///
    /// LLM calls: 3 (startup, attach, LED status).
    #[tokio::test]
    async fn test_usb_keyboard_led_status_reaches_the_model() -> E2EResult<()> {
        let server_config =
            NetGetConfig::new("Create a USB keyboard. Report LED status changes.".to_string())
                .with_mock(|mock| {
                    mock.on_instruction_containing("USB keyboard")
                        .respond_with_actions(serde_json::json!([{
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "USB-Keyboard",
                            "instruction": "Report LED status changes"
                        }]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_keyboard_attached")
                        .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                        .expect_calls(1)
                        .and()
                        // The rule matches on the decoded flag, so a server that reported the
                        // wrong LED, or reported the raw byte, would not satisfy it.
                        .on_event("usb_keyboard_led_status")
                        .and_event_data_contains("caps_lock", "true")
                        .respond_with_actions(serde_json::json!([
                            {"type": "show_message", "message": "Caps Lock is now ON"}
                        ]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_keyboard_detached")
                        .respond_with_actions(serde_json::json!([
                            {"type": "show_message", "message": "detached"}
                        ]))
                        .expect_at_least(0)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // Caps Lock on: bit 1 of the LED byte.
        client.control_out(set_leds_setup(), &[0x02]).await?;
        server.wait_for_log(LED_LOG, 10).await?;

        // The device also answers GET_REPORT with the LED state it was given, which is how a
        // host re-reads it after a resume.
        let mut get_report = [0u8; 8];
        get_report[0] = 0xa1; // device-to-host | class | interface
        get_report[1] = 0x01; // GET_REPORT
        get_report[2..4].copy_from_slice(&0x0200u16.to_le_bytes());
        get_report[6..8].copy_from_slice(&1u16.to_le_bytes());
        let leds = client.control_in(get_report, 1).await?;
        assert_eq!(
            leds,
            vec![0x02],
            "GET_REPORT must return the LED byte the host set"
        );

        // An identical repeat must not raise a second event; the mock's expect_calls(1) is what
        // catches it, since a duplicate would make it 2.
        client.control_out(set_leds_setup(), &[0x02]).await?;
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Closing the USB/IP session raises `usb_keyboard_detached`.
    ///
    /// LLM calls: 3 (startup, attach, detach).
    #[tokio::test]
    async fn test_usb_keyboard_detach() -> E2EResult<()> {
        let server_config =
            NetGetConfig::new("Create a USB keyboard. Log when device is detached.".to_string())
                .with_mock(|mock| {
                    mock.on_instruction_containing("USB keyboard")
                        .respond_with_actions(serde_json::json!([{
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "USB-Keyboard",
                            "instruction": "Log when detached"
                        }]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_keyboard_attached")
                        .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_keyboard_detached")
                        .respond_with_actions(serde_json::json!([
                            {"type": "show_message", "message": "Keyboard device detached"}
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        let client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        drop(client);
        server
            .wait_for_log("USB keyboard host detached on connection", 10)
            .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A `connection_id` too large to be one must not silently become a different one.
    ///
    /// Every USB protocol resolved the model's `connection_id` with `ConnectionId::new(id as
    /// u32)`. That wraps: `4294967298` is connection **2** after the cast, so an action naming
    /// a nonsense connection would have been carried out against a real host's session -- and
    /// on a keyboard that means keystrokes typed into somebody else's window. The value is now
    /// read at its full width and refused if it is not a connection number.
    #[tokio::test]
    async fn an_out_of_range_connection_id_is_refused_rather_than_wrapped() {
        use ::netget::llm::actions::Server;
        use ::netget::server::usb::keyboard::UsbKeyboardProtocol;

        let protocol = UsbKeyboardProtocol::new();

        let err = protocol
            .execute_action(serde_json::json!({
                "type": "type_text", "text": "hello", "connection_id": 4_294_967_298u64
            }))
            .expect_err("a connection id past 32 bits must be refused");
        let message = format!("{err}");
        assert!(
            message.contains("4294967298"),
            "the refusal must quote the value the model sent, so its repair loop can see it: \
             {message}"
        );
        assert!(
            !message.contains("connection 2"),
            "the id must not have been narrowed to a real connection: {message}"
        );

        // An in-range id that simply has no host attached is a different, ordinary error --
        // otherwise the check above would be indistinguishable from refusing everything.
        let err = protocol
            .execute_action(serde_json::json!({
                "type": "type_text", "text": "hello", "connection_id": 2
            }))
            .expect_err("no host is attached in this test");
        assert!(
            format!("{err}").contains("No USB keyboard attached"),
            "an in-range id must reach handler lookup: {err}"
        );
    }

    /// A string descriptor must never declare a length it does not have.
    ///
    /// Lives here because `src/server/usb/descriptors.rs` is shared across the whole USB family
    /// under the `usb-common` feature and has no test directory of its own; declaring one would
    /// mean editing `tests/server/mod.rs`.
    ///
    /// `bLength` is a single byte, so the whole descriptor caps at 255 bytes -- 126 UTF-16 code
    /// units of text. The builder did `desc.push(len as u8)` with no check, so a 127-character
    /// string declared `bLength = 0` and a 128-character one declared 2: in both cases a
    /// descriptor contradicting its own contents, which a host either rejects or reads past.
    #[tokio::test]
    async fn a_string_descriptor_never_declares_a_length_it_does_not_have() {
        use ::netget::server::usb::descriptors::build_string_descriptor;

        for len in [0usize, 1, 125, 126, 127, 128, 200, 1000] {
            let descriptor = build_string_descriptor(&"a".repeat(len));
            assert_eq!(
                descriptor[0] as usize,
                descriptor.len(),
                "bLength must equal the real length for a {len}-character string"
            );
            assert!(
                descriptor.len() <= u8::MAX as usize,
                "a {len}-character string produced a descriptor bLength cannot describe"
            );
            assert_eq!(descriptor[1], 0x03, "bDescriptorType must be STRING");
        }

        // Truncation must not split a surrogate pair, or the host decodes a lone surrogate.
        // Each emoji is two UTF-16 code units, so 200 of them is 400 -- well past the cap, and
        // the cut lands exactly where a naive truncation would halve one.
        let emoji = build_string_descriptor(&"\u{1F600}".repeat(200));
        assert_eq!(emoji[0] as usize, emoji.len());
        let units: Vec<u16> = emoji[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert!(
            String::from_utf16(&units).is_ok(),
            "the truncated descriptor must still be valid UTF-16"
        );
    }
}
