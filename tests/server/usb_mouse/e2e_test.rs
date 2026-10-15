//! E2E tests for the USB HID mouse server.
//!
//! The question these answer: *the model says "move right and click" — do the 4-byte reports a
//! host reads off the interrupt endpoint say that?*
//!
//! They drive a real USB/IP client over TCP (`tests/helpers/usbip_client.rs`): `OP_REQ_IMPORT`,
//! then interrupt transfers on endpoint 1. At the USB/IP layer an interrupt transfer is
//! indistinguishable from a bulk one — both are `USBIP_CMD_SUBMIT` carrying an endpoint
//! *number* — so `bulk_in` drives the HID endpoint. Reports are decoded here against the
//! boot-protocol mouse layout (buttons, dx, dy, wheel), not against netget's encoder.
//!
//! **What this does not prove.** There is no `vhci-hcd` and no `/dev/input/eventX`; macOS has no
//! USB/IP client. A passing run means netget emits the right HID reports for the model's
//! actions, not that a pointer moves on a Linux desktop.
//!
//! ## What this file replaced
//!
//! Seven tests that opened a bare `TcpStream` and asserted only that a mock rule fired. They
//! passed while the protocol did **nothing at all**: `handle_connection` took the accepted
//! socket as `_stream` and dropped it, never ran a USB/IP session, logged
//! "NOT YET FUNCTIONAL - waiting for usbip crate mouse support", and parked on
//! `sleep(u64::MAX)`; and every action in `actions.rs` parsed its parameters, logged
//! "not yet implemented", and returned `NoAction`. A suite that never enumerates the device
//! cannot tell that apart from a working mouse.

#[cfg(all(unix, feature = "libusb"))]
mod usb_mouse_e2e {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;

    /// Log line emitted by the server *after* the attach LLM call returns.
    ///
    /// Must be the post-call line, not the "Calling LLM for ..." line that precedes it: the
    /// pre-call line is printed before the HTTP request reaches the mock, so waiting on it
    /// races `verify_mocks()` under parallel load.
    const ATTACH_LOG: &str = "USB mouse LLM call completed for connection";

    /// A boot-protocol mouse report: buttons, dx, dy, wheel.
    const REPORT_LEN: usize = 4;

    const BUTTON_LEFT: u8 = 0x01;

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

    /// Decode one report's buttons and signed axes.
    fn axes(report: &[u8]) -> (u8, i8, i8, i8) {
        (report[0], report[1] as i8, report[2] as i8, report[3] as i8)
    }

    /// The headline case: move, click and scroll, decoded off the wire.
    ///
    /// All three actions are bundled into one attach response, so the vocabulary costs a single
    /// LLM call. The move is deliberately larger than one report can carry: a boot-protocol
    /// report holds one signed byte per axis, so 300 has to become several reports summing to
    /// 300, and the model is not asked to know that.
    ///
    /// LLM calls: 2 (startup, attach).
    #[tokio::test]
    async fn test_usb_mouse_moves_clicks_and_scrolls() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Create a USB mouse. When attached, move right, click and scroll down.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB mouse")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Mouse",
                    "instruction": "Move, click and scroll when attached"
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_mouse_attached")
                .respond_with_actions(serde_json::json!([
                    {"type": "move_relative", "x": 300, "y": -5},
                    {"type": "click", "button": "left"},
                    {"type": "scroll", "direction": "down", "amount": 2}
                ]))
                .expect_calls(1)
                .and()
                .on_event("usb_mouse_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        assert!(server.is_running(), "USB mouse server should be running");

        // 1. Enumeration: the device must actually be exported. The previous implementation
        //    dropped the accepted socket, so this alone would have failed.
        let mut client = UsbIpClient::connect(server.port).await?;
        let devices = client.list_devices().await?;
        assert_eq!(devices.len(), 1, "exactly one device should be exported");
        assert_eq!(
            devices[0].interfaces,
            vec![(0x03, 0x01, 0x02)],
            "the interface must advertise HID / boot interface / mouse"
        );

        client.import("0-0-0").await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // 2. move_relative(300, -5): several reports whose dx sums to 300.
        let moves = read_reports(&mut client, 3).await?;
        for (i, report) in moves.iter().enumerate() {
            assert_eq!(
                report.len(),
                REPORT_LEN,
                "report {} is {} bytes; a boot-protocol mouse report is 4",
                i,
                report.len()
            );
        }
        let total_x: i32 = moves.iter().map(|r| axes(r).1 as i32).sum();
        let total_y: i32 = moves.iter().map(|r| axes(r).2 as i32).sum();
        assert_eq!(
            total_x, 300,
            "the split reports must sum to the movement the model asked for"
        );
        assert_eq!(total_y, -5, "vertical movement must survive the split too");
        assert!(
            moves.iter().all(|r| axes(r).0 == 0),
            "a plain move must hold no buttons"
        );

        // 3. click: press then release.
        let click = read_reports(&mut client, 2).await?;
        assert_eq!(
            axes(&click[0]).0,
            BUTTON_LEFT,
            "the click must set the left button bit"
        );
        assert_eq!(
            click[1],
            vec![0u8; REPORT_LEN],
            "a click must be followed by a release, or it becomes a stuck drag"
        );

        // 4. scroll down x2: one detent per report, negative wheel.
        let scroll = read_reports(&mut client, 2).await?;
        for report in &scroll {
            assert_eq!(
                axes(report).3,
                -1,
                "scrolling down must send negative wheel detents, got {}",
                axes(report).3
            );
        }

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A drag must hold the button down for *every* intermediate movement.
    ///
    /// Releasing at the first move is the classic mistake: the host sees a click followed by a
    /// pointer move rather than a drag, and a selection or a window drag silently does nothing.
    ///
    /// LLM calls: 2 (startup, attach).
    #[tokio::test]
    async fn test_usb_mouse_drag_holds_the_button_throughout() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Create a USB mouse and drag from one point to another when attached.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB mouse")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Mouse",
                    "instruction": "Drag when attached"
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_mouse_attached")
                .respond_with_actions(serde_json::json!([{
                    "type": "drag",
                    "start_x": 100, "start_y": 100,
                    "end_x": 140, "end_y": 120,
                    "duration_ms": 40
                }]))
                .expect_calls(1)
                .and()
                .on_event("usb_mouse_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        // duration_ms 40 at the endpoint's 10ms interval is 4 movement steps, plus a press
        // report and a release report.
        let reports = read_reports(&mut client, 6).await?;

        assert_eq!(
            axes(&reports[0]),
            (BUTTON_LEFT, 0, 0, 0),
            "a drag must begin by pressing the button without moving"
        );

        let movements = &reports[1..reports.len() - 1];
        assert!(
            movements.iter().all(|r| axes(r).0 == BUTTON_LEFT),
            "every intermediate report must keep the button held: {:?}",
            movements.iter().map(|r| axes(r)).collect::<Vec<_>>()
        );
        let total_x: i32 = movements.iter().map(|r| axes(r).1 as i32).sum();
        let total_y: i32 = movements.iter().map(|r| axes(r).2 as i32).sum();
        assert_eq!(total_x, 40, "the drag must cover the full horizontal delta");
        assert_eq!(total_y, 20, "the drag must cover the full vertical delta");

        assert_eq!(
            reports[reports.len() - 1],
            vec![0u8; REPORT_LEN],
            "a drag must end by releasing the button"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Closing the USB/IP session raises `usb_mouse_detached`.
    ///
    /// This was `#[ignore]`d as a product gap, and correctly so: the event had no emit site
    /// because `handle_connection` parked on `sleep(u64::MAX)` and there was no session to end.
    ///
    /// LLM calls: 3 (startup, attach, detach).
    #[tokio::test]
    async fn test_usb_mouse_detach() -> E2EResult<()> {
        let server_config =
            NetGetConfig::new("Create a USB mouse. Log when device is detached.".to_string())
                .with_mock(|mock| {
                    mock.on_instruction_containing("USB mouse")
                        .respond_with_actions(serde_json::json!([{
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "USB-Mouse",
                            "instruction": "Log when detached"
                        }]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_mouse_attached")
                        .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                        .expect_calls(1)
                        .and()
                        .on_event("usb_mouse_detached")
                        .respond_with_actions(serde_json::json!([
                            {"type": "show_message", "message": "Mouse device detached"}
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        let client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_LOG, 10).await?;

        drop(client);
        server
            .wait_for_log("USB mouse host detached on connection", 10)
            .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A model asking for an absurd movement must be refused, not obeyed.
    ///
    /// `split_movement` emits one 4-byte report per 127 units, and nothing bounded the units.
    /// `{"type": "move_relative", "x": 9223372036854775807}` therefore asked for ~7.3e16
    /// reports: `execute_action` is synchronous and runs on a tokio worker, so the executor
    /// never returned, the worker never came back, and the queue grew until the process died.
    /// `move_absolute` had a second shape of the same bug -- it computes `-screen_width - 127`,
    /// which overflows `i64` outright for a large dimension, panicking in every test build and
    /// wrapping in release.
    ///
    /// This runs against `execute_action` directly rather than through USB/IP, because the
    /// point is that the executor refuses *before* anything is queued.
    #[tokio::test]
    async fn absurd_movement_is_refused_rather_than_queued() {
        use ::netget::llm::actions::Server;
        use ::netget::server::usb::mouse::UsbMouseProtocol;

        let protocol = UsbMouseProtocol::new();

        for (label, action) in [
            (
                "move_relative x",
                serde_json::json!({"type": "move_relative", "x": i64::MAX, "y": 0}),
            ),
            (
                "move_relative y",
                serde_json::json!({"type": "move_relative", "x": 0, "y": i64::MIN}),
            ),
            (
                "move_absolute screen_width",
                serde_json::json!({
                    "type": "move_absolute", "x": 1, "y": 1,
                    "screen_width": i64::MAX, "screen_height": 1080
                }),
            ),
            (
                "drag end_x",
                serde_json::json!({
                    "type": "drag", "start_x": 0, "start_y": 0,
                    "end_x": i64::MAX, "end_y": 0
                }),
            ),
        ] {
            let result = protocol.execute_action(action);
            assert!(
                result.is_err(),
                "{label}: an out-of-range coordinate must be refused, not turned into reports"
            );
        }

        // A guard that refused everything would pass the assertions above while breaking the
        // protocol, so pin the ordinary case too. No host is attached, so this fails at
        // handler resolution -- after the range check, which is the part being pinned.
        let err = protocol
            .execute_action(serde_json::json!({"type": "move_relative", "x": 50, "y": -20}))
            .expect_err("no host is attached in this test");
        let message = format!("{err}");
        assert!(
            message.contains("No USB/IP host") || message.contains("nowhere to go"),
            "an ordinary movement must reach handler resolution, not be range-refused: {message}"
        );
    }
}
