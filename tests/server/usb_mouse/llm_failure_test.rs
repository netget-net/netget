//! What a HID host gets when the LLM backend fails: nothing, on purpose.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `usb_mouse_attached` event then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! ## Why silence is the right answer here, unlike everywhere else in this sweep
//!
//! A HID mouse owes the host no reply. The host polls the interrupt IN endpoint and is NAKed
//! whenever the pointer is not moving, which is what every mouse does most of the time. There is
//! no HID vocabulary for "the device's brain is unreachable" — STALLing the endpoint is a fault
//! that makes a host reset or unbind the device rather than a refusal it can act on, and `usbip`
//! cannot express it anyway (an `Err` from `handle_urb` aborts the session for the whole
//! device).
//!
//! What must hold is the other direction, and this test pins it: a failed LLM call must never
//! move the pointer or press a button. A phantom click during an outage would be considerably
//! worse than a pointer that does not move. The failure is dual-logged at ERROR so an operator
//! can tell a stalled model from a mouse nobody is using.

#[cfg(all(unix, feature = "libusb"))]
mod usb_mouse_llm_failure {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;

    /// The dual-logged ERROR the LLM-failure path emits.
    const LLM_FAILURE_LOG: &str = "LLM call failed for USB mouse connection";

    /// The tag that separates a backend outage from the model answering with nothing. Both
    /// look identical on the wire (a pointer that does not move), so the log is the only place
    /// an operator can tell them apart, and that makes the tag part of the contract.
    const LLM_FAILURE_DECISION: &str = "decision=fail_closed_llm_error";

    /// A boot-protocol mouse report: buttons, dx, dy, wheel.
    const REPORT_LEN: u32 = 4;

    /// How long to keep polling for a report that must never arrive.
    const QUIET_WINDOW: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn test_usb_mouse_stays_still_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Create a USB mouse on port {AVAILABLE_PORT}. Click when attached.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB mouse")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Mouse",
                    "instruction": "Click when attached"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for usb_mouse_attached: the mock answers 500, which is what
            // drives the server down its LLM-failure path.
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB mouse server should be running");

        let mut client = UsbIpClient::attach(server.port).await?;

        // The attach handler fails. This is the only event this protocol raises that a model
        // would answer with pointer movement.
        server.wait_for_log(LLM_FAILURE_LOG, 15).await?;
        server.wait_for_log(LLM_FAILURE_DECISION, 5).await?;

        // Poll the interrupt IN endpoint the way a host does. Every URB must succeed and every
        // one must be empty — no movement, and above all no button press.
        let deadline = std::time::Instant::now() + QUIET_WINDOW;
        let mut polls = 0usize;
        while std::time::Instant::now() < deadline {
            let report = client.bulk_in(REPORT_LEN).await?;
            assert!(
                report.is_empty(),
                "an LLM failure must never move the pointer or press a button; the host read a \
                 HID report: {:02x?}",
                report
            );
            polls += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            polls > 10,
            "expected the device to answer a stream of interrupt polls, got {polls}"
        );

        // The mouse must still be enumerable: a refusal to act is not a broken device.
        let mut fresh = UsbIpClient::connect(server.port).await?;
        let devices = fresh.list_devices().await?;
        assert_eq!(devices.len(), 1, "the mouse must still be exported");
        assert_eq!(
            devices[0].interfaces,
            vec![(0x03, 0x01, 0x02)],
            "the interface must still advertise HID / boot / mouse"
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
