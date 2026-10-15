//! What a HID host gets when the LLM backend fails: nothing, on purpose.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `usb_keyboard_attached` event then matches no rule, the mock Ollama server answers HTTP 500,
//! and `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! ## Why silence is the right answer here, unlike everywhere else in this sweep
//!
//! Most protocols owe the peer a reply, and going quiet on an LLM failure leaves it hanging
//! until its own timeout. A HID keyboard owes nothing: the host polls the interrupt IN endpoint
//! and is NAKed whenever no key is down, which is the state of every keyboard in the world most
//! of the time. There is no HID vocabulary for "the device's brain is unreachable" — STALLing
//! the endpoint is a *fault* that makes a host reset or unbind the device, which is both less
//! truthful and worse than reporting no keystrokes. (`usbip` cannot express it either: an `Err`
//! from `handle_urb` aborts the USB/IP session for the whole device.)
//!
//! So the two things that must hold are the ones asserted below:
//!
//! 1. **Nothing is typed.** A failed LLM call must never put a keystroke on the wire. This is
//!    the fail-closed property that matters for a keyboard — a device that types *something*
//!    when its brain is unreachable would be far worse than one that types nothing.
//! 2. **The failure is recorded at ERROR, on both channels, tagged `decision=fail_closed_llm_error`.** Silence that goes unlogged is
//!    indistinguishable from a working keyboard nobody is using, which is exactly the situation
//!    an operator needs to be able to tell apart.
//!
//! The device must also still be *there*: the session survives, so a host that keeps polling
//! gets a working keyboard back the moment the backend recovers.

#[cfg(all(unix, feature = "libusb"))]
mod usb_keyboard_llm_failure {
    use crate::helpers::usbip_client::UsbIpClient;
    use crate::helpers::*;
    use std::time::Duration;

    /// The dual-logged ERROR the LLM-failure path emits.
    const LLM_FAILURE_LOG: &str = "LLM call failed for USB keyboard connection";

    /// A boot-protocol keyboard report: modifier, reserved, six key slots.
    const REPORT_LEN: u32 = 8;

    /// How long to keep polling for a keystroke that must never arrive. Long enough that a
    /// late-arriving report from a slow path would be caught, short enough not to pad the suite.
    const QUIET_WINDOW: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn test_usb_keyboard_types_nothing_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Create a USB keyboard on port {AVAILABLE_PORT}. Type a password when attached."
                .to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB keyboard")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-Keyboard",
                    "instruction": "Type something when attached"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for usb_keyboard_attached: the mock answers 500, which is
            // what drives the server down its LLM-failure path.
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB keyboard server should be running");

        let mut client = UsbIpClient::attach(server.port).await?;

        // The attach handler fails. This is the only event this protocol raises that a model
        // would answer with keystrokes.
        server.wait_for_log(LLM_FAILURE_LOG, 15).await?;

        // Silence has three causes and they must not look alike in the log: a backend failure,
        // a model that answered with no keystrokes, and a model that typed. Only the first one
        // is a fault, so the failure path carries its own `decision=` tag.
        server
            .wait_for_log("decision=fail_closed_llm_error", 15)
            .await?;

        // Poll the interrupt IN endpoint the way a host does. Every URB must succeed — the
        // device is still there and the session is intact — and every one must be empty.
        let deadline = std::time::Instant::now() + QUIET_WINDOW;
        let mut polls = 0usize;
        while std::time::Instant::now() < deadline {
            let report = client.bulk_in(REPORT_LEN).await?;
            assert!(
                report.is_empty(),
                "an LLM failure must never put a keystroke on the wire; the host read a HID \
                 report: {:02x?}",
                report
            );
            polls += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            polls > 10,
            "expected the device to answer a stream of interrupt polls, got {polls}"
        );

        // The keyboard must still be enumerable. A separate USB/IP session proves the server
        // itself is healthy, not merely that one socket has not been closed yet.
        let mut fresh = UsbIpClient::connect(server.port).await?;
        let devices = fresh.list_devices().await?;
        assert_eq!(devices.len(), 1, "the keyboard must still be exported");
        assert_eq!(
            devices[0].interfaces,
            vec![(0x03, 0x00, 0x00)],
            "the interface must still advertise the HID class"
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
