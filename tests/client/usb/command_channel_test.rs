//! The dashboard's `[ send ]` path on a USB client.
//!
//! **What this environment can and cannot check.** A USB client only exists once a real device
//! matching the requested VID:PID has been opened and one of its interfaces claimed. There is no
//! socket, no loopback, and no software stand-in — so on a machine without that exact device the
//! injection half of this test cannot run, and pretending otherwise would be a fabricated pass.
//!
//! What the always-running test *does* check is the rule that is easiest to get wrong and that
//! does not need hardware: the command handle must be registered only after the device is open,
//! so a client whose connect failed is never left offering `[ send ]` into nothing. If someone
//! moves `register_command_channel` above the `nusb` open, this fails.
//!
//! The hardware half is `injected_bulk_out_reaches_a_real_device`, `#[ignore]`d, with the exact
//! outcomes it must produce. Note what those outcomes are: `bulk_transfer_out` and a
//! `control_transfer` OUT report `Sent { bytes_sent }` — a completed OUT transfer really put
//! those bytes on the USB wire — while every IN transfer reports `Executed` naming how many
//! bytes came back.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features usb --test client -- usb::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A connect that never reached an open device must leave no command handle behind.
#[tokio::test]
async fn failed_device_open_leaves_no_command_handle() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // dead:beef is not a real VID:PID; the address parses, the device lookup fails.
    let created = ClientForm {
        protocol: "usb".to_string(),
        remote_addr: Some("dead:beef".to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await;

    let err = match created {
        Err(e) => e,
        Ok(id) => panic!(
            "USB client #{} connected to VID:dead PID:beef - this machine has a device that \
             should not exist; rerun the ignored hardware test instead",
            id.as_u32()
        ),
    };
    assert!(
        format!("{err:#}").contains("dead") || format!("{err:#}").to_lowercase().contains("usb"),
        "the failure should name the device it could not open, got {err:#}"
    );

    for client in state.get_all_clients().await {
        assert!(
            !state.has_client_handle(client.id).await,
            "client #{} left a stale command handle after a failed device open",
            client.id.as_u32()
        );
        // And the dashboard's send path must refuse rather than hang.
        let sent = state
            .send_to_client(
                client.id,
                serde_json::json!({"type": "bulk_transfer_out", "endpoint": 2, "data_hex": "00"}),
                Duration::from_secs(2),
            )
            .await;
        assert!(
            sent.is_err(),
            "send_to_client must fail for a client with no handle, got {sent:?}"
        );
    }
}

/// Requires a real USB device. Set `NETGET_USB_TEST_DEVICE` to `VID:PID[:INTERFACE]` (hex) and
/// `NETGET_USB_TEST_OUT_EP` to a bulk OUT endpoint on it, then run with `--ignored`.
///
/// Ignored because it cannot be satisfied without hardware: nusb has no loopback device and the
/// interface claim needs the device to be present and not held by a kernel driver.
#[tokio::test]
#[ignore = "requires a real USB device (set NETGET_USB_TEST_DEVICE / NETGET_USB_TEST_OUT_EP)"]
async fn injected_bulk_out_reaches_a_real_device() {
    let device = std::env::var("NETGET_USB_TEST_DEVICE")
        .expect("set NETGET_USB_TEST_DEVICE=VID:PID[:IFACE]");
    let endpoint: u8 = std::env::var("NETGET_USB_TEST_OUT_EP")
        .expect("set NETGET_USB_TEST_OUT_EP=<bulk OUT endpoint>")
        .parse()
        .expect("NETGET_USB_TEST_OUT_EP must be a number");

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "usb".to_string(),
        remote_addr: Some(device),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("open the USB device named by NETGET_USB_TEST_DEVICE");

    for _ in 0..1_000 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        state.has_client_handle(client_id).await,
        "the command handle must be registered before the usb_device_opened LLM call"
    );

    // 4 payload bytes; a completed OUT transfer is the one case that may claim Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "bulk_transfer_out",
                "endpoint": endpoint,
                "data_hex": "deadbeef",
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 4 }),
        "expected Sent{{4}}, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "detach_device"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client detach");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
}
