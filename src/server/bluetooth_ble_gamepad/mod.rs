//! BLE Gamepad Service
pub mod actions;

/// Length in bytes of the input report [`HID_GAMEPAD_REPORT_DESCRIPTOR`] describes.
///
/// 16 one-bit buttons, so exactly two bytes with no padding. The startup examples in
/// `actions.rs` size the input report characteristic's initial value from it.
pub const HID_GAMEPAD_INPUT_REPORT_LEN: usize = 2;

/// HID Report Descriptor for a 16-button gamepad.
///
/// Buttons only. This profile deliberately declares no axes: the base stack's startup
/// examples are what a model copies onto a real GATT table, and a descriptor promising
/// analog sticks whose bytes nothing ever fills is worse than one that describes only
/// what is here.
///
/// This is the single source of truth for the report map — `actions.rs` hex-encodes these
/// bytes into its startup examples rather than carrying a second copy, and
/// `tests/server/bluetooth_ble_gamepad/report_descriptor_test.rs` walks every item and
/// asserts the total is `HID_GAMEPAD_INPUT_REPORT_LEN` bytes.
pub const HID_GAMEPAD_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x05, // Usage (Game Pad)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x09, //   Usage Page (Button)
    0x19, 0x01, //   Usage Minimum (Button 1)
    0x29, 0x10, //   Usage Maximum (Button 16)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x10, //   Report Count (16)
    0x81, 0x02, //   Input (Data, Variable, Absolute) - 16 button bits, two whole bytes
    0xC0, // End Collection
];
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct BluetoothBleGamepad;
impl BluetoothBleGamepad {
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm: crate::llm::ollama_client::OllamaClient,
        state: Arc<crate::state::app_state::AppState>,
        tx: mpsc::UnboundedSender<String>,
        id: crate::state::ServerId,
        inst: String,
    ) -> Result<std::net::SocketAddr> {
        crate::server::bluetooth_ble::BluetoothBle::spawn_with_llm_actions(
            device_name,
            llm,
            state,
            tx,
            id,
            format!("{}. Configure as BLE Gamepad.", inst),
        )
        .await
    }
}
#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleGamepad {
    pub async fn spawn_with_llm_actions(
        _: String,
        _: crate::llm::ollama_client::OllamaClient,
        _: Arc<crate::state::app_state::AppState>,
        _: mpsc::UnboundedSender<String>,
        _: crate::state::ServerId,
        _: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!("BLE gamepad not enabled")
    }
}
