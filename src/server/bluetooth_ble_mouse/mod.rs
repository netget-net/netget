//! Bluetooth Low Energy (BLE) HID Mouse implementation
//!
//! Builds on bluetooth-ble to provide HID over GATT mouse functionality.
//! Supports connection tracking and targeted messages to specific devices.

pub mod actions;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::console_error;
use crate::llm::ollama_client::OllamaClient;
use crate::server::bluetooth_ble::BluetoothBle;
use crate::state::app_state::AppState;

/// BLE HID Mouse server.
///
/// A unit struct: this profile owns no state. `ble-peripheral-rust` 0.2 gives the
/// peripheral no per-central identity, and the base stack emits no connect or
/// disconnect events, so there is nothing a connection table could be keyed on or
/// populated from.
pub struct BluetoothBleMouse;

impl BluetoothBleMouse {
    /// Spawn BLE HID mouse server
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        info!("Starting BLE HID Mouse server: {}", device_name);

        // Create the underlying BLE server with HID mouse configuration
        let mouse_instruction = format!(
            "Configure as a BLE HID mouse with HID Service (UUID: 0x1812). {} {}",
            instruction,
            "Add HID Report Map, HID Report Input, HID Information, and HID Control Point characteristics for mouse."
        );

        // Use the base bluetooth-ble server.
        //
        // This profile decides nothing once the radio is up: the base stack owns the event
        // loop, and every `decision=` a read, write or subscribe produces is emitted there
        // against `BluetoothBleProtocol`. The one terminal outcome the profile does own is
        // this — the shared radio would not come up, so no HID service was ever published.
        let log_tx = status_tx.clone();
        let log_name = device_name.clone();
        match BluetoothBle::spawn_with_llm_actions(
            device_name,
            llm_client,
            app_state,
            status_tx,
            server_id,
            mouse_instruction,
        )
        .await
        {
            Ok(addr) => Ok(addr),
            Err(e) => {
                console_error!(log_tx, "{}", radio_start_failure(&log_name, &e));
                Err(e)
            }
        }
    }
}

/// The single source of the text used when the shared BLE radio could not be brought up.
///
/// `pub` so a test can assert the `decision=` tag without claiming a Bluetooth adapter: this is
/// the profile's only terminal outcome of its own, and the project forbids `#[cfg(test)]`
/// modules in `src/`. No model is consulted on this path — the radio fails before any event
/// exists — so the token is deliberately not one of the `fail_closed_llm_*` pair, which would
/// send someone to restart Ollama over an adapter that is switched off.
pub fn radio_start_failure(device_name: &str, err: &anyhow::Error) -> String {
    format!(
        "BLE HID mouse '{device_name}' could not start \
         (decision=refused_adapter_unavailable): {err}. No HID service was published and \
         nothing is advertising."
    )
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleMouse {
    pub async fn spawn_with_llm_actions(
        _device_name: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _instruction: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!("BLE mouse support not enabled - compile with --features bluetooth-ble-mouse")
    }
}

/// HID mouse button bits
pub mod hid_mouse_buttons {
    pub const BUTTON_LEFT: u8 = 0x01;
    pub const BUTTON_RIGHT: u8 = 0x02;
    pub const BUTTON_MIDDLE: u8 = 0x04;
}

/// Length in bytes of the input report [`HID_MOUSE_REPORT_DESCRIPTOR`] describes.
///
/// One byte of three button bits plus five padding bits, then one signed byte each of X, Y
/// and Wheel. The startup examples in `actions.rs` size the input report characteristic's
/// initial value from it.
pub const HID_MOUSE_INPUT_REPORT_LEN: usize = 4;

/// HID Report Descriptor for mouse.
///
/// This is the single source of truth for the report map: `actions.rs` hex-encodes these
/// bytes into its startup examples rather than carrying a second copy, and
/// `tests/server/bluetooth_ble_mouse/report_descriptor_test.rs` walks every item and
/// asserts the total is `HID_MOUSE_INPUT_REPORT_LEN` bytes.
///
/// X, Y and Wheel are **signed** and **relative**: Logical Minimum is `0x81` (-127) and
/// Logical Maximum `0x7F` (127), and the Input item sets the Relative bit (0x06, not 0x02).
/// Both matter — a host reading these as unsigned sees every leftward movement as a large
/// rightward one.
pub const HID_MOUSE_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x01, //   Usage (Pointer)
    0xA1, 0x00, //   Collection (Physical)
    0x05, 0x09, //     Usage Page (Buttons)
    0x19, 0x01, //     Usage Minimum (1)
    0x29, 0x03, //     Usage Maximum (3)
    0x15, 0x00, //     Logical Minimum (0)
    0x25, 0x01, //     Logical Maximum (1)
    0x95, 0x03, //     Report Count (3)
    0x75, 0x01, //     Report Size (1)
    0x81, 0x02, //     Input (Data, Variable, Absolute) - Button bits
    0x95, 0x01, //     Report Count (1)
    0x75, 0x05, //     Report Size (5)
    0x81, 0x01, //     Input (Constant) - Padding
    0x05, 0x01, //     Usage Page (Generic Desktop)
    0x09, 0x30, //     Usage (X)
    0x09, 0x31, //     Usage (Y)
    0x09, 0x38, //     Usage (Wheel)
    0x15, 0x81, //     Logical Minimum (-127)
    0x25, 0x7F, //     Logical Maximum (127)
    0x75, 0x08, //     Report Size (8)
    0x95, 0x03, //     Report Count (3)
    0x81, 0x06, //     Input (Data, Variable, Relative) - X, Y, Wheel
    0xC0, //   End Collection (Physical)
    0xC0, // End Collection (Application)
];
