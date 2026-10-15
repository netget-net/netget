//! Bluetooth Low Energy (BLE) HID Keyboard implementation
//!
//! Builds on bluetooth-ble to provide HID over GATT keyboard functionality.
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

/// BLE HID Keyboard server.
///
/// A unit struct: this profile owns no state. `ble-peripheral-rust` 0.2 gives the
/// peripheral no per-central identity, and the base stack emits no connect or
/// disconnect events, so there is nothing a connection table could be keyed on or
/// populated from.
pub struct BluetoothBleKeyboard;

impl BluetoothBleKeyboard {
    /// Spawn BLE HID keyboard server
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        info!("Starting BLE HID Keyboard server: {}", device_name);

        // Create the underlying BLE server with HID keyboard configuration
        let keyboard_instruction = format!(
            "Configure as a BLE HID keyboard with HID Service (UUID: 0x1812). {} {}",
            instruction,
            "Add HID Report Map, HID Report Input, HID Information, and HID Control Point characteristics."
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
            keyboard_instruction,
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
        "BLE HID keyboard '{device_name}' could not start \
         (decision=refused_adapter_unavailable): {err}. No HID service was published and \
         nothing is advertising."
    )
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleKeyboard {
    pub async fn spawn_with_llm_actions(
        _device_name: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _instruction: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!(
            "BLE keyboard support not enabled - compile with --features bluetooth-ble-keyboard"
        )
    }
}

/// HID keyboard scan codes (USB HID specification)
pub mod hid_keycodes {
    pub const KEY_A: u8 = 0x04;
    pub const KEY_B: u8 = 0x05;
    pub const KEY_C: u8 = 0x06;
    // ... (full mapping in actual implementation)
    pub const KEY_ENTER: u8 = 0x28;
    pub const KEY_SPACE: u8 = 0x2C;

    /// Modifier bits
    pub const MOD_LEFT_CTRL: u8 = 0x01;
    pub const MOD_LEFT_SHIFT: u8 = 0x02;
    pub const MOD_LEFT_ALT: u8 = 0x04;
    pub const MOD_LEFT_GUI: u8 = 0x08;

    /// Convert ASCII character to HID keycode
    pub fn char_to_keycode(c: char) -> Option<(u8, u8)> {
        // Returns (modifiers, keycode)
        match c {
            'a'..='z' => Some((0, KEY_A + (c as u8 - b'a'))),
            'A'..='Z' => Some((MOD_LEFT_SHIFT, KEY_A + (c as u8 - b'A'))),
            ' ' => Some((0, KEY_SPACE)),
            '\n' => Some((0, KEY_ENTER)),
            _ => None,
        }
    }
}

/// Length in bytes of the input report [`HID_KEYBOARD_REPORT_DESCRIPTOR`] describes.
///
/// One modifier byte, one reserved byte, and a six-slot key array: the standard boot
/// keyboard input report. The startup examples in `actions.rs` size the input report
/// characteristic's initial value from it.
pub const HID_KEYBOARD_INPUT_REPORT_LEN: usize = 8;

/// HID Report Descriptor for keyboard.
///
/// This is the single source of truth for the report map: `actions.rs` hex-encodes these
/// bytes into its startup examples rather than carrying a second copy, and
/// `tests/server/bluetooth_ble_keyboard/report_descriptor_test.rs` walks every item and
/// asserts the total is `HID_KEYBOARD_INPUT_REPORT_LEN` bytes.
///
/// Input-only: there is no LED Output block, so a host cannot drive Caps/Num Lock. That is
/// a deliberate omission rather than a missing piece — nothing in this profile consumes an
/// output report — and it is why the descriptor is shorter than the boot-protocol keyboard
/// descriptor in the HID specification's Appendix B.
pub const HID_KEYBOARD_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0xE0, //   Usage Minimum (224)
    0x29, 0xE7, //   Usage Maximum (231)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute) - Modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Constant) - Reserved byte
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array) - Key array
    0xC0, // End Collection
];
