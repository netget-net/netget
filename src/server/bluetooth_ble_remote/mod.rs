//! Bluetooth Low Energy (BLE) Remote Control implementation
//!
//! Builds on bluetooth-ble to provide HID Consumer Control functionality.
//! Acts as a media remote control for TVs, media players, etc.

pub mod actions;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::console_error;
use crate::llm::ollama_client::OllamaClient;
use crate::server::bluetooth_ble::BluetoothBle;
use crate::state::app_state::AppState;

/// BLE Remote Control server
pub struct BluetoothBleRemote;

impl BluetoothBleRemote {
    /// Spawn BLE remote control server
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        info!("Starting BLE Remote Control server: {}", device_name);

        // Create the underlying BLE server with HID remote configuration
        let remote_instruction = format!(
            "Configure as a BLE HID remote control with HID Service (UUID: 0x1812). {} {}",
            instruction,
            "Add HID Report Map, HID Report Input, HID Information, and HID Control Point characteristics for consumer control."
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
            remote_instruction,
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
        "BLE HID remote control '{device_name}' could not start \
         (decision=refused_adapter_unavailable): {err}. No HID service was published and \
         nothing is advertising."
    )
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleRemote {
    pub async fn spawn_with_llm_actions(
        _device_name: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _instruction: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!(
            "BLE remote support not enabled - compile with --features bluetooth-ble-remote"
        )
    }
}

/// HID Consumer Control usage codes
pub mod consumer_control {
    // Media control
    pub const PLAY_PAUSE: u16 = 0xCD;
    pub const NEXT_TRACK: u16 = 0xB5;
    pub const PREVIOUS_TRACK: u16 = 0xB6;
    pub const STOP: u16 = 0xB7;
    pub const FAST_FORWARD: u16 = 0xB3;
    pub const REWIND: u16 = 0xB4;

    // Volume control
    pub const VOLUME_UP: u16 = 0xE9;
    pub const VOLUME_DOWN: u16 = 0xEA;
    pub const MUTE: u16 = 0xE2;

    // Other controls
    pub const POWER: u16 = 0x30;
    pub const MENU: u16 = 0x40;
    pub const HOME: u16 = 0x223;
}

/// Length in bytes of the input report [`HID_REMOTE_REPORT_DESCRIPTOR`] describes.
///
/// 16 one-bit buttons, so exactly two bytes with no padding. `build_remote_report`
/// returns this many bytes, and the startup examples in `actions.rs` size the input
/// report characteristic's initial value from it.
pub const HID_REMOTE_INPUT_REPORT_LEN: usize = 2;

/// HID Report Descriptor for Consumer Control remote.
///
/// This is the single source of truth for the report map: `actions.rs` hex-encodes
/// these bytes into its startup examples rather than carrying a second copy, and
/// `tests/server/bluetooth_ble_remote/report_descriptor_test.rs` walks every item and
/// asserts the total is `HID_REMOTE_INPUT_REPORT_LEN` bytes.
///
/// Bit order matches [`build_remote_report`] exactly: the *n*th Usage below is bit *n*
/// of the report.
pub const HID_REMOTE_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x0C, // Usage Page (Consumer)
    0x09, 0x01, // Usage (Consumer Control)
    0xA1, 0x01, // Collection (Application)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x0C, //   Report Count (12) - one bit per named control below
    0x09, 0xCD, //   Usage (Play/Pause)           -> bit 0
    0x09, 0xB5, //   Usage (Scan Next Track)      -> bit 1
    0x09, 0xB6, //   Usage (Scan Previous Track)  -> bit 2
    0x09, 0xB7, //   Usage (Stop)                 -> bit 3
    0x09, 0xB3, //   Usage (Fast Forward)         -> bit 4
    0x09, 0xB4, //   Usage (Rewind)               -> bit 5
    0x09, 0xE9, //   Usage (Volume Increment)     -> bit 6
    0x09, 0xEA, //   Usage (Volume Decrement)     -> bit 7
    0x09, 0xE2, //   Usage (Mute)                 -> bit 8
    0x09, 0x30, //   Usage (Power)                -> bit 9
    0x09, 0x40, //   Usage (Menu)                 -> bit 10
    // AC Home is 0x0223, a two-byte usage, so it needs the bSize=2 form of the Usage
    // item (0x0A) and not the one-byte form (0x09). Written as `0x09, 0x23, 0x02` the
    // trailing 0x02 is not data at all: it parses as a *new* item with bTag=0000 and
    // bType=Main, which is reserved, and it then swallows the two bytes after it. That
    // is what this descriptor said until September 2026, and a host walking it would
    // have rejected the report map outright.
    0x0A, 0x23, 0x02, //   Usage (AC Home)        -> bit 11
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    // Pad bits 12-15 so the report is exactly two whole bytes. Constant padding is the
    // spec's mechanism for this; the four `Usage (0x00)` items that used to stand here
    // named the Undefined usage, which is not a padding declaration.
    0x95, 0x04, //   Report Count (4)
    0x81, 0x03, //   Input (Constant, Variable, Absolute) - padding
    0xC0, // End Collection
];

/// Build a remote control report from a control name.
///
/// The report is [`HID_REMOTE_INPUT_REPORT_LEN`] bytes, little-endian bit order: bit *n*
/// is the *n*th Usage declared in [`HID_REMOTE_REPORT_DESCRIPTOR`]. Bits 12-15 are the
/// descriptor's constant padding and are always zero.
///
/// Example: Play/Pause pressed is bit 0, so `[0x01, 0x00]`.
///
/// Returns `None` for a name this profile does not define. That is deliberate and is the
/// reason this is not `[u8; 2]`: a report full of zeroes is a *valid* report meaning "no
/// control is pressed", so returning one for an unrecognised name would turn a caller's
/// mistake into an affirmative statement on the wire that every button was released. The
/// caller has to decide what an unknown name means; this function will not decide for it.
pub fn build_remote_report(button: &str) -> Option<[u8; HID_REMOTE_INPUT_REPORT_LEN]> {
    let bit_position: u32 = match button {
        "play_pause" => 0,
        "next_track" => 1,
        "previous_track" => 2,
        "stop" => 3,
        "fast_forward" => 4,
        "rewind" => 5,
        "volume_up" => 6,
        "volume_down" => 7,
        "mute" => 8,
        "power" => 9,
        "menu" => 10,
        "home" => 11,
        _ => return None,
    };

    let mut report = [0u8; HID_REMOTE_INPUT_REPORT_LEN];
    report[(bit_position / 8) as usize] = 1u8 << (bit_position % 8);
    Some(report)
}
