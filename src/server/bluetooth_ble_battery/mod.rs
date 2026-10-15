//! Bluetooth Low Energy (BLE) Battery Service implementation
//!
//! Builds on bluetooth-ble to provide standard Battery Service (0x180F).
//! Reports battery level as a percentage (0-100%).

pub mod actions;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::console_error;
use crate::llm::ollama_client::OllamaClient;
use crate::server::bluetooth_ble::BluetoothBle;
use crate::state::app_state::AppState;

/// BLE Battery Service server
pub struct BluetoothBleBattery;

impl BluetoothBleBattery {
    /// Spawn BLE battery service server
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        initial_level: u8,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        info!(
            "Starting BLE Battery Service: {} (initial level: {}%)",
            device_name, initial_level
        );

        // The user's instruction leads; the profile preamble is appended to it. Replacing it
        // outright would silently discard whatever the user actually asked the server to do.
        // The empty case is handled separately so a server created with no instruction does
        // not get a prompt beginning with a stray period.
        let sentence = format!(
            "Configure as a BLE Battery Service (0x180F) with a Battery Level characteristic \
             (0x2A19) starting at {initial_level}%."
        );
        let trimmed = instruction.trim().trim_end_matches('.').trim();
        let instruction = if trimmed.is_empty() {
            sentence
        } else {
            format!("{trimmed}. {sentence}")
        };

        // This profile decides nothing once the radio is up: the base stack owns the event
        // loop, and every `decision=` a read, write or subscribe produces is emitted there
        // against `BluetoothBleProtocol`. The one terminal outcome the profile does own is
        // this — the shared radio would not come up, so no Battery Service was ever published.
        let log_tx = status_tx.clone();
        let log_name = device_name.clone();
        match BluetoothBle::spawn_with_llm_actions(
            device_name,
            llm_client,
            app_state,
            status_tx,
            server_id,
            instruction,
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
        "BLE Battery Service '{device_name}' could not start \
         (decision=refused_adapter_unavailable): {err}. No Battery Service was published and \
         nothing is advertising."
    )
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleBattery {
    pub async fn spawn_with_llm_actions(
        _device_name: String,
        _initial_level: u8,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _instruction: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!(
            "BLE battery support not enabled - compile with --features bluetooth-ble-battery"
        )
    }
}

/// Battery Service UUIDs (Bluetooth SIG assigned numbers)
pub mod battery_uuids {
    /// Battery Service UUID
    pub const BATTERY_SERVICE: u16 = 0x180F;

    /// Battery Level characteristic UUID
    pub const BATTERY_LEVEL: u16 = 0x2A19;
}

/// Encode a Battery Level (0x2A19) characteristic value.
///
/// The characteristic is a single `uint8` carrying a **percentage**: the Bluetooth SIG Battery
/// Service 1.0 specification §3.1 defines 0 to 100 and reserves every other value. 75% is the
/// single octet `0x4B`.
///
/// **Returns `Err` rather than clamping.** This used to be `level.min(100)`, which turned 200
/// into a confident "100%". A percentage is the one type where truncation is least survivable:
/// every out-of-range value lands on a perfectly ordinary reading, so a caller's obvious
/// mistake becomes an unfalsifiable claim about a device's charge. There is no octet that
/// honestly represents 200%, so there is nothing to return.
pub fn encode_battery_level(level: u8) -> Result<[u8; 1]> {
    if level > 100 {
        anyhow::bail!(
            "Battery Level (0x2A19) is a percentage and the Bluetooth SIG reserves every \
             value above 100: {level} cannot be encoded. Refusing rather than clamping, \
             because a clamped 100 is indistinguishable from a full battery."
        );
    }
    Ok([level])
}
