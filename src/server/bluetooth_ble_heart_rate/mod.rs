//! BLE Heart Rate Service (0x180D)

pub mod actions;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

pub struct BluetoothBleHeartRate;

impl BluetoothBleHeartRate {
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm_client: crate::llm::ollama_client::OllamaClient,
        app_state: Arc<crate::state::app_state::AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        info!("Starting BLE Heart Rate Service: {}", device_name);
        // The user's instruction leads; the profile preamble is appended. This previously
        // discarded the instruction entirely, so "start at 60 BPM" never reached the model.
        // The empty case is handled separately so a server created with no instruction does
        // not get a prompt beginning with a stray period.
        const SENTENCE: &str = "Configure as a BLE Heart Rate Service (0x180D) with a Heart \
                                Rate Measurement characteristic (0x2A37).";
        let trimmed = instruction.trim().trim_end_matches('.').trim();
        let hr_instruction = if trimmed.is_empty() {
            SENTENCE.to_string()
        } else {
            format!("{trimmed}. {SENTENCE}")
        };
        // This profile decides nothing once the radio is up: the base stack owns the event
        // loop, and every `decision=` a read, write or subscribe produces is emitted there
        // against `BluetoothBleProtocol`. The one terminal outcome the profile does own is
        // this — the shared radio would not come up, so no Heart Rate Service was published.
        let log_tx = status_tx.clone();
        let log_name = device_name.clone();
        match crate::server::bluetooth_ble::BluetoothBle::spawn_with_llm_actions(
            device_name,
            llm_client,
            app_state,
            status_tx,
            server_id,
            hr_instruction,
        )
        .await
        {
            Ok(addr) => Ok(addr),
            Err(e) => {
                crate::console_error!(log_tx, "{}", radio_start_failure(&log_name, &e));
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
        "BLE Heart Rate Service '{device_name}' could not start \
         (decision=refused_adapter_unavailable): {err}. No Heart Rate Service was published \
         and nothing is advertising."
    )
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleHeartRate {
    pub async fn spawn_with_llm_actions(
        _: String,
        _: crate::llm::ollama_client::OllamaClient,
        _: Arc<crate::state::app_state::AppState>,
        _: mpsc::UnboundedSender<String>,
        _: crate::state::ServerId,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!(
            "BLE heart-rate not enabled - compile with --features bluetooth-ble-heart-rate"
        )
    }
}

/// Heart Rate Service, Bluetooth SIG assigned number.
pub const HEART_RATE_SERVICE: u16 = 0x180D;
/// Heart Rate Measurement characteristic.
pub const HEART_RATE_MEASUREMENT: u16 = 0x2A37;
/// Body Sensor Location characteristic.
pub const BODY_SENSOR_LOCATION: u16 = 0x2A38;

/// Encode a Heart Rate Measurement (0x2A37) characteristic value.
///
/// Layout, from the Bluetooth SIG Heart Rate Service 1.0 specification §3.1: a mandatory 8-bit
/// Flags octet, then the Heart Rate Measurement Value. **Flags bit 0 selects the value's
/// type** — 0 means a `uint8` in one octet, 1 means a `uint16` in two, little-endian. The other
/// flag bits describe optional fields (sensor contact, energy expended, RR-interval) that this
/// encoder does not emit, so they stay clear.
///
/// The format bit and the field width are chosen together here rather than left to the caller,
/// because disagreeing about them is the invisible failure this function exists to prevent: a
/// central handed `00 48 00` reads 72 BPM and then a stray octet it cannot account for, while
/// `01 48` is one octet short of the uint16 the flags promised.
///
/// **There is deliberately no clamp.** This used to be `[0x00, bpm.clamp(30, 220)]`, so a
/// caller asking for 25 got a confident 30 and one asking for 250 got 220 — an obvious error
/// silently rewritten into a believable claim about a human heart. The spec constrains the
/// field width and nothing else, so the width is all this enforces; whether a number is a
/// *plausible* heart rate is a judgement the wire format does not make and neither does this.
pub fn encode_heart_rate(bpm: u16) -> Vec<u8> {
    if let Ok(small) = u8::try_from(bpm) {
        // Flags bit 0 clear: the value is the single following octet. The conversion is
        // checked rather than cast, so the branch and the width cannot drift apart.
        vec![0x00, small]
    } else {
        let mut v = Vec::with_capacity(3);
        v.push(0x01); // Flags bit 0 set: uint16 value follows.
        v.extend_from_slice(&bpm.to_le_bytes()); // GATT is little-endian.
        v
    }
}
